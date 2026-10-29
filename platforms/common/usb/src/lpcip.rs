// Licensed under the Apache-2.0 license

use caliptra_mcu_ocp::usb::descriptors::*;
use caliptra_mcu_ocp::usb::setup::SetupPacket;
use caliptra_mcu_registers_generated::{usb_combo, usb_dev0_mem};
use caliptra_mcu_romtime::StaticRef;
use tock_registers::interfaces::{Readable, Writeable};
use usb_combo::bits::{ConfigT, DevcmdstatT, UlpidebugT};
use zerocopy::IntoBytes;

const PACKET_SIZE: usize = 64;
const SETUP_OFFSET: usize = 0x100;
const OUT_OFFSET: usize = 0x140;
const IN_OFFSET: usize = 0x180;
const ACTIVE: u32 = 1 << 31;
const DISABLED: u32 = 1 << 30;
const STALL: u32 = 1 << 29;
const DATA1: u32 = (1 << 28) | (1 << 27);
const KEEP_CLOCK: u32 = DevcmdstatT::ForceNeedclk::SET.value;

/// All caller-supplied USB configuration. No release identity or mapping default.
pub struct UsbParams {
    pub registers: StaticRef<usb_combo::regs::UsbCombo>,
    /// Dedicated Device 0 SRAM; the driver reserves its first 448 bytes.
    pub packet_memory: StaticRef<usb_dev0_mem::regs::UsbDev0Mem>,
    pub vendor_id: u16,
    pub product_id: u16,
    pub device_revision: u16,
    pub self_powered: bool,
    /// Maximum current drawn from USB VBUS, in 2 mA units.
    pub max_power_2ma: u8,
    /// Currently unsupported: initialization rejects `true`.
    pub remote_wakeup: bool,
    pub force_full_speed: bool,
    /// Maximum MMIO polls per PHY access, VBUS wait or endpoint cancellation.
    pub poll_limit: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsbError {
    InvalidParameters,
    InvalidDescriptor,
    InvalidPacketMemory,
    UnsupportedPhyInterface,
    UnsupportedRemoteWakeup,
    PhyAccessTimeout,
    PhyIdentityMismatch,
    PhyConfigurationMismatch,
    VbusTimeout,
    CancellationTimeout,
    NotInitialized,
    UnsupportedRequest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsbPoll {
    Idle,
    Progress,
    BusReset,
    Stalled,
    ConfigurationChanged(u8),
    Disconnected,
}

#[derive(Clone, Copy)]
enum Action {
    None,
    Address(u8),
    Configuration(u8),
}

enum Stage {
    Idle,
    Read { zlp: bool },
    StatusOut,
    StatusIn(Action),
    Stalled,
}

struct Reply {
    data: [u8; PACKET_SIZE],
    length: usize,
    requested: usize,
    action: Option<Action>,
}

impl Reply {
    fn read(data: &[u8], requested: usize) -> Result<Self, UsbError> {
        if data.len() > PACKET_SIZE {
            return Err(UsbError::InvalidDescriptor);
        }
        let length = data.len().min(requested);
        let mut reply = Self {
            data: [0; PACKET_SIZE],
            length,
            requested,
            action: None,
        };
        for (destination, source) in reply.data.iter_mut().zip(data).take(length) {
            *destination = *source;
        }
        Ok(reply)
    }

    fn status(action: Action) -> Self {
        Self {
            data: [0; PACKET_SIZE],
            length: 0,
            requested: 0,
            action: Some(action),
        }
    }
}

pub struct LpcipUsbDriver {
    params: UsbParams,
    stage: Stage,
    address: u8,
    configuration: u8,
    initialized: bool,
    buffer_base: u32,
}

impl LpcipUsbDriver {
    pub const fn new(params: UsbParams) -> Self {
        Self {
            params,
            stage: Stage::Idle,
            address: 0,
            configuration: 0,
            initialized: false,
            buffer_base: 0,
        }
    }

    pub fn configuration(&self) -> u8 {
        self.configuration
    }

    /// Disconnect, initialize SRAM/ULPI, validate USB3320 and wait for real VBUS
    /// before asserting DCON. Errors leave Device 0 disconnected with its clock on.
    pub fn initialize(&mut self) -> Result<(), UsbError> {
        self.initialized = false;
        self.address = 0;
        self.configuration = 0;
        self.stage = Stage::Idle;
        self.command(false, 0);
        self.validate()?;
        if !self.params.registers.dev0_csr_config.is_set(ConfigT::Ulpi) {
            return Err(UsbError::UnsupportedPhyInterface);
        }
        let memory = (&*self.params.packet_memory as *const _ as usize)
            .try_into()
            .map_err(|_| UsbError::InvalidPacketMemory)?;
        self.buffer_base = memory;
        if memory & 0xff != 0 || memory & 0x1ffff > 0x20000 - (IN_OFFSET + PACKET_SIZE) as u32 {
            return Err(UsbError::InvalidPacketMemory);
        }
        self.params.registers.dev0_csr_epliststart.set(memory);
        self.params
            .registers
            .dev0_csr_databufstart
            .set(memory & !0x1ffff);
        self.params.registers.dev0_csr_epbufcfg.set(0);
        self.params.registers.dev0_csr_inten.set(0);
        self.params.registers.dev0_csr_intstat.set(u32::MAX);
        for index in 0..64 {
            self.write_word(index, if index >= 4 { DISABLED } else { 0 })?;
        }
        self.write_word(1, self.descriptor(SETUP_OFFSET, 0)?)?;
        let mut identity = [0; 4];
        for (address, value) in identity.iter_mut().enumerate() {
            *value = self.ulpi(address as u8, None)?;
        }
        if identity != [0x24, 0x04, 0x07, 0] {
            return Err(UsbError::PhyIdentityMismatch);
        }
        self.ulpi(4, Some(0x40))?; // HS device mode, SUSPENDM keeps the PHY awake.
        self.ulpi(0x0a, Some(0))?; // No pull-downs, VBUS drive or discharge.
        if self.ulpi(4, None)? != 0x40 || self.ulpi(0x0a, None)? != 0 {
            return Err(UsbError::PhyConfigurationMismatch);
        }
        self.wait(
            || {
                self.params
                    .registers
                    .dev0_csr_devcmdstat
                    .is_set(DevcmdstatT::VbusDebounced)
            },
            UsbError::VbusTimeout,
        )?;
        self.command(true, 0);
        self.initialized = true;
        Ok(())
    }

    fn validate(&self) -> Result<(), UsbError> {
        if self.params.poll_limit == 0 || self.params.max_power_2ma > 250 {
            return Err(UsbError::InvalidParameters);
        }
        if self.params.remote_wakeup {
            return Err(UsbError::UnsupportedRemoteWakeup);
        }
        Ok(())
    }

    fn command(&self, connected: bool, clear: u32) {
        self.params.registers.dev0_csr_devcmdstat.set(
            KEEP_CLOCK
                | u32::from(self.address)
                | if self.params.force_full_speed {
                    DevcmdstatT::ForceFullspeed::SET.value
                } else {
                    0
                }
                | if connected {
                    DevcmdstatT::DevEn::SET.value | DevcmdstatT::Dcon::SET.value
                } else {
                    0
                }
                | clear,
        );
    }

    fn wait(&self, mut condition: impl FnMut() -> bool, error: UsbError) -> Result<(), UsbError> {
        for _ in 0..self.params.poll_limit {
            if condition() {
                return Ok(());
            }
        }
        Err(error)
    }

    fn ulpi(&self, address: u8, write: Option<u8>) -> Result<u8, UsbError> {
        let register = &self.params.registers.hub_ulpidebug;
        let command = UlpidebugT::PhyMode::SET.value
            | UlpidebugT::PhyAddr.val(u32::from(address & 0xf)).value
            | UlpidebugT::PhyAddrHigh.val(u32::from(address >> 4)).value
            | write.map_or(0, |value| {
                UlpidebugT::PhyRw::SET.value | UlpidebugT::PhyWdata.val(u32::from(value)).value
            });
        register.set(command);
        register.set(command | UlpidebugT::PhyAccess::SET.value);
        self.wait(
            || !register.is_set(UlpidebugT::PhyAccess),
            UsbError::PhyAccessTimeout,
        )?;
        Ok(register.read(UlpidebugT::PhyRdata) as u8)
    }

    fn descriptor(&self, offset: usize, length: usize) -> Result<u32, UsbError> {
        encode_descriptor((self.buffer_base & 0x1ffff) as usize + offset, length)
    }

    fn read_word(&self, index: usize) -> Result<u32, UsbError> {
        self.params
            .packet_memory
            .usb_dev0_mem
            .get(index)
            .map(Readable::get)
            .ok_or(UsbError::InvalidPacketMemory)
    }

    fn write_word(&self, index: usize, word: u32) -> Result<(), UsbError> {
        let register = self
            .params
            .packet_memory
            .usb_dev0_mem
            .get(index)
            .ok_or(UsbError::InvalidPacketMemory)?;
        register.set(word);
        Ok(())
    }

    fn arm(&self, input: bool, length: usize) -> Result<(), UsbError> {
        let (descriptor, offset) = if input {
            (2, IN_OFFSET)
        } else {
            (0, OUT_OFFSET)
        };
        self.write_word(
            descriptor,
            self.descriptor(offset, length)? | ACTIVE | DATA1,
        )
    }

    fn cancel(&self) -> Result<(), UsbError> {
        self.params.registers.dev0_csr_epskip.set(3);
        self.wait(
            || self.params.registers.dev0_csr_epskip.get() & 3 == 0,
            UsbError::CancellationTimeout,
        )?;
        self.params.registers.dev0_csr_intstat.set(3);
        self.write_word(0, 0)?;
        self.write_word(2, 0)
    }

    fn stall(&mut self) -> Result<UsbPoll, UsbError> {
        self.cancel()?;
        self.write_word(0, self.descriptor(OUT_OFFSET, 0)? | STALL)?;
        self.write_word(2, self.descriptor(IN_OFFSET, 0)? | STALL)?;
        self.stage = Stage::Stalled;
        Ok(UsbPoll::Stalled)
    }

    fn setup(&mut self) -> Result<UsbPoll, UsbError> {
        let first = self.read_word(SETUP_OFFSET / 4)?.to_le_bytes();
        let second = self.read_word(SETUP_OFFSET / 4 + 1)?.to_le_bytes();
        let setup: SetupPacket = zerocopy::transmute!([
            first[0], first[1], first[2], first[3], second[0], second[1], second[2], second[3],
        ]);
        self.cancel()?;
        let result = match request(&self.params, &setup, self.address, self.configuration) {
            Ok(reply) => {
                if let Some(action) = reply.action {
                    self.arm(true, 0)?;
                    self.stage = Stage::StatusIn(action);
                } else if reply.requested == 0 {
                    self.arm(true, 0)?;
                    self.stage = Stage::StatusIn(Action::None);
                } else {
                    let data = reply
                        .data
                        .get(..reply.length)
                        .ok_or(UsbError::InvalidDescriptor)?;
                    for (index, bytes) in data.chunks(4).enumerate() {
                        let mut word = [0; 4];
                        for (destination, source) in word.iter_mut().zip(bytes) {
                            *destination = *source;
                        }
                        self.write_word(IN_OFFSET / 4 + index, u32::from_le_bytes(word))?;
                    }
                    self.arm(true, reply.length)?;
                    self.stage = Stage::Read {
                        zlp: needs_zlp(reply.length, reply.requested),
                    };
                }
                UsbPoll::Progress
            }
            Err(UsbError::UnsupportedRequest) => self.stall()?,
            Err(error) => return Err(error),
        };
        // Publish the prepared response before releasing the SETUP hold.
        self.command(true, DevcmdstatT::Setup::SET.value);
        Ok(result)
    }

    pub fn poll(&mut self) -> Result<UsbPoll, UsbError> {
        if !self.initialized {
            return Err(UsbError::NotInitialized);
        }
        let command = self.params.registers.dev0_csr_devcmdstat.get();
        if command & DevcmdstatT::VbusDebounced::SET.value == 0 {
            self.cancel()?;
            self.command(false, 0);
            self.initialized = false;
            self.configuration = 0;
            self.stage = Stage::Idle;
            return Ok(UsbPoll::Disconnected);
        }
        if command & DevcmdstatT::DresC::SET.value != 0 {
            self.cancel()?;
            self.address = 0;
            self.configuration = 0;
            self.stage = Stage::Idle;
            self.command(true, DevcmdstatT::DresC::SET.value);
            return Ok(UsbPoll::BusReset);
        }
        if command & DevcmdstatT::Setup::SET.value != 0 {
            return self.setup();
        }
        match self.stage {
            Stage::Read { zlp } if self.read_word(2)? & ACTIVE == 0 => {
                self.params.registers.dev0_csr_intstat.set(2);
                if zlp {
                    self.arm(true, 0)?;
                    self.stage = Stage::Read { zlp: false };
                } else {
                    self.arm(false, PACKET_SIZE)?;
                    self.stage = Stage::StatusOut;
                }
                Ok(UsbPoll::Progress)
            }
            Stage::StatusOut if self.read_word(0)? & ACTIVE == 0 => {
                if (self.read_word(0)? >> 11) & 0x7fff != PACKET_SIZE as u32 {
                    return self.stall();
                }
                self.params.registers.dev0_csr_intstat.set(1);
                self.stage = Stage::Idle;
                Ok(UsbPoll::Progress)
            }
            Stage::StatusIn(action) if self.read_word(2)? & ACTIVE == 0 => {
                self.params.registers.dev0_csr_intstat.set(2);
                self.stage = Stage::Idle;
                match action {
                    Action::Address(address) => {
                        // Stage only after the old-address IN status ACK.
                        // Selected RTL latches the next SETUP token's address.
                        self.address = address;
                        self.command(true, 0);
                        Ok(UsbPoll::Progress)
                    }
                    Action::Configuration(configuration) => {
                        self.configuration = configuration;
                        Ok(UsbPoll::ConfigurationChanged(configuration))
                    }
                    Action::None => Ok(UsbPoll::Progress),
                }
            }
            _ => Ok(UsbPoll::Idle),
        }
    }
}

fn encode_descriptor(offset: usize, length: usize) -> Result<u32, UsbError> {
    if offset & 63 != 0 || offset >= 0x20000 || length > PACKET_SIZE {
        return Err(UsbError::InvalidPacketMemory);
    }
    Ok((offset as u32 >> 6) | ((length as u32) << 11))
}

fn needs_zlp(length: usize, requested: usize) -> bool {
    length < requested && length.is_multiple_of(PACKET_SIZE)
}

fn request(
    params: &UsbParams,
    setup: &SetupPacket,
    address: u8,
    configuration: u8,
) -> Result<Reply, UsbError> {
    let value = u16::from_le_bytes(setup.w_value);
    let index = u16::from_le_bytes(setup.w_index);
    let length = usize::from(setup.data_length());
    match (setup.bm_request_type.0, setup.b_request) {
        (0x80, 6) => {
            let descriptor_type = setup.w_value[1];
            let descriptor_index = setup.w_value[0];
            if descriptor_type != 3 && (index != 0 || descriptor_index != 0) {
                return Err(UsbError::UnsupportedRequest);
            }
            match descriptor_type {
                1 => Reply::read(
                    DeviceDescriptor::ocp(
                        0x0200,
                        params.vendor_id,
                        params.product_id,
                        params.device_revision,
                        0,
                        0,
                        0,
                    )
                    .as_bytes(),
                    length,
                ),
                2 | 7 if descriptor_type == 2 || !params.force_full_speed => {
                    let mut data = [0; CONFIGURATION_TREE_LEN];
                    data.copy_from_slice(
                        ConfigurationTree::ocp(
                            BmAttributes::new(params.self_powered, false),
                            MaxPower2mA(params.max_power_2ma),
                            Some(0),
                            64,
                            64,
                        )
                        .as_bytes(),
                    );
                    data[1] = descriptor_type;
                    Reply::read(&data, length)
                }
                3 if descriptor_index == 0 && index == 0 => {
                    Reply::read(StringDescriptorZero::ocp().as_bytes(), length)
                }
                3 if descriptor_index == OCP_INTERFACE_STRING_INDEX
                    && index == LANG_ID_ENGLISH_US =>
                {
                    Reply::read(OcpInterfaceStringDescriptor::ocp().as_bytes(), length)
                }
                6 if !params.force_full_speed => {
                    Reply::read(&[10, 6, 0, 2, 0, 0, 0, 64, 1, 0], length)
                }
                _ => Err(UsbError::UnsupportedRequest),
            }
        }
        (0, 5) if value <= 127 && index == 0 && length == 0 && configuration == 0 => {
            Ok(Reply::status(Action::Address(value as u8)))
        }
        (0, 9) if value <= 1 && index == 0 && length == 0 && address != 0 => {
            Ok(Reply::status(Action::Configuration(value as u8)))
        }
        (0x80, 8) if value == 0 && index == 0 && length == 1 && address != 0 => {
            Reply::read(&[configuration], length)
        }
        (0x80, 0) if value == 0 && index == 0 && length == 2 => {
            Reply::read(&[u8::from(params.self_powered), 0], length)
        }
        (0x81, 0) if value == 0 && index == 0 && length == 2 && configuration != 0 => {
            Reply::read(&[0, 0], length)
        }
        (0x82, 0) if value == 0 && matches!(index, 0 | 0x80) && length == 2 && address != 0 => {
            Reply::read(&[0, 0], length)
        }
        (0x81, 10) if value == 0 && index == 0 && length == 1 && configuration != 0 => {
            Reply::read(&[0], length)
        }
        (1, 11) if value == 0 && index == 0 && length == 0 && configuration != 0 => {
            Ok(Reply::status(Action::None))
        }
        _ => Err(UsbError::UnsupportedRequest),
    }
}

#[cfg(test)]
mod tests;
