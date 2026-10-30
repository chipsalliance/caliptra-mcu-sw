// Licensed under the Apache-2.0 license

//! Behavioral LPCIP compound controller, separate from the OpenTitan USBDEV.

use caliptra_emu_bus::ReadWriteRegister;
use caliptra_emu_cpu::Irq;
use caliptra_mcu_emulator_registers_generated::{
    usb_combo::UsbComboPeripheral, usb_dev0_mem::UsbDev0MemPeripheral, usb_dev1::UsbDev1Peripheral,
    usb_dev1_mem::UsbDev1MemPeripheral,
};
use caliptra_mcu_registers_generated::{
    usb_combo::bits, usb_dev0_mem::USB_DEV0_MEM_ADDR, usb_dev1::bits as dev1_bits,
    usb_dev1_mem::USB_DEV1_MEM_ADDR,
};
use std::ops::Range;
use std::sync::{Arc, Mutex};
use tock_registers::interfaces::Readable;

mod hub;
pub use hub::LpcipUsbHubHostController;
pub mod ip;
pub use ip::{UsbIpServer, BUS_ID as USBIP_BUS_ID};
mod phy;
pub use phy::{LpcipUsbPhy, LpcipUsbPhyError, LpcipUsbPhySnapshot};
mod recovery;
pub use recovery::LpcipUsbRecoverySnapshot;
#[cfg(test)]
mod phy_tests;
#[cfg(test)]
mod recovery_tests;

const MEMORY_SIZE: usize = 0x10000;
const ENDPOINTS: u8 = 30;
const NONCONTROL_ENDPOINTS: u32 = 0x3fff_fffc;
const DEV_EN: u32 = 1 << 7;
const SETUP: u32 = 1 << 8;
const FORCE_VBUS: u32 = 1 << 10;
const CONNECT: u32 = 1 << 16;
const CONNECT_CHANGE: u32 = 1 << 24;
const RESET_CHANGE: u32 = 1 << 26;
const CHANGE_BITS: u32 = 0x0f00_0000;
const VBUS: u32 = 1 << 28;
const DEVICE_INTERRUPT: u32 = 1 << 31;
const FRAME_INTERRUPT: u32 = 1 << 30;
const ACTIVE: u32 = 1 << 31;
const DISABLED: u32 = 1 << 30;
const STALL: u32 = 1 << 29;
const TOGGLE_RESET: u32 = 1 << 28;
const TOGGLE_VALUE: u32 = 1 << 27;
const PERIODIC: u32 = 1 << 26;
const LENGTH_MASK: u32 = 0x7fff << 11;
const OFFSET_MASK: u32 = 0x7ff;

/// A successful transaction is ACKed; errors distinguish retryable NAK from
/// STALL, missing devices, unsupported endpoints, and invalid firmware DMA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LpcipUsbError {
    Disconnected,
    AddressMismatch,
    Nak,
    Stall,
    EndpointDisabled,
    InvalidEndpoint,
    InvalidPort,
    UnsupportedTransfer,
    InvalidSetup,
    InvalidMemory,
    DataTooLong,
}

impl std::fmt::Display for LpcipUsbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LPCIP USB transaction failed: {self:?}")
    }
}

impl std::error::Error for LpcipUsbError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LpcipUsbSpeed {
    Full,
    High,
}

struct DeviceState {
    memory: Vec<u8>,
    memory_base: u32,
    command: u32,
    address: u8,
    pending_address: u8,
    vbus: bool,
    speed: LpcipUsbSpeed,
    epliststart: u32,
    databufstart: u32,
    epskip: u32,
    epinuse: u32,
    epbufcfg: u32,
    eptoggle: u32,
    intstat: u32,
    inten: u32,
    introute: u32,
    frame: u16,
    error_code: u8,
    recovery: Option<recovery::Recovery>,
}

impl Default for DeviceState {
    fn default() -> Self {
        Self {
            memory: vec![0; MEMORY_SIZE],
            memory_base: USB_DEV0_MEM_ADDR,
            command: 0,
            address: 0,
            pending_address: 0,
            vbus: false,
            speed: LpcipUsbSpeed::Full,
            epliststart: 0,
            databufstart: 0,
            epskip: 0,
            epinuse: 0,
            epbufcfg: 0,
            eptoggle: 0,
            intstat: 0,
            inten: 0,
            introute: 0,
            frame: 0,
            error_code: 0,
            recovery: None,
        }
    }
}

impl DeviceState {
    fn reset_bus(&mut self, speed: LpcipUsbSpeed) {
        if let Some(recovery) = &mut self.recovery {
            recovery.abort();
        }
        self.speed = if self.command & (1 << 21) != 0 {
            LpcipUsbSpeed::Full
        } else {
            speed
        };
        self.address = 0;
        self.pending_address = 0;
        self.eptoggle = 0;
        self.command |= RESET_CHANGE;
        self.intstat |= DEVICE_INTERRUPT;
    }

    fn link_connected(&self) -> bool {
        self.command & CONNECT != 0 && (self.vbus || self.command & FORCE_VBUS != 0)
    }

    fn connected(&self) -> bool {
        self.command & DEV_EN != 0 && self.link_connected()
    }

    fn check_token(&self, address: u8) -> Result<(), LpcipUsbError> {
        if !self.connected() {
            return Err(LpcipUsbError::Disconnected);
        }
        // usb_pie accepts both addresses until usb_reg_if latches the address
        // of the next SETUP token. No standard request is decoded here.
        if address != self.address && address != self.pending_address {
            return Err(LpcipUsbError::AddressMismatch);
        }
        Ok(())
    }

    fn memory_range(&self, address: u32, length: usize) -> Result<Range<usize>, LpcipUsbError> {
        let start = address
            .checked_sub(self.memory_base)
            .ok_or(LpcipUsbError::InvalidMemory)? as usize;
        let end = start
            .checked_add(length)
            .filter(|&end| end <= self.memory.len())
            .ok_or(LpcipUsbError::InvalidMemory)?;
        Ok(start..end)
    }

    fn descriptor(&self, physical: u8, setup: bool) -> Result<(usize, u32), LpcipUsbError> {
        let bank = if setup {
            1
        } else {
            (self.epinuse >> physical) & 1
        };
        let address = self
            .epliststart
            .checked_add(u32::from(physical) * 8 + bank * 4)
            .ok_or(LpcipUsbError::InvalidMemory)?;
        let range = self.memory_range(address, 4)?;
        let offset = range.start;
        let word = u32::from_le_bytes(self.memory[range].try_into().unwrap());
        Ok((offset, word))
    }

    fn buffer(&self, word: u32, length: usize) -> Result<Range<usize>, LpcipUsbError> {
        let address = self
            .databufstart
            .checked_add((word & OFFSET_MASK) << 6)
            .ok_or(LpcipUsbError::InvalidMemory)?;
        self.memory_range(address, length)
    }

    fn max_packet(&self, physical: u8, word: u32) -> usize {
        if physical < 2 {
            64
        } else {
            match self.speed {
                LpcipUsbSpeed::Full => 64,
                LpcipUsbSpeed::High if word & PERIODIC != 0 => 1024,
                LpcipUsbSpeed::High => 512,
            }
        }
    }

    fn ready_descriptor(&mut self, physical: u8) -> Result<(usize, u32), LpcipUsbError> {
        if physical >= ENDPOINTS {
            return Err(LpcipUsbError::InvalidEndpoint);
        }
        let (offset, word) = self.descriptor(physical, false)?;
        if physical >= 2 && word & DISABLED != 0 {
            return Err(LpcipUsbError::EndpointDisabled);
        }
        if physical >= 2 && word & PERIODIC != 0 && word & TOGGLE_VALUE == 0 {
            return Err(LpcipUsbError::UnsupportedTransfer);
        }
        let held =
            (physical < 2 && self.command & SETUP != 0) || self.epskip & (1 << physical) != 0;
        // usb_dma masks STALL while ACTIVE or while EP0 SETUP is pending.
        if !held && word & (ACTIVE | STALL) == STALL {
            self.error_code = 10;
            return Err(LpcipUsbError::Stall);
        }
        if held || word & ACTIVE == 0 {
            let nak_enable = match physical {
                0 => 14,
                1 => 15,
                ep if ep & 1 == 0 => 12,
                _ => 13,
            };
            if self.command & (1 << nak_enable) != 0 {
                self.intstat |= 1 << physical;
            }
            self.error_code = 9;
            return Err(LpcipUsbError::Nak);
        }
        Ok((offset, word))
    }

    fn complete(&mut self, physical: u8, offset: usize, word: u32, length: usize, done: bool) {
        let remaining = ((word & LENGTH_MASK) >> 11).saturating_sub(length as u32);
        let next_buffer = ((word & OFFSET_MASK) + length.div_ceil(64) as u32) & OFFSET_MASK;
        let mut updated =
            (word & !(LENGTH_MASK | OFFSET_MASK | TOGGLE_RESET)) | (remaining << 11) | next_buffer;
        if word & TOGGLE_RESET != 0 {
            self.eptoggle &= !(1 << physical);
            if word & TOGGLE_VALUE != 0 {
                self.eptoggle |= 1 << physical;
            }
        } else if physical >= 2 && word & (PERIODIC | TOGGLE_VALUE) == TOGGLE_VALUE {
            self.eptoggle &= !(1 << physical);
        }
        self.eptoggle ^= 1 << physical;
        if done {
            updated &= !ACTIVE;
            self.intstat |= 1 << physical;
            if self.epbufcfg & (1 << physical) != 0 {
                self.epinuse ^= 1 << physical;
            }
        }
        self.memory[offset..offset + 4].copy_from_slice(&updated.to_le_bytes());
    }

    fn skip(&mut self) -> Result<(), LpcipUsbError> {
        for physical in 0..ENDPOINTS {
            if self.epskip & (1 << physical) != 0 {
                let (offset, word) = self.descriptor(physical, false)?;
                self.memory[offset..offset + 4].copy_from_slice(&(word & !ACTIVE).to_le_bytes());
                self.epskip &= !(1 << physical);
                self.intstat |= 1 << physical;
            }
        }
        Ok(())
    }

    fn connection_changed(&mut self, was_connected: bool) {
        if was_connected && !self.link_connected() {
            self.command |= CONNECT_CHANGE;
            self.intstat |= DEVICE_INTERRUPT;
        }
    }
}

/// Cloneable host-side access to the same descriptors and packet SRAM used by
/// CPU MMIO. Transactions do not run firmware; callers step the emulator on NAK.
#[derive(Clone)]
pub struct LpcipUsbHostController {
    state: Arc<Mutex<DeviceState>>,
    phy: LpcipUsbPhy,
}

impl LpcipUsbHostController {
    pub fn phy(&self) -> LpcipUsbPhy {
        self.phy.clone()
    }

    pub fn device_enabled(&self) -> bool {
        self.state.lock().unwrap().command & DEV_EN != 0
    }

    pub fn connected(&self) -> bool {
        self.state.lock().unwrap().connected()
    }

    pub fn device_address(&self) -> u8 {
        self.state.lock().unwrap().address
    }

    pub fn set_vbus(&self, present: bool) {
        self.phy.set_vbus(present);
        let mut state = self.state.lock().unwrap();
        let connected = state.link_connected();
        state.vbus = present;
        state.connection_changed(connected);
    }

    pub fn bus_reset(&self, speed: LpcipUsbSpeed) -> Result<(), LpcipUsbError> {
        let mut state = self.state.lock().unwrap();
        if !state.connected() {
            return Err(LpcipUsbError::Disconnected);
        }
        state.reset_bus(speed);
        // A USB bus reset does not clear SRAM or software-owned descriptors.
        Ok(())
    }

    pub fn host_setup(&self, address: u8, setup: &[u8]) -> Result<(), LpcipUsbError> {
        if setup.len() != 8 {
            return Err(LpcipUsbError::InvalidSetup);
        }
        let mut state = self.state.lock().unwrap();
        state.check_token(address)?;
        let (_, word) = state.descriptor(0, true)?;
        let range = state.buffer(word, 8)?;
        state.memory[range].copy_from_slice(setup);
        state.address = address;
        state.pending_address = address;
        if state
            .recovery
            .as_mut()
            .is_some_and(|recovery| recovery.setup(setup))
        {
            return Ok(());
        }
        state.command |= SETUP;
        state.eptoggle |= 3;
        state.intstat |= 1;
        Ok(())
    }

    pub fn host_in(&self, address: u8, endpoint: u8) -> Result<Vec<u8>, LpcipUsbError> {
        let mut state = self.state.lock().unwrap();
        state.check_token(address)?;
        if endpoint == 0 {
            if let Some(result) = state
                .recovery
                .as_mut()
                .and_then(recovery::Recovery::host_in)
            {
                return result;
            }
        }
        let physical = endpoint
            .checked_mul(2)
            .and_then(|ep| ep.checked_add(1))
            .filter(|&ep| ep < ENDPOINTS)
            .ok_or(LpcipUsbError::InvalidEndpoint)?;
        let (offset, word) = state.ready_descriptor(physical)?;
        let remaining = ((word & LENGTH_MASK) >> 11) as usize;
        let length = remaining.min(state.max_packet(physical, word));
        let data = if length == 0 {
            Vec::new()
        } else {
            let range = state.buffer(word, length)?;
            state.memory[range].to_vec()
        };
        state.complete(physical, offset, word, length, length == remaining);
        Ok(data)
    }

    pub fn host_out(&self, address: u8, endpoint: u8, data: &[u8]) -> Result<(), LpcipUsbError> {
        let mut state = self.state.lock().unwrap();
        state.check_token(address)?;
        if endpoint == 0 {
            if let Some(result) = state
                .recovery
                .as_mut()
                .and_then(|recovery| recovery.host_out(data))
            {
                return result;
            }
        }
        let physical = endpoint
            .checked_mul(2)
            .filter(|&ep| ep < ENDPOINTS)
            .ok_or(LpcipUsbError::InvalidEndpoint)?;
        let (offset, word) = state.ready_descriptor(physical)?;
        let remaining = ((word & LENGTH_MASK) >> 11) as usize;
        let max_packet = state.max_packet(physical, word);
        if data.len() > remaining || data.len() > max_packet {
            return Err(LpcipUsbError::DataTooLong);
        }
        if !data.is_empty() {
            let range = state.buffer(word, data.len())?;
            state.memory[range].copy_from_slice(data);
        }
        let done = data.len() == remaining || data.len() < max_packet;
        state.complete(physical, offset, word, data.len(), done);
        Ok(())
    }

    /// Device 1 has no hardware recovery engine and returns `None`.
    pub fn recovery_snapshot(&self) -> Option<LpcipUsbRecoverySnapshot> {
        self.state
            .lock()
            .unwrap()
            .recovery
            .as_ref()
            .map(recovery::Recovery::snapshot)
    }

    pub fn host_sof(&self, frame: u16) -> Result<(), LpcipUsbError> {
        let mut state = self.state.lock().unwrap();
        if !state.connected() {
            return Err(LpcipUsbError::Disconnected);
        }
        state.frame = frame & 0x7ff;
        state.intstat |= FRAME_INTERRUPT;
        Ok(())
    }

    pub fn interrupt_pending(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.intstat & state.inten & !state.introute != 0
    }

    pub fn fast_interrupt_pending(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.intstat & state.inten & state.introute != 0
    }
}

struct UsbDevice {
    state: Arc<Mutex<DeviceState>>,
    phy: LpcipUsbPhy,
    irq: Option<Irq>,
    legacy_host: Option<crate::UsbHostController>,
    peer: Option<LpcipUsbHostController>,
}

impl Default for UsbDevice {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(DeviceState::default())),
            phy: LpcipUsbPhy::default(),
            irq: None,
            legacy_host: None,
            peer: None,
        }
    }
}

impl UsbDevice {
    fn host_controller(&self) -> LpcipUsbHostController {
        LpcipUsbHostController {
            state: self.state.clone(),
            phy: self.phy.clone(),
        }
    }

    fn device0_memory(&self) -> UsbDev0Mem {
        UsbDev0Mem {
            state: self.state.clone(),
        }
    }

    fn update_irq(&self) {
        if let Some(irq) = &self.irq {
            let legacy_pending = self
                .legacy_host
                .as_ref()
                .is_some_and(crate::UsbHostController::interrupt_pending);
            let peer_pending = self
                .peer
                .as_ref()
                .is_some_and(LpcipUsbHostController::interrupt_pending);
            irq.set_level(
                self.host_controller().interrupt_pending() || peer_pending || legacy_pending,
            );
        }
    }

    fn reset(&mut self) {
        let mut state = self.state.lock().unwrap();
        let memory = std::mem::take(&mut state.memory);
        let vbus = state.vbus;
        let memory_base = state.memory_base;
        let recovery = state.recovery.take().map(|mut recovery| {
            recovery.reset();
            recovery
        });
        *state = DeviceState {
            memory,
            memory_base,
            vbus,
            recovery,
            ..DeviceState::default()
        };
        drop(state);
        self.update_irq();
    }
}

macro_rules! device_register {
    ($read:ident, $write:ident, $field:ident, $register:ident, $mask:expr) => {
        fn $read(&mut self) -> ReadWriteRegister<u32, bits::$register::Register> {
            ReadWriteRegister::new(self.state.lock().unwrap().$field)
        }
        fn $write(&mut self, val: ReadWriteRegister<u32, bits::$register::Register>) {
            self.state.lock().unwrap().$field = val.reg.get() & $mask;
            self.update_irq();
        }
    };
}

impl UsbComboPeripheral for UsbDevice {
    fn poll(&mut self) {
        self.update_irq();
    }

    fn warm_reset(&mut self) {
        self.reset();
    }

    fn update_reset(&mut self) {
        self.reset();
    }

    fn read_dev0_csr_devcmdstat(&mut self) -> ReadWriteRegister<u32, bits::DevcmdstatT::Register> {
        let state = self.state.lock().unwrap();
        let mut value = state.command | u32::from(state.address);
        if state.vbus {
            value |= VBUS;
        }
        if state.connected() {
            value |= match state.speed {
                LpcipUsbSpeed::Full => 1 << 22,
                LpcipUsbSpeed::High => 2 << 22,
            };
        }
        ReadWriteRegister::new(value)
    }

    fn write_dev0_csr_devcmdstat(
        &mut self,
        val: ReadWriteRegister<u32, bits::DevcmdstatT::Register>,
    ) {
        let value = val.reg.get();
        let mut state = self.state.lock().unwrap();
        let connected = state.link_connected();
        state.pending_address = (value & 0x7f) as u8;
        let status = state.command & (SETUP | CHANGE_BITS) & !value;
        // Suspend, speed, VBUS and LPM host status are hardware-owned.
        state.command = status | (value & 0xe021_fe80);
        state.connection_changed(connected);
        drop(state);
        self.update_irq();
    }

    fn read_dev0_csr_info(&mut self) -> ReadWriteRegister<u32, bits::InfoT::Register> {
        let state = self.state.lock().unwrap();
        ReadWriteRegister::new(
            0x0200_0000 | u32::from(state.frame) | (u32::from(state.error_code) << 11),
        )
    }

    fn write_dev0_csr_info(&mut self, val: ReadWriteRegister<u32, bits::InfoT::Register>) {
        self.state.lock().unwrap().error_code = ((val.reg.get() >> 11) & 15) as u8;
    }

    device_register!(
        read_dev0_csr_epliststart,
        write_dev0_csr_epliststart,
        epliststart,
        EpliststartT,
        0xffff_ff00
    );
    device_register!(
        read_dev0_csr_databufstart,
        write_dev0_csr_databufstart,
        databufstart,
        DatabufstartT,
        0xfffe_0000
    );
    device_register!(
        read_dev0_csr_epinuse,
        write_dev0_csr_epinuse,
        epinuse,
        EpinuseT,
        NONCONTROL_ENDPOINTS
    );
    device_register!(
        read_dev0_csr_epbufcfg,
        write_dev0_csr_epbufcfg,
        epbufcfg,
        EpbufcfgT,
        NONCONTROL_ENDPOINTS
    );
    device_register!(
        read_dev0_csr_inten,
        write_dev0_csr_inten,
        inten,
        IntenT,
        u32::MAX
    );
    device_register!(
        read_dev0_csr_introute,
        write_dev0_csr_introute,
        introute,
        IntrouteT,
        u32::MAX
    );

    fn read_dev0_csr_epskip(&mut self) -> ReadWriteRegister<u32, bits::EpskipT::Register> {
        ReadWriteRegister::new(self.state.lock().unwrap().epskip)
    }

    fn write_dev0_csr_epskip(&mut self, val: ReadWriteRegister<u32, bits::EpskipT::Register>) {
        let mut state = self.state.lock().unwrap();
        state.epskip = val.reg.get() & 0x3fff_ffff;
        if let Err(error) = state.skip() {
            eprintln!("[EMU] LPCIP EPSKIP failed: {error}");
        }
        drop(state);
        self.update_irq();
    }

    fn read_dev0_csr_intstat(&mut self) -> ReadWriteRegister<u32, bits::IntstatT::Register> {
        ReadWriteRegister::new(self.state.lock().unwrap().intstat)
    }

    fn write_dev0_csr_intstat(&mut self, val: ReadWriteRegister<u32, bits::IntstatT::Register>) {
        self.state.lock().unwrap().intstat &= !val.reg.get();
        self.update_irq();
    }

    fn read_dev0_csr_intsetstat(&mut self) -> ReadWriteRegister<u32, bits::Intsetstat::Register> {
        ReadWriteRegister::new(self.state.lock().unwrap().intstat)
    }

    fn write_dev0_csr_intsetstat(
        &mut self,
        val: ReadWriteRegister<u32, bits::Intsetstat::Register>,
    ) {
        self.state.lock().unwrap().intstat |= val.reg.get();
        self.update_irq();
    }

    fn read_dev0_csr_config(&mut self) -> ReadWriteRegister<u32, bits::ConfigT::Register> {
        // 28 non-control physical endpoints, both buffering modes and readable
        // toggles. No PHY interface is claimed by this transaction-level model.
        ReadWriteRegister::new(28 | (1 << 5) | (1 << 6) | (1 << 7))
    }

    fn read_dev0_csr_eptoggle(&mut self) -> ReadWriteRegister<u32, bits::EptoggleT::Register> {
        ReadWriteRegister::new(self.state.lock().unwrap().eptoggle)
    }
}

pub struct UsbDev0Mem {
    state: Arc<Mutex<DeviceState>>,
}

impl UsbDev0MemPeripheral for UsbDev0Mem {
    fn read_usb_dev0_mem(&mut self, index: usize) -> u32 {
        let state = self.state.lock().unwrap();
        u32::from_le_bytes(state.memory[index * 4..index * 4 + 4].try_into().unwrap())
    }

    fn write_usb_dev0_mem(&mut self, value: u32, index: usize) {
        self.state.lock().unwrap().memory[index * 4..index * 4 + 4]
            .copy_from_slice(&value.to_le_bytes());
    }
}

pub struct UsbDev1Mem {
    memory: UsbDev0Mem,
}

impl UsbDev1MemPeripheral for UsbDev1Mem {
    fn read_usb_dev1_mem(&mut self, index: usize) -> u32 {
        self.memory.read_usb_dev0_mem(index)
    }

    fn write_usb_dev1_mem(&mut self, value: u32, index: usize) {
        self.memory.write_usb_dev0_mem(value, index);
    }
}

/// Independent Device 1 CSRs. The model exposes one register owner through the
/// MCU bus; it does not attach a competing SoC controller or enable the device.
pub struct UsbDev1 {
    device: UsbDevice,
}

/// Device controllers share protocol semantics, not CSR state or packet SRAM.
/// Only Device 0 owns the hardware-assisted OCP recovery path.
pub struct UsbCombo {
    device0: UsbDevice,
    device1: LpcipUsbHostController,
    hub: Arc<Mutex<hub::Hub>>,
    recovery_events: Option<recovery::RecoveryEvents>,
}

impl Default for UsbCombo {
    fn default() -> Self {
        let phy = LpcipUsbPhy::default();
        let device1 = LpcipUsbHostController {
            phy: phy.clone(),
            state: Arc::new(Mutex::new(DeviceState {
                memory_base: USB_DEV1_MEM_ADDR,
                ..DeviceState::default()
            })),
        };
        Self {
            device0: UsbDevice {
                phy,
                peer: Some(device1.clone()),
                state: Arc::new(Mutex::new(DeviceState {
                    recovery: Some(recovery::Recovery::default()),
                    ..DeviceState::default()
                })),
                ..UsbDevice::default()
            },
            device1,
            hub: Arc::new(Mutex::new(hub::Hub::default())),
            recovery_events: None,
        }
    }
}

impl UsbCombo {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with_irq(irq: Irq, legacy_host: crate::UsbHostController) -> Self {
        let mut combo = Self::new();
        combo.device0.irq = Some(irq);
        combo.device0.legacy_host = Some(legacy_host);
        combo
    }

    pub fn host_controller(&self) -> LpcipUsbHostController {
        self.device0.host_controller()
    }

    pub fn device1_host_controller(&self) -> LpcipUsbHostController {
        self.device1.clone()
    }

    pub fn hub_host_controller(&self) -> LpcipUsbHubHostController {
        LpcipUsbHubHostController::new(
            self.hub.clone(),
            [self.host_controller(), self.device1.clone()],
        )
    }

    pub fn device0_memory(&self) -> UsbDev0Mem {
        self.device0.device0_memory()
    }

    pub fn device1(&self) -> UsbDev1 {
        UsbDev1 {
            device: UsbDevice {
                state: self.device1.state.clone(),
                phy: self.device1.phy.clone(),
                irq: None,
                legacy_host: None,
                peer: None,
            },
        }
    }

    pub fn device1_memory(&self) -> UsbDev1Mem {
        UsbDev1Mem {
            memory: UsbDev0Mem {
                state: self.device1.state.clone(),
            },
        }
    }

    fn recovery_read(&self, offset: u32) -> u32 {
        self.device0
            .state
            .lock()
            .unwrap()
            .recovery
            .as_mut()
            .unwrap()
            .read(offset)
    }

    fn recovery_write(&self, offset: u32, value: u32) {
        self.device0
            .state
            .lock()
            .unwrap()
            .recovery
            .as_mut()
            .unwrap()
            .write(offset, value);
    }

    fn reset(&mut self) {
        self.device0.reset();
        self.device1().device.reset();
        self.hub.lock().unwrap().reset();
        self.device0.phy.reset_gateway();
        self.device0.update_irq();
    }
}

macro_rules! recovery_register {
    ($read:ident, $offset:expr) => {
        fn $read(&mut self) -> u32 {
            self.recovery_read($offset)
        }
    };
    ($read:ident, $write:ident, $offset:expr) => {
        recovery_register!($read, $offset);
        fn $write(&mut self, value: u32) {
            self.recovery_write($offset, value);
        }
    };
    (typed $read:ident, $register:ident, $offset:expr) => {
        fn $read(&mut self) -> ReadWriteRegister<u32, bits::$register::Register> {
            ReadWriteRegister::new(self.recovery_read($offset))
        }
    };
    (typed $read:ident, $write:ident, $register:ident, $offset:expr) => {
        recovery_register!(typed $read, $register, $offset);
        fn $write(&mut self, value: ReadWriteRegister<u32, bits::$register::Register>) {
            self.recovery_write($offset, value.reg.get());
        }
    };
}

macro_rules! forward_register {
    ($field:ident, $bits:ident, $read:ident, $write:ident, $model_read:ident, $model_write:ident, $register:ident) => {
        fn $read(&mut self) -> ReadWriteRegister<u32, $bits::$register::Register> {
            ReadWriteRegister::new(self.$field.$model_read().reg.get())
        }
        fn $write(&mut self, val: ReadWriteRegister<u32, $bits::$register::Register>) {
            self.$field
                .$model_write(ReadWriteRegister::new(val.reg.get()));
        }
    };
}

impl UsbComboPeripheral for UsbCombo {
    fn register_event_channels(
        &mut self,
        to_caliptra: std::sync::mpsc::Sender<caliptra_emu_bus::Event>,
        from_caliptra: std::sync::mpsc::Receiver<caliptra_emu_bus::Event>,
        to_mcu: std::sync::mpsc::Sender<caliptra_emu_bus::Event>,
        from_mcu: std::sync::mpsc::Receiver<caliptra_emu_bus::Event>,
    ) {
        self.recovery_events = Some(recovery::RecoveryEvents::new(
            to_caliptra,
            from_caliptra,
            to_mcu,
            from_mcu,
        ));
    }

    fn poll(&mut self) {
        if let Some(events) = &mut self.recovery_events {
            events.poll(
                self.device0
                    .state
                    .lock()
                    .unwrap()
                    .recovery
                    .as_mut()
                    .unwrap(),
            );
        }
        self.device0.phy.poll();
        self.hub_host_controller().poll();
        self.device0.poll();
    }

    fn warm_reset(&mut self) {
        self.reset();
    }

    fn update_reset(&mut self) {
        self.reset();
    }

    recovery_register!(read_recovery_prot_cap_0, 0x04);
    recovery_register!(read_recovery_prot_cap_1, 0x08);
    recovery_register!(typed read_recovery_prot_cap_2, write_recovery_prot_cap_2, ProtCap2, 0x0c);
    recovery_register!(typed read_recovery_prot_cap_3, write_recovery_prot_cap_3, ProtCap3, 0x10);
    recovery_register!(typed read_recovery_device_id_0, write_recovery_device_id_0, DeviceId0, 0x14);
    recovery_register!(read_recovery_device_id_1, write_recovery_device_id_1, 0x18);
    recovery_register!(read_recovery_device_id_2, write_recovery_device_id_2, 0x1c);
    recovery_register!(read_recovery_device_id_3, write_recovery_device_id_3, 0x20);
    recovery_register!(read_recovery_device_id_4, write_recovery_device_id_4, 0x24);
    recovery_register!(read_recovery_device_id_5, write_recovery_device_id_5, 0x28);
    recovery_register!(typed read_recovery_device_status_0, write_recovery_device_status_0, DeviceStatus0, 0x30);
    recovery_register!(typed read_recovery_device_status_1, DeviceStatus1, 0x34);
    recovery_register!(typed read_recovery_device_reset, write_recovery_device_reset, DeviceReset, 0x38);
    recovery_register!(typed read_recovery_recovery_ctrl, write_recovery_recovery_ctrl, RecoveryCtrl, 0x3c);
    recovery_register!(typed read_recovery_recovery_status, write_recovery_recovery_status, RecoveryStatus, 0x40);
    recovery_register!(typed read_recovery_hw_status, write_recovery_hw_status, HwStatus, 0x44);
    recovery_register!(typed read_recovery_indirect_fifo_ctrl_0, write_recovery_indirect_fifo_ctrl_0, IndirectFifoCtrl0, 0x48);
    recovery_register!(
        read_recovery_indirect_fifo_ctrl_1,
        write_recovery_indirect_fifo_ctrl_1,
        0x4c
    );
    recovery_register!(typed read_recovery_indirect_fifo_status_0, IndirectFifoStatus0, 0x50);
    recovery_register!(read_recovery_indirect_fifo_status_1, 0x54);
    recovery_register!(read_recovery_indirect_fifo_status_2, 0x58);
    recovery_register!(read_recovery_indirect_fifo_status_3, 0x5c);
    recovery_register!(read_recovery_indirect_fifo_status_4, 0x60);
    recovery_register!(read_recovery_indirect_fifo_data, 0x68);
    recovery_register!(typed read_recovery_vendor, write_recovery_vendor, Vendor, 0x100);
    recovery_register!(typed read_recovery_caliptra_ctrl, write_recovery_caliptra_ctrl, CaliptraCtrl, 0x200);
    recovery_register!(typed read_recovery_caliptra_status, CaliptraStatus, 0x204);
    recovery_register!(read_recovery_window_pad, 0x7fc);

    forward_register!(
        device0,
        bits,
        read_dev0_csr_devcmdstat,
        write_dev0_csr_devcmdstat,
        read_dev0_csr_devcmdstat,
        write_dev0_csr_devcmdstat,
        DevcmdstatT
    );
    forward_register!(
        device0,
        bits,
        read_dev0_csr_info,
        write_dev0_csr_info,
        read_dev0_csr_info,
        write_dev0_csr_info,
        InfoT
    );
    forward_register!(
        device0,
        bits,
        read_dev0_csr_epliststart,
        write_dev0_csr_epliststart,
        read_dev0_csr_epliststart,
        write_dev0_csr_epliststart,
        EpliststartT
    );
    forward_register!(
        device0,
        bits,
        read_dev0_csr_databufstart,
        write_dev0_csr_databufstart,
        read_dev0_csr_databufstart,
        write_dev0_csr_databufstart,
        DatabufstartT
    );
    forward_register!(
        device0,
        bits,
        read_dev0_csr_epskip,
        write_dev0_csr_epskip,
        read_dev0_csr_epskip,
        write_dev0_csr_epskip,
        EpskipT
    );
    forward_register!(
        device0,
        bits,
        read_dev0_csr_epinuse,
        write_dev0_csr_epinuse,
        read_dev0_csr_epinuse,
        write_dev0_csr_epinuse,
        EpinuseT
    );
    forward_register!(
        device0,
        bits,
        read_dev0_csr_epbufcfg,
        write_dev0_csr_epbufcfg,
        read_dev0_csr_epbufcfg,
        write_dev0_csr_epbufcfg,
        EpbufcfgT
    );
    forward_register!(
        device0,
        bits,
        read_dev0_csr_intstat,
        write_dev0_csr_intstat,
        read_dev0_csr_intstat,
        write_dev0_csr_intstat,
        IntstatT
    );
    forward_register!(
        device0,
        bits,
        read_dev0_csr_inten,
        write_dev0_csr_inten,
        read_dev0_csr_inten,
        write_dev0_csr_inten,
        IntenT
    );
    forward_register!(
        device0,
        bits,
        read_dev0_csr_intsetstat,
        write_dev0_csr_intsetstat,
        read_dev0_csr_intsetstat,
        write_dev0_csr_intsetstat,
        Intsetstat
    );
    forward_register!(
        device0,
        bits,
        read_dev0_csr_introute,
        write_dev0_csr_introute,
        read_dev0_csr_introute,
        write_dev0_csr_introute,
        IntrouteT
    );

    fn read_dev0_csr_config(&mut self) -> ReadWriteRegister<u32, bits::ConfigT::Register> {
        ReadWriteRegister::new(
            self.device0.read_dev0_csr_config().reg.get() | bits::ConfigT::Ulpi::SET.value,
        )
    }

    fn read_dev0_csr_eptoggle(&mut self) -> ReadWriteRegister<u32, bits::EptoggleT::Register> {
        self.device0.read_dev0_csr_eptoggle()
    }

    fn read_hub_descriptor_low(&mut self, index: usize) -> u32 {
        self.hub.lock().unwrap().read_word(index)
    }

    fn write_hub_descriptor_low(&mut self, value: u32, index: usize) {
        self.hub.lock().unwrap().write_word(index, value);
    }

    fn read_hub_descriptor_high(&mut self, index: usize) -> u32 {
        self.hub.lock().unwrap().read_word(index + 16)
    }

    fn write_hub_descriptor_high(&mut self, value: u32, index: usize) {
        self.hub.lock().unwrap().write_word(index + 16, value);
    }

    fn read_hub_control(&mut self) -> ReadWriteRegister<u32, bits::Control::Register> {
        ReadWriteRegister::new(self.hub.lock().unwrap().read_word(12))
    }

    fn write_hub_control(&mut self, value: ReadWriteRegister<u32, bits::Control::Register>) {
        self.hub.lock().unwrap().write_word(12, value.reg.get());
    }

    fn read_hub_ulpidebug(&mut self) -> ReadWriteRegister<u32, bits::UlpidebugT::Register> {
        ReadWriteRegister::new(self.device0.phy.read())
    }

    fn write_hub_ulpidebug(&mut self, value: ReadWriteRegister<u32, bits::UlpidebugT::Register>) {
        self.device0.phy.write(value.reg.get());
    }
}

impl UsbDev1Peripheral for UsbDev1 {
    fn warm_reset(&mut self) {
        self.device.reset();
    }

    fn update_reset(&mut self) {
        self.device.reset();
    }

    forward_register!(
        device,
        dev1_bits,
        read_devcmdstat,
        write_devcmdstat,
        read_dev0_csr_devcmdstat,
        write_dev0_csr_devcmdstat,
        DevcmdstatT
    );
    forward_register!(
        device,
        dev1_bits,
        read_info,
        write_info,
        read_dev0_csr_info,
        write_dev0_csr_info,
        InfoT
    );
    forward_register!(
        device,
        dev1_bits,
        read_epliststart,
        write_epliststart,
        read_dev0_csr_epliststart,
        write_dev0_csr_epliststart,
        EpliststartT
    );
    forward_register!(
        device,
        dev1_bits,
        read_databufstart,
        write_databufstart,
        read_dev0_csr_databufstart,
        write_dev0_csr_databufstart,
        DatabufstartT
    );
    forward_register!(
        device,
        dev1_bits,
        read_epskip,
        write_epskip,
        read_dev0_csr_epskip,
        write_dev0_csr_epskip,
        EpskipT
    );
    forward_register!(
        device,
        dev1_bits,
        read_epinuse,
        write_epinuse,
        read_dev0_csr_epinuse,
        write_dev0_csr_epinuse,
        EpinuseT
    );
    forward_register!(
        device,
        dev1_bits,
        read_epbufcfg,
        write_epbufcfg,
        read_dev0_csr_epbufcfg,
        write_dev0_csr_epbufcfg,
        EpbufcfgT
    );
    forward_register!(
        device,
        dev1_bits,
        read_intstat,
        write_intstat,
        read_dev0_csr_intstat,
        write_dev0_csr_intstat,
        IntstatT
    );
    forward_register!(
        device,
        dev1_bits,
        read_inten,
        write_inten,
        read_dev0_csr_inten,
        write_dev0_csr_inten,
        IntenT
    );
    forward_register!(
        device,
        dev1_bits,
        read_intsetstat,
        write_intsetstat,
        read_dev0_csr_intsetstat,
        write_dev0_csr_intsetstat,
        Intsetstat
    );
    forward_register!(
        device,
        dev1_bits,
        read_introute,
        write_introute,
        read_dev0_csr_introute,
        write_dev0_csr_introute,
        IntrouteT
    );

    fn read_config(&mut self) -> ReadWriteRegister<u32, dev1_bits::ConfigT::Register> {
        ReadWriteRegister::new(self.device.read_dev0_csr_config().reg.get())
    }

    fn read_eptoggle(&mut self) -> ReadWriteRegister<u32, dev1_bits::EptoggleT::Register> {
        ReadWriteRegister::new(self.device.read_dev0_csr_eptoggle().reg.get())
    }
}

#[cfg(test)]
mod hub_tests;
#[cfg(test)]
mod tests;
