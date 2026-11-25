// Licensed under the Apache-2.0 license

use super::*;
use tock_registers::interfaces::ReadWriteable;
use usb_combo::bits::CaliptraCtrl;

const BULK_OUT: usize = 4;
const BULK_IN: usize = 6;
const BULK_OUT_BUFFER: usize = 0x200;
const BULK_IN_BUFFER: usize = 0x400;
const BULK_MAX: usize = 512;
const CONTROL_MAX: usize = 1024;
const TOGGLE: u32 = 1 << 27;
const TOGGLE_RESET: u32 = 1 << 28;

#[derive(Clone, Copy)]
enum ControlAction {
    Standard(Action),
    Alternate(u8),
    Mode(u8),
    Halt { input: bool, halted: bool },
    Store(usize),
}

enum Response {
    Read(usize),
    Write(usize),
    Status(ControlAction),
}

enum ControlStage {
    Idle,
    Read {
        total: usize,
        sent: usize,
        requested: usize,
        zlp: bool,
    },
    Write {
        total: usize,
        received: usize,
        armed: usize,
    },
    StatusOut,
    StatusIn(ControlAction),
}

/// Source/sink and loopback personality on EP1, independent of OCP recovery.
pub struct UsbStressDriver {
    driver: LpcipUsbDriver,
    control: ControlStage,
    data: [u8; CONTROL_MAX],
    stored: [u8; CONTROL_MAX],
    stored_length: usize,
    alternate: u8,
    mode: u8,
    halted: [bool; 2],
    armed: [bool; 2],
    in_length: usize,
    loopback_pending: bool,
    counters: [u32; 4],
}

impl UsbStressDriver {
    pub const fn new(params: UsbParams) -> Self {
        Self {
            driver: LpcipUsbDriver::new(params),
            control: ControlStage::Idle,
            data: [0; CONTROL_MAX],
            stored: [0; CONTROL_MAX],
            stored_length: 0,
            alternate: 0,
            mode: 0,
            halted: [false; 2],
            armed: [false; 2],
            in_length: 0,
            loopback_pending: false,
            counters: [0; 4],
        }
    }

    pub fn initialize(&mut self) -> Result<(), UsbError> {
        let params = &self.driver.params;
        if params.packet_memory.usb_dev0_mem.len() * 4 < BULK_IN_BUFFER + BULK_MAX
            || (&*params.packet_memory as *const _ as usize) & 0x1ffff
                > 0x20000 - BULK_IN_BUFFER - BULK_MAX
        {
            return Err(UsbError::InvalidPacketMemory);
        }
        if params.shared_phy_owner {
            params
                .registers
                .recovery_caliptra_ctrl
                .modify(CaliptraCtrl::OcpPathDisable::SET);
            if !params
                .registers
                .recovery_caliptra_ctrl
                .is_set(CaliptraCtrl::OcpPathDisable)
            {
                return Err(UsbError::RecoveryPathEnabled);
            }
        }
        self.driver.initialize()?;
        self.reset_session();
        Ok(())
    }

    fn packet_size(&self) -> usize {
        if !self.driver.params.force_full_speed
            && (self.driver.params.registers.dev0_csr_devcmdstat.get() >> 22) & 3 == 2
        {
            512
        } else {
            64
        }
    }

    fn reset_session(&mut self) {
        self.control = ControlStage::Idle;
        self.alternate = 0;
        self.mode = 0;
        self.halted = [false; 2];
        self.armed = [false; 2];
        self.loopback_pending = false;
        self.counters = [0; 4];
        self.stored_length = 0;
    }

    fn buffer_write(&self, offset: usize, bytes: &[u8]) -> Result<(), UsbError> {
        for (index, chunk) in bytes.chunks(4).enumerate() {
            let mut word = [0; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            self.driver
                .write_word(offset / 4 + index, u32::from_le_bytes(word))?;
        }
        Ok(())
    }

    fn buffer_read(&self, offset: usize, bytes: &mut [u8]) -> Result<(), UsbError> {
        for (index, chunk) in bytes.chunks_mut(4).enumerate() {
            let word = self.driver.read_word(offset / 4 + index)?.to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        Ok(())
    }

    fn arm_control_next(&self, input: bool, length: usize) -> Result<(), UsbError> {
        let (descriptor, offset) = if input {
            (2, IN_OFFSET)
        } else {
            (0, OUT_OFFSET)
        };
        let toggle = self.driver.read_word(descriptor)? & TOGGLE;
        self.driver.write_word(
            descriptor,
            self.driver.descriptor(offset, length)? | ACTIVE | toggle,
        )
    }

    fn cancel_bulk_endpoint(&mut self, input: bool) -> Result<(), UsbError> {
        let direction = usize::from(input);
        let descriptor = if input { BULK_IN } else { BULK_OUT };
        let bit = 1 << (2 + direction);
        if self.armed[direction] {
            self.driver.params.registers.dev0_csr_epskip.set(bit);
            self.driver.wait(
                || self.driver.params.registers.dev0_csr_epskip.get() & bit == 0,
                UsbError::CancellationTimeout,
            )?;
        }
        self.driver.params.registers.dev0_csr_intstat.set(bit);
        self.driver
            .write_word(descriptor, DISABLED | TOGGLE_RESET)?;
        self.armed[direction] = false;
        Ok(())
    }

    fn reset_bulk(&mut self) -> Result<(), UsbError> {
        self.cancel_bulk_endpoint(false)?;
        self.cancel_bulk_endpoint(true)?;
        self.halted = [false; 2];
        self.loopback_pending = false;
        Ok(())
    }

    fn arm_bulk(&mut self, input: bool, length: usize) -> Result<(), UsbError> {
        let direction = usize::from(input);
        let (descriptor, offset) = if input {
            (BULK_IN, BULK_IN_BUFFER)
        } else {
            (BULK_OUT, BULK_OUT_BUFFER)
        };
        if length > BULK_MAX {
            return Err(UsbError::InvalidPacketMemory);
        }
        let address = (self.driver.buffer_base & 0x1ffff) as usize + offset;
        let toggle = self.driver.read_word(descriptor)? & (TOGGLE | TOGGLE_RESET);
        self.driver.write_word(
            descriptor,
            (address as u32 >> 6) | ((length as u32) << 11) | ACTIVE | toggle,
        )?;
        self.armed[direction] = true;
        if input {
            self.in_length = length;
        }
        Ok(())
    }

    fn enable_idle_bulk(&self, input: bool) -> Result<(), UsbError> {
        let (descriptor, offset) = if input {
            (BULK_IN, BULK_IN_BUFFER)
        } else {
            (BULK_OUT, BULK_OUT_BUFFER)
        };
        let word = self.driver.read_word(descriptor)?;
        if word & DISABLED != 0 {
            let address = (self.driver.buffer_base & 0x1ffff) as usize + offset;
            self.driver.write_word(
                descriptor,
                (address as u32 >> 6) | (word & (TOGGLE | TOGGLE_RESET)),
            )?;
        }
        Ok(())
    }

    fn poll_bulk(&mut self) -> Result<(), UsbError> {
        if self.driver.configuration != 1 || self.alternate != 1 {
            return Ok(());
        }
        let packet = self.packet_size();
        if self.armed[1] && self.driver.read_word(BULK_IN)? & ACTIVE == 0 {
            self.armed[1] = false;
            self.loopback_pending = false;
            self.counters[1] = self.counters[1].wrapping_add(self.in_length as u32);
            self.counters[3] = self.counters[3].wrapping_add(1);
            self.driver.params.registers.dev0_csr_intstat.set(8);
        }
        if self.armed[0] && self.driver.read_word(BULK_OUT)? & ACTIVE == 0 {
            self.armed[0] = false;
            let residual = (self.driver.read_word(BULK_OUT)? >> 11) & 0x7fff;
            let received = packet
                .checked_sub(residual as usize)
                .ok_or(UsbError::InvalidPacketMemory)?;
            self.counters[0] = self.counters[0].wrapping_add(received as u32);
            self.counters[2] = self.counters[2].wrapping_add(1);
            self.driver.params.registers.dev0_csr_intstat.set(4);
            if self.mode == 1 {
                for index in 0..received.div_ceil(4) {
                    self.driver.write_word(
                        BULK_IN_BUFFER / 4 + index,
                        self.driver.read_word(BULK_OUT_BUFFER / 4 + index)?,
                    )?;
                }
                self.loopback_pending = true;
                self.in_length = received;
            }
        }
        if !self.halted[1] && !self.armed[1] {
            if self.mode == 0 {
                for index in 0..packet / 4 {
                    self.driver.write_word(BULK_IN_BUFFER / 4 + index, 0)?;
                }
                self.arm_bulk(true, packet)?;
            } else if self.loopback_pending {
                self.arm_bulk(true, self.in_length)?;
            } else {
                self.enable_idle_bulk(true)?;
            }
        }
        if !self.halted[0]
            && !self.armed[0]
            && (self.mode == 0 || (!self.loopback_pending && !self.halted[1]))
        {
            self.arm_bulk(false, packet)?;
        } else if !self.halted[0] && !self.armed[0] {
            self.enable_idle_bulk(false)?;
        }
        Ok(())
    }

    fn apply(&mut self, action: ControlAction) -> Result<UsbPoll, UsbError> {
        match action {
            ControlAction::Standard(Action::Address(address)) => {
                self.driver.address = address;
                self.driver.command(true, 0);
                if self.driver.params.enable_logs {
                    caliptra_mcu_romtime::println!("[usb-stress] Address set to {}", address);
                }
            }
            ControlAction::Standard(Action::Configuration(configuration)) => {
                self.reset_bulk()?;
                self.driver.configuration = configuration;
                self.alternate = 0;
                self.mode = 0;
                self.counters = [0; 4];
                return Ok(UsbPoll::ConfigurationChanged(configuration));
            }
            ControlAction::Standard(Action::None) => {}
            ControlAction::Alternate(alternate) => {
                self.reset_bulk()?;
                self.alternate = alternate;
            }
            ControlAction::Mode(mode) => {
                self.reset_bulk()?;
                self.mode = mode;
                self.counters = [0; 4];
            }
            ControlAction::Halt { input, halted } => {
                let direction = usize::from(input);
                let descriptor = if input { BULK_IN } else { BULK_OUT };
                if halted {
                    self.cancel_bulk_endpoint(input)?;
                    self.driver.write_word(descriptor, STALL | TOGGLE_RESET)?;
                    if input && self.mode == 1 {
                        self.cancel_bulk_endpoint(false)?;
                        self.loopback_pending = false;
                    }
                } else if self.halted[direction] {
                    self.driver.write_word(descriptor, TOGGLE_RESET)?;
                } else {
                    // Reset DATA0 without abandoning a queued transfer.
                    let word = self.driver.read_word(descriptor)?;
                    self.driver
                        .write_word(descriptor, (word & !TOGGLE) | TOGGLE_RESET)?;
                }
                self.halted[direction] = halted;
            }
            ControlAction::Store(length) => {
                self.stored[..length].copy_from_slice(&self.data[..length]);
                self.stored_length = length;
            }
        }
        self.poll_bulk()?;
        Ok(UsbPoll::Progress)
    }

    fn request(&mut self, setup: &SetupPacket) -> Result<Response, UsbError> {
        let value = u16::from_le_bytes(setup.w_value);
        let index = u16::from_le_bytes(setup.w_index);
        let length = usize::from(setup.data_length());
        let configured = self.driver.configuration == 1;
        match (setup.bm_request_type.0, setup.b_request) {
            (0x80, 6) => match setup.w_value[1] {
                1 if value == 0x100 && index == 0 => {
                    let descriptor = DeviceDescriptor::ocp(
                        0x200,
                        self.driver.params.vendor_id,
                        self.driver.params.product_id,
                        self.driver.params.device_revision,
                        0,
                        0,
                        0,
                    );
                    self.data[..18].copy_from_slice(descriptor.as_bytes());
                    return Ok(Response::Read(18));
                }
                kind @ (2 | 7)
                    if value & 0xff == 0
                        && index == 0
                        && (kind == 2 || !self.driver.params.force_full_speed) =>
                {
                    let packet = if kind == 7 {
                        576 - self.packet_size()
                    } else {
                        self.packet_size()
                    };
                    let [lo, hi] = (packet as u16).to_le_bytes();
                    self.data[..41].copy_from_slice(&[
                        9,
                        kind,
                        41,
                        0,
                        1,
                        1,
                        0,
                        if self.driver.params.self_powered {
                            0xc0
                        } else {
                            0x80
                        },
                        self.driver.params.max_power_2ma,
                        9,
                        4,
                        0,
                        0,
                        0,
                        0xff,
                        0,
                        0,
                        1,
                        9,
                        4,
                        0,
                        1,
                        2,
                        0xff,
                        0,
                        0,
                        1,
                        7,
                        5,
                        1,
                        2,
                        lo,
                        hi,
                        0,
                        7,
                        5,
                        0x81,
                        2,
                        lo,
                        hi,
                        0,
                    ]);
                    return Ok(Response::Read(41));
                }
                3 if value == 0x301 && index == LANG_ID_ENGLISH_US => {
                    let text = b"Caliptra USB stress";
                    self.data[0] = (2 + text.len() * 2) as u8;
                    self.data[1] = 3;
                    for (i, byte) in text.iter().enumerate() {
                        self.data[2 + i * 2] = *byte;
                        self.data[3 + i * 2] = 0;
                    }
                    return Ok(Response::Read(2 + text.len() * 2));
                }
                _ => {}
            },
            (0x81, 10) if configured && value == 0 && index == 0 && length == 1 => {
                self.data[0] = self.alternate;
                return Ok(Response::Read(1));
            }
            (1, 11) if configured && value <= 1 && index == 0 && length == 0 => {
                return Ok(Response::Status(ControlAction::Alternate(value as u8)));
            }
            (0x82, 0)
                if configured
                    && self.alternate == 1
                    && value == 0
                    && matches!(index, 1 | 0x81)
                    && length == 2 =>
            {
                self.data[..2]
                    .copy_from_slice(&[u8::from(self.halted[usize::from(index == 0x81)]), 0]);
                return Ok(Response::Read(2));
            }
            (2, operation @ (1 | 3))
                if configured
                    && self.alternate == 1
                    && value == 0
                    && matches!(index, 1 | 0x81)
                    && length == 0 =>
            {
                return Ok(Response::Status(ControlAction::Halt {
                    input: index == 0x81,
                    halted: operation == 3,
                }));
            }
            (0x40, 0x5b) if configured && value == 0 && index == 0 && length <= CONTROL_MAX => {
                return Ok(if length == 0 {
                    Response::Status(ControlAction::Store(0))
                } else {
                    Response::Write(length)
                });
            }
            (0xc0, 0x5c) if configured && value == 0 && index == 0 && length <= CONTROL_MAX => {
                self.data[..self.stored_length].copy_from_slice(&self.stored[..self.stored_length]);
                return Ok(Response::Read(self.stored_length));
            }
            (0xc0, 0x5d) if configured && value == 0 && index == 0 => {
                let packet = self.packet_size() as u16;
                self.data[..16].copy_from_slice(&[
                    b'C',
                    b'S',
                    b'T',
                    b'1',
                    1,
                    self.mode,
                    self.alternate,
                    if packet == 512 { 2 } else { 1 },
                    packet as u8,
                    (packet >> 8) as u8,
                    0,
                    4,
                    0x0f,
                    0,
                    0,
                    0,
                ]);
                return Ok(Response::Read(16));
            }
            (0x40, 0x5e) if configured && index == 0 && length == 0 && value <= 1 => {
                return Ok(Response::Status(ControlAction::Mode(value as u8)));
            }
            (0xc0, 0x5f) if configured && value == 0 && index == 0 => {
                for (i, counter) in self.counters.iter().enumerate() {
                    self.data[i * 4..i * 4 + 4].copy_from_slice(&counter.to_le_bytes());
                }
                return Ok(Response::Read(16));
            }
            _ => {}
        }
        let reply = request(
            &self.driver.params,
            setup,
            self.driver.address,
            self.driver.configuration,
        )?;
        if let Some(action) = reply.action {
            Ok(Response::Status(ControlAction::Standard(action)))
        } else {
            self.data[..reply.length].copy_from_slice(&reply.data[..reply.length]);
            Ok(Response::Read(reply.length))
        }
    }

    fn setup(&mut self) -> Result<UsbPoll, UsbError> {
        let mut bytes = [0; 8];
        self.buffer_read(SETUP_OFFSET, &mut bytes)?;
        let setup: SetupPacket = zerocopy::transmute!(bytes);
        self.driver.cancel()?;
        match self.request(&setup) {
            Ok(Response::Status(action)) => {
                self.driver.arm(true, 0)?;
                self.control = ControlStage::StatusIn(action);
            }
            Ok(Response::Read(total)) => {
                let requested = usize::from(setup.data_length());
                let total = total.min(requested);
                if requested == 0 {
                    self.driver.arm(true, 0)?;
                    self.control = ControlStage::StatusIn(ControlAction::Standard(Action::None));
                } else {
                    let sent = total.min(PACKET_SIZE);
                    self.buffer_write(IN_OFFSET, &self.data[..sent])?;
                    self.driver.arm(true, sent)?;
                    self.control = ControlStage::Read {
                        total,
                        sent,
                        requested,
                        zlp: total != 0 && needs_zlp(total, requested),
                    };
                }
            }
            Ok(Response::Write(total)) => {
                let armed = total.min(PACKET_SIZE);
                self.driver.arm(false, armed)?;
                self.control = ControlStage::Write {
                    total,
                    received: 0,
                    armed,
                };
            }
            Err(UsbError::UnsupportedRequest) => {
                self.control = ControlStage::Idle;
                let result = self.driver.stall()?;
                self.driver.command(true, DevcmdstatT::Setup::SET.value);
                return Ok(result);
            }
            Err(error) => return Err(error),
        }
        self.driver.command(true, DevcmdstatT::Setup::SET.value);
        Ok(UsbPoll::Progress)
    }

    fn poll_control(&mut self) -> Result<UsbPoll, UsbError> {
        match self.control {
            ControlStage::Read {
                total,
                sent,
                requested,
                zlp,
            } if self.driver.read_word(2)? & ACTIVE == 0 => {
                self.driver.params.registers.dev0_csr_intstat.set(2);
                if sent < total {
                    let next = (total - sent).min(PACKET_SIZE);
                    self.buffer_write(IN_OFFSET, &self.data[sent..sent + next])?;
                    self.arm_control_next(true, next)?;
                    self.control = ControlStage::Read {
                        total,
                        sent: sent + next,
                        requested,
                        zlp,
                    };
                } else if zlp {
                    self.arm_control_next(true, 0)?;
                    self.control = ControlStage::Read {
                        total,
                        sent,
                        requested,
                        zlp: false,
                    };
                } else {
                    self.driver.arm(false, PACKET_SIZE)?;
                    self.control = ControlStage::StatusOut;
                }
                Ok(UsbPoll::Progress)
            }
            ControlStage::Write {
                total,
                received,
                armed,
            } if self.driver.read_word(0)? & ACTIVE == 0 => {
                let residual = (self.driver.read_word(0)? >> 11) & 0x7fff;
                if residual != 0 {
                    self.control = ControlStage::Idle;
                    return self.driver.stall();
                }
                let mut packet = [0; PACKET_SIZE];
                self.buffer_read(OUT_OFFSET, &mut packet[..armed])?;
                self.data[received..received + armed].copy_from_slice(&packet[..armed]);
                let received = received + armed;
                if received == total {
                    self.driver.arm(true, 0)?;
                    self.control = ControlStage::StatusIn(ControlAction::Store(total));
                } else {
                    let armed = (total - received).min(PACKET_SIZE);
                    self.arm_control_next(false, armed)?;
                    self.control = ControlStage::Write {
                        total,
                        received,
                        armed,
                    };
                }
                Ok(UsbPoll::Progress)
            }
            ControlStage::StatusOut if self.driver.read_word(0)? & ACTIVE == 0 => {
                if (self.driver.read_word(0)? >> 11) & 0x7fff != PACKET_SIZE as u32 {
                    self.control = ControlStage::Idle;
                    return self.driver.stall();
                }
                self.driver.params.registers.dev0_csr_intstat.set(1);
                self.control = ControlStage::Idle;
                Ok(UsbPoll::Progress)
            }
            ControlStage::StatusIn(action) if self.driver.read_word(2)? & ACTIVE == 0 => {
                self.driver.params.registers.dev0_csr_intstat.set(2);
                self.control = ControlStage::Idle;
                self.apply(action)
            }
            _ => Ok(UsbPoll::Idle),
        }
    }

    pub fn poll(&mut self) -> Result<UsbPoll, UsbError> {
        if !self.driver.initialized {
            return Err(UsbError::NotInitialized);
        }
        let command = self.driver.params.registers.dev0_csr_devcmdstat.get();
        if command & DevcmdstatT::VbusDebounced::SET.value == 0 {
            self.driver.cancel()?;
            self.reset_bulk()?;
            self.driver.command(false, 0);
            self.driver.initialized = false;
            self.reset_session();
            return Ok(UsbPoll::Disconnected);
        }
        if command & DevcmdstatT::DresC::SET.value != 0 {
            self.driver.cancel()?;
            self.reset_bulk()?;
            self.driver.address = 0;
            self.driver.configuration = 0;
            self.reset_session();
            self.driver.command(true, DevcmdstatT::DresC::SET.value);
            if self.driver.params.enable_logs {
                caliptra_mcu_romtime::println!("[usb-stress] Bus reset");
            }
            return Ok(UsbPoll::BusReset);
        }
        let mut event = UsbPoll::Idle;
        if matches!(self.control, ControlStage::StatusIn(_))
            && self.driver.read_word(2)? & ACTIVE == 0
            && self.driver.params.registers.dev0_csr_intstat.get() & 2 != 0
        {
            event = self.poll_control()?;
        }
        self.poll_bulk()?;
        if command & DevcmdstatT::Setup::SET.value != 0 {
            self.setup()
        } else {
            let control_event = self.poll_control()?;
            Ok(if control_event == UsbPoll::Idle {
                event
            } else {
                control_event
            })
        }
    }
}

#[cfg(test)]
mod tests;
