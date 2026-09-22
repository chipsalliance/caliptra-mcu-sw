// Licensed under the Apache-2.0 license.

use caliptra_emu_bus::{Device, Event, EventData};
use caliptra_mcu_emulator_registers_generated::{
    usb_combo::{UsbComboGenerated, UsbComboPeripheral},
    usb_dev0_mem::{UsbDev0MemGenerated, UsbDev0MemPeripheral},
    usb_dev1::{UsbDev1Generated, UsbDev1Peripheral},
    usb_dev1_mem::{UsbDev1MemGenerated, UsbDev1MemPeripheral},
};
use caliptra_mcu_ocp::protocol::RecoveryCommand;
use std::collections::VecDeque;
use std::sync::{mpsc, Arc, Mutex};
use tock_registers::interfaces::Readable;

use crate::usbdev::UsbTransactionError;

const OCP_RECOVERY_INTERFACE: u8 = 0;
const OCP_MAX_CONTROL_TRANSFER_SIZE: usize = 64;
const OCP_FIFO_DEPTH_DWORDS: usize = 64;
const OCP_FIFO_MAX_TRANSFER_DWORDS: u32 = 64;

#[derive(Debug, Eq, PartialEq)]
pub enum UsbControlTransferResult {
    NotClaimed,
    Complete(Vec<u8>),
}

#[derive(Debug, Eq, PartialEq)]
pub enum UsbRecoveryError {
    Stall,
    UnsupportedDataPath,
    Disconnected,
}

const EP0_OUT_DESCRIPTOR: usize = 0;
const SETUP_DESCRIPTOR: usize = 1;
const EP0_IN_DESCRIPTOR: usize = 2;
const DESCRIPTOR_ACTIVE: u32 = 1 << 31;
const DESCRIPTOR_STALL: u32 = 1 << 29;
const DESCRIPTOR_NBYTES_SHIFT: u32 = 11;
const DESCRIPTOR_NBYTES_MASK: u32 = 0x7fff;
const DESCRIPTOR_OFFSET_MASK: u32 = 0x7ff;
const DEVCMDSTAT_DEV_ADDR_MASK: u32 = 0x7f;
const DEVCMDSTAT_DEV_EN: u32 = 1 << 7;
const DEVCMDSTAT_SETUP: u32 = 1 << 8;
const DEVCMDSTAT_DCON: u32 = 1 << 16;
const DEVCMDSTAT_DRES_C: u32 = 1 << 26;
const DEVCMDSTAT_VBUS_DEBOUNCED: u32 = 1 << 28;
const DEVCMDSTAT_W1C_MASK: u32 = DEVCMDSTAT_SETUP | (0xf << 24);
const INTSTAT_EP0OUT: u32 = 1;
const INTSTAT_EP0IN: u32 = 1 << 1;
const INTSTAT_DEV_INT: u32 = 1 << 31;

#[derive(Debug)]
struct LpcipState {
    memory: UsbDev0MemGenerated,
    devcmdstat: u32,
    intstat: u32,
}

impl LpcipState {
    fn new() -> Self {
        Self {
            memory: UsbDev0MemGenerated::new(),
            devcmdstat: DEVCMDSTAT_VBUS_DEBOUNCED,
            intstat: 0,
        }
    }

    fn descriptor(&mut self, index: usize) -> u32 {
        self.memory.read_usb_dev0_mem(index)
    }

    fn write_descriptor(&mut self, index: usize, value: u32) {
        self.memory.write_usb_dev0_mem(value, index);
    }

    fn descriptor_buffer_offset(descriptor: u32) -> usize {
        ((descriptor & DESCRIPTOR_OFFSET_MASK) as usize) << 6
    }

    fn write_buffer(&mut self, offset: usize, data: &[u8]) {
        for (index, chunk) in data.chunks(4).enumerate() {
            let mut word = [0; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            self.memory
                .write_usb_dev0_mem(u32::from_le_bytes(word), offset / 4 + index);
        }
    }

    fn read_buffer(&mut self, offset: usize, length: usize) -> Vec<u8> {
        let mut data = Vec::with_capacity(length);
        for index in 0..length.div_ceil(4) {
            data.extend_from_slice(
                &self
                    .memory
                    .read_usb_dev0_mem(offset / 4 + index)
                    .to_le_bytes(),
            );
        }
        data.truncate(length);
        data
    }
}

#[derive(Clone)]
pub struct LpcipUsbHostController {
    state: Arc<Mutex<LpcipState>>,
}

impl LpcipUsbHostController {
    pub fn device_enabled(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.devcmdstat & (DEVCMDSTAT_DEV_EN | DEVCMDSTAT_DCON)
            == DEVCMDSTAT_DEV_EN | DEVCMDSTAT_DCON
    }

    pub fn bus_reset(&self) {
        let mut state = self.state.lock().unwrap();
        state.devcmdstat &= !DEVCMDSTAT_DEV_ADDR_MASK;
        state.devcmdstat |= DEVCMDSTAT_DRES_C;
        state.intstat |= INTSTAT_DEV_INT;
    }

    pub fn host_setup(&self, data: &[u8]) -> Result<(), UsbTransactionError> {
        if data.len() != 8 {
            return Err(UsbTransactionError::DataTooLong);
        }
        let mut state = self.state.lock().unwrap();
        if state.devcmdstat & DEVCMDSTAT_DEV_EN == 0 {
            return Err(UsbTransactionError::EndpointDisabled);
        }
        let setup_offset = LpcipState::descriptor_buffer_offset(state.descriptor(SETUP_DESCRIPTOR));
        state.write_buffer(setup_offset, data);
        for descriptor_index in [EP0_OUT_DESCRIPTOR, EP0_IN_DESCRIPTOR] {
            let descriptor =
                state.descriptor(descriptor_index) & !(DESCRIPTOR_ACTIVE | DESCRIPTOR_STALL);
            state.write_descriptor(descriptor_index, descriptor);
        }
        state.devcmdstat |= DEVCMDSTAT_SETUP;
        state.intstat |= INTSTAT_EP0OUT;
        Ok(())
    }

    pub fn host_out(&self, data: &[u8]) -> Result<(), UsbTransactionError> {
        let mut state = self.state.lock().unwrap();
        let descriptor = state.descriptor(EP0_OUT_DESCRIPTOR);
        if descriptor & DESCRIPTOR_STALL != 0 {
            return Err(UsbTransactionError::Stall);
        }
        if descriptor & DESCRIPTOR_ACTIVE == 0 {
            return Err(UsbTransactionError::Nak);
        }
        let capacity = ((descriptor >> DESCRIPTOR_NBYTES_SHIFT) & DESCRIPTOR_NBYTES_MASK) as usize;
        if data.len() > capacity {
            return Err(UsbTransactionError::DataTooLong);
        }
        let offset = LpcipState::descriptor_buffer_offset(descriptor);
        state.write_buffer(offset, data);
        state.write_descriptor(EP0_OUT_DESCRIPTOR, descriptor & !DESCRIPTOR_ACTIVE);
        state.intstat |= INTSTAT_EP0OUT;
        Ok(())
    }

    pub fn host_in(&self) -> Result<Vec<u8>, UsbTransactionError> {
        let mut state = self.state.lock().unwrap();
        let descriptor = state.descriptor(EP0_IN_DESCRIPTOR);
        if descriptor & DESCRIPTOR_STALL != 0 {
            return Err(UsbTransactionError::Stall);
        }
        if descriptor & DESCRIPTOR_ACTIVE == 0 {
            return Err(UsbTransactionError::Nak);
        }
        let length = ((descriptor >> DESCRIPTOR_NBYTES_SHIFT) & DESCRIPTOR_NBYTES_MASK) as usize;
        let offset = LpcipState::descriptor_buffer_offset(descriptor);
        let data = state.read_buffer(offset, length);
        state.write_descriptor(EP0_IN_DESCRIPTOR, descriptor & !DESCRIPTOR_ACTIVE);
        state.intstat |= INTSTAT_EP0IN;
        Ok(data)
    }
}

struct UsbRecoveryRequest {
    setup: [u8; 8],
    data: Vec<u8>,
    response: mpsc::SyncSender<Result<UsbControlTransferResult, UsbRecoveryError>>,
}

struct PendingCaliptraFifoRead {
    start_addr: u32,
    len: usize,
    data: Vec<u8>,
}

#[derive(Clone)]
pub struct UsbRecoveryHost {
    requests: mpsc::Sender<UsbRecoveryRequest>,
}

impl UsbRecoveryHost {
    pub fn control(
        &self,
        setup: [u8; 8],
        data: &[u8],
    ) -> Result<UsbControlTransferResult, UsbRecoveryError> {
        let (response, result) = mpsc::sync_channel(1);
        self.requests
            .send(UsbRecoveryRequest {
                setup,
                data: data.to_vec(),
                response,
            })
            .map_err(|_| UsbRecoveryError::Disconnected)?;
        result.recv().map_err(|_| UsbRecoveryError::Disconnected)?
    }
}

#[derive(Clone, Copy)]
struct RegisterCommand {
    offset: u32,
    response_len: usize,
    direction: CommandDirection,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CommandDirection {
    Read,
    Write,
    ReadWrite,
}

pub struct UsbCombo {
    generated: UsbComboGenerated,
    lpcip_state: Arc<Mutex<LpcipState>>,
    recovery_fifo: VecDeque<u32>,
    recovery_fifo_write_index: u32,
    recovery_fifo_read_index: u32,
    pending_caliptra_fifo_read: Option<PendingCaliptraFifoRead>,
    host_request_sender: mpsc::Sender<UsbRecoveryRequest>,
    host_requests: mpsc::Receiver<UsbRecoveryRequest>,
    events_to_caliptra: Option<mpsc::Sender<Event>>,
    events_from_caliptra: Option<mpsc::Receiver<Event>>,
    caliptra_event_mirror: Option<mpsc::Sender<Event>>,
    events_to_mcu: Option<mpsc::Sender<Event>>,
    events_from_mcu: Option<mpsc::Receiver<Event>>,
}

impl UsbCombo {
    pub fn new() -> Self {
        let (host_request_sender, host_requests) = mpsc::channel();
        Self {
            generated: UsbComboGenerated::default(),
            lpcip_state: Arc::new(Mutex::new(LpcipState::new())),
            recovery_fifo: VecDeque::new(),
            recovery_fifo_write_index: 0,
            recovery_fifo_read_index: 0,
            pending_caliptra_fifo_read: None,
            host_request_sender,
            host_requests,
            events_to_caliptra: None,
            events_from_caliptra: None,
            caliptra_event_mirror: None,
            events_to_mcu: None,
            events_from_mcu: None,
        }
    }

    pub fn host_controller(&self) -> UsbRecoveryHost {
        UsbRecoveryHost {
            requests: self.host_request_sender.clone(),
        }
    }

    pub fn lpcip_host_controller(&self) -> LpcipUsbHostController {
        LpcipUsbHostController {
            state: Arc::clone(&self.lpcip_state),
        }
    }

    pub fn device0_memory(&self) -> UsbDev0Mem {
        UsbDev0Mem {
            state: Arc::clone(&self.lpcip_state),
        }
    }

    pub fn handle_control_transfer(
        &mut self,
        setup: [u8; 8],
        data: &[u8],
    ) -> Result<UsbControlTransferResult, UsbRecoveryError> {
        let request_type = setup[0];
        let command = setup[2];
        let length = u16::from_le_bytes([setup[6], setup[7]]) as usize;

        if request_type & 0x7f != 0x21
            || setup[1] != 0
            || setup[3] != 0
            || setup[4] != OCP_RECOVERY_INTERFACE
            || setup[5] != 0
        {
            return Ok(UsbControlTransferResult::NotClaimed);
        }

        let command = RecoveryCommand::try_from(command).map_err(|_| UsbRecoveryError::Stall)?;
        if command == RecoveryCommand::IndirectFifoData {
            let transfer_dwords = length.div_ceil(4);
            if request_type & 0x80 != 0
                || data.len() != length
                || data.is_empty()
                || length > OCP_MAX_CONTROL_TRANSFER_SIZE
                || self.recovery_fifo.len() + transfer_dwords > OCP_FIFO_DEPTH_DWORDS
            {
                return Err(UsbRecoveryError::Stall);
            }
            for chunk in data.chunks(4) {
                let mut word = [0; 4];
                word[..chunk.len()].copy_from_slice(chunk);
                self.recovery_fifo.push_back(u32::from_le_bytes(word));
                self.recovery_fifo_write_index =
                    (self.recovery_fifo_write_index + 1) % OCP_FIFO_DEPTH_DWORDS as u32;
            }
            return Ok(UsbControlTransferResult::Complete(Vec::new()));
        }
        let Some(register) = Self::register_command(command) else {
            return Err(UsbRecoveryError::Stall);
        };
        let is_read = request_type & 0x80 != 0;
        if length > OCP_MAX_CONTROL_TRANSFER_SIZE
            || (is_read && register.direction == CommandDirection::Write)
            || (!is_read && register.direction == CommandDirection::Read)
        {
            return Err(UsbRecoveryError::Stall);
        }

        if is_read {
            if length < register.response_len || !data.is_empty() {
                return Err(UsbRecoveryError::Stall);
            }
            let response = self
                .read_recovery_bytes(register.offset, register.response_len)
                .ok_or(UsbRecoveryError::Stall)?;
            Ok(UsbControlTransferResult::Complete(response))
        } else {
            if length != register.response_len || data.len() != length {
                return Err(UsbRecoveryError::Stall);
            }
            self.write_recovery_bytes(register.offset, data)?;
            Ok(UsbControlTransferResult::Complete(Vec::new()))
        }
    }

    fn register_command(command: RecoveryCommand) -> Option<RegisterCommand> {
        let (offset, response_len, direction) = match command {
            RecoveryCommand::ProtCap => (0x000, 15, CommandDirection::Read),
            RecoveryCommand::DeviceId => (0x010, 24, CommandDirection::Read),
            RecoveryCommand::DeviceStatus => (0x028, 7, CommandDirection::Read),
            RecoveryCommand::DeviceReset => (0x068, 3, CommandDirection::ReadWrite),
            RecoveryCommand::RecoveryCtrl => (0x06c, 3, CommandDirection::Write),
            RecoveryCommand::RecoveryStatus => (0x070, 2, CommandDirection::Read),
            RecoveryCommand::HwStatus => (0x074, 4, CommandDirection::Read),
            RecoveryCommand::Vendor => (0x1a4, 1, CommandDirection::ReadWrite),
            RecoveryCommand::IndirectFifoCtrl => (0x184, 6, CommandDirection::ReadWrite),
            RecoveryCommand::IndirectFifoStatus => (0x18c, 20, CommandDirection::Read),
            RecoveryCommand::IndirectCtrl
            | RecoveryCommand::IndirectStatus
            | RecoveryCommand::IndirectData
            | RecoveryCommand::IndirectFifoData => return None,
        };
        Some(RegisterCommand {
            offset,
            response_len,
            direction,
        })
    }

    fn read_recovery_bytes(&mut self, offset: u32, len: usize) -> Option<Vec<u8>> {
        if offset == 0x184 && len == 6 {
            let ctrl = self.read_recovery_indirect_fifo_ctrl_0().reg.get();
            let image_size = self.read_recovery_indirect_fifo_ctrl_1();
            return Some(vec![
                ctrl as u8,
                (ctrl >> 8) as u8,
                image_size as u8,
                (image_size >> 8) as u8,
                (image_size >> 16) as u8,
                (image_size >> 24) as u8,
            ]);
        }
        let mut data = Vec::with_capacity(len);
        for address in (offset..offset + len as u32).step_by(4) {
            data.extend_from_slice(&self.read_recovery_interface(address)?.to_le_bytes());
        }
        data.truncate(len);
        Some(data)
    }

    fn write_recovery_bytes(&mut self, offset: u32, data: &[u8]) -> Result<(), UsbRecoveryError> {
        if offset == 0x184 && data.len() == 6 {
            self.write_recovery_indirect_fifo_ctrl_0(caliptra_emu_bus::ReadWriteRegister::new(
                u16::from_le_bytes(data[..2].try_into().unwrap()) as u32,
            ));
            self.write_recovery_indirect_fifo_ctrl_1(u32::from_le_bytes(
                data[2..].try_into().unwrap(),
            ));
            return Ok(());
        }
        for (word_index, bytes) in data.chunks(4).enumerate() {
            let address = offset + word_index as u32 * 4;
            let mut word = self
                .read_recovery_interface(address)
                .ok_or(UsbRecoveryError::Stall)?
                .to_le_bytes();
            word[..bytes.len()].copy_from_slice(bytes);
            if !self.write_recovery_interface(address, u32::from_le_bytes(word)) {
                return Err(UsbRecoveryError::Stall);
            }
        }
        Ok(())
    }

    fn read_recovery_interface(&mut self, addr: u32) -> Option<u32> {
        Some(match addr {
            0x00 => self.read_recovery_prot_cap_0(),
            0x04 => self.read_recovery_prot_cap_1(),
            0x08 => self.read_recovery_prot_cap_2().reg.get(),
            0x0c => self.read_recovery_prot_cap_3().reg.get(),
            0x10 => self.read_recovery_device_id_0().reg.get(),
            0x14 => self.read_recovery_device_id_1(),
            0x18 => self.read_recovery_device_id_2(),
            0x1c => self.read_recovery_device_id_3(),
            0x20 => self.read_recovery_device_id_4(),
            0x24 => self.read_recovery_device_id_5(),
            0x28 => self.read_recovery_device_status_0().reg.get(),
            0x2c => self.read_recovery_device_status_1().reg.get(),
            0x30 => self.read_recovery_device_status_2(),
            0x34 => self.read_recovery_device_status_3(),
            0x38 => self.read_recovery_device_status_4(),
            0x3c => self.read_recovery_device_status_5(),
            0x40 => self.read_recovery_device_status_6(),
            0x44 => self.read_recovery_device_status_7(),
            0x48 => self.read_recovery_device_status_8(),
            0x4c => self.read_recovery_device_status_9(),
            0x50 => self.read_recovery_device_status_10(),
            0x54 => self.read_recovery_device_status_11(),
            0x58 => self.read_recovery_device_status_12(),
            0x5c => self.read_recovery_device_status_13(),
            0x60 => self.read_recovery_device_status_14(),
            0x64 => self.read_recovery_device_status_15(),
            0x68 => self.read_recovery_device_reset().reg.get(),
            0x6c => self.read_recovery_recovery_ctrl().reg.get(),
            0x70 => self.read_recovery_recovery_status().reg.get(),
            0x74 => self.read_recovery_hw_status().reg.get(),
            0x184 => self.read_recovery_indirect_fifo_ctrl_0().reg.get(),
            0x188 => self.read_recovery_indirect_fifo_ctrl_1(),
            0x18c => self.read_recovery_indirect_fifo_status_0().reg.get(),
            0x190 => self.read_recovery_indirect_fifo_status_1(),
            0x194 => self.read_recovery_indirect_fifo_status_2(),
            0x198 => self.read_recovery_indirect_fifo_status_3(),
            0x19c => self.read_recovery_indirect_fifo_status_4(),
            0x1a0 => self.read_recovery_indirect_fifo_data(),
            0x1a4 => self.read_recovery_vendor().reg.get(),
            _ => return None,
        })
    }

    fn write_recovery_interface(&mut self, addr: u32, value: u32) -> bool {
        match addr {
            0x08 => self.write_recovery_prot_cap_2(caliptra_emu_bus::ReadWriteRegister::new(value)),
            0x0c => self.write_recovery_prot_cap_3(caliptra_emu_bus::ReadWriteRegister::new(value)),
            0x28 => {
                self.write_recovery_device_status_0(caliptra_emu_bus::ReadWriteRegister::new(value))
            }
            0x68 => {
                self.write_recovery_device_reset(caliptra_emu_bus::ReadWriteRegister::new(value))
            }
            0x6c => {
                self.write_recovery_recovery_ctrl(caliptra_emu_bus::ReadWriteRegister::new(value))
            }
            0x70 => {
                self.write_recovery_recovery_status(caliptra_emu_bus::ReadWriteRegister::new(value))
            }
            0x74 => self.write_recovery_hw_status(caliptra_emu_bus::ReadWriteRegister::new(value)),
            0x184 => self.write_recovery_indirect_fifo_ctrl_0(
                caliptra_emu_bus::ReadWriteRegister::new(value),
            ),
            0x188 => self.write_recovery_indirect_fifo_ctrl_1(value),
            0x1a4 => self.write_recovery_vendor(caliptra_emu_bus::ReadWriteRegister::new(value)),
            _ => return false,
        }
        true
    }

    fn reset_recovery_fifo(&mut self) {
        self.recovery_fifo.clear();
        self.recovery_fifo_write_index = 0;
        self.recovery_fifo_read_index = 0;
    }

    fn caliptra_recovery_offset(offset: u32) -> Option<u32> {
        Some(match offset {
            0x04..=0x28 => offset - 0x04,
            0x30..=0x34 => offset - 0x08,
            0x38 => 0x068,
            0x3c => 0x06c,
            0x40 => 0x070,
            0x44 => 0x074,
            0x48 => 0x184,
            0x4c => 0x188,
            0x50..=0x60 => offset + 0x13c,
            0x68 => 0x1a0,
            _ => return None,
        })
    }

    fn progress_caliptra_fifo_read(&mut self) {
        let Some(mut pending) = self.pending_caliptra_fifo_read.take() else {
            return;
        };
        while pending.data.len() < pending.len {
            let Some(value) = self.recovery_fifo.pop_front() else {
                break;
            };
            self.recovery_fifo_read_index =
                (self.recovery_fifo_read_index + 1) % OCP_FIFO_DEPTH_DWORDS as u32;
            pending.data.extend_from_slice(&value.to_le_bytes());
        }
        if pending.data.len() < pending.len {
            self.pending_caliptra_fifo_read = Some(pending);
            return;
        }
        pending.data.truncate(pending.len);
        self.events_to_caliptra
            .as_ref()
            .unwrap()
            .send(Event::new(
                Device::RecoveryIntf,
                Device::CaliptraCore,
                EventData::MemoryReadResponse {
                    start_addr: pending.start_addr,
                    data: pending.data,
                },
            ))
            .unwrap();
    }

    fn handle_caliptra_event(&mut self, event: Event) {
        match event.event {
            EventData::MemoryRead { start_addr, len } => {
                if start_addr == 0x68 {
                    self.pending_caliptra_fifo_read = Some(PendingCaliptraFifoRead {
                        start_addr,
                        len: len as usize,
                        data: Vec::with_capacity(len as usize),
                    });
                    self.progress_caliptra_fifo_read();
                    return;
                }
                let mut data = Vec::with_capacity(len as usize);
                for index in (0..len).step_by(4) {
                    let addr = start_addr + index;
                    let Some(offset) = Self::caliptra_recovery_offset(addr) else {
                        return;
                    };
                    let Some(value) = self.read_recovery_interface(offset) else {
                        return;
                    };
                    data.extend_from_slice(&value.to_le_bytes());
                }
                self.events_to_caliptra
                    .as_ref()
                    .unwrap()
                    .send(Event::new(
                        Device::RecoveryIntf,
                        Device::CaliptraCore,
                        EventData::MemoryReadResponse { start_addr, data },
                    ))
                    .unwrap();
            }
            EventData::MemoryWrite { start_addr, data } => {
                for (index, bytes) in data.chunks_exact(4).enumerate() {
                    let Some(offset) =
                        Self::caliptra_recovery_offset(start_addr + index as u32 * 4)
                    else {
                        return;
                    };
                    let value = u32::from_le_bytes(bytes.try_into().unwrap());
                    if !self.write_recovery_interface(offset, value) {
                        return;
                    }
                }
            }
            EventData::RecoveryFifoStatusRequest => {
                let fifo_status = self.read_recovery_indirect_fifo_status_0().reg.get();
                let status = u32::from(fifo_status & 1 == 0);
                self.events_to_caliptra
                    .as_ref()
                    .unwrap()
                    .send(Event::new(
                        Device::RecoveryIntf,
                        Device::CaliptraCore,
                        EventData::RecoveryFifoStatusResponse { status },
                    ))
                    .unwrap();
            }
            _ => {}
        }
    }
}

impl Default for UsbCombo {
    fn default() -> Self {
        Self::new()
    }
}

impl UsbComboPeripheral for UsbCombo {
    fn generated(&mut self) -> Option<&mut UsbComboGenerated> {
        Some(&mut self.generated)
    }

    fn set_caliptra_event_mirror(&mut self, sender: mpsc::Sender<Event>) {
        self.caliptra_event_mirror = Some(sender);
    }

    fn read_dev0_csr_devcmdstat(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::usb_combo::bits::DevcmdstatT::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.lpcip_state.lock().unwrap().devcmdstat)
    }

    fn write_dev0_csr_devcmdstat(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            caliptra_mcu_registers_generated::usb_combo::bits::DevcmdstatT::Register,
        >,
    ) {
        let write_value = val.reg.get();
        let mut state = self.lpcip_state.lock().unwrap();
        state.devcmdstat &= !(write_value & DEVCMDSTAT_W1C_MASK);
        let software_mask = DEVCMDSTAT_DEV_ADDR_MASK
            | DEVCMDSTAT_DEV_EN
            | (0x7f << 9)
            | DEVCMDSTAT_DCON
            | (1 << 20)
            | (1 << 21)
            | (0x7 << 29);
        state.devcmdstat = (state.devcmdstat & !software_mask) | (write_value & software_mask);
    }

    fn read_dev0_csr_intstat(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::usb_combo::bits::IntstatT::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.lpcip_state.lock().unwrap().intstat)
    }

    fn write_dev0_csr_intstat(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            caliptra_mcu_registers_generated::usb_combo::bits::IntstatT::Register,
        >,
    ) {
        self.lpcip_state.lock().unwrap().intstat &= !val.reg.get();
    }

    fn write_recovery_indirect_fifo_ctrl_0(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            caliptra_mcu_registers_generated::usb_combo::bits::IndirectFifoCtrl0::Register,
        >,
    ) {
        if val.reg.get() & 0x100 != 0 {
            self.reset_recovery_fifo();
        }
        self.generated.write_recovery_indirect_fifo_ctrl_0(
            caliptra_emu_bus::ReadWriteRegister::new(val.reg.get() & !0x100),
        );
    }

    fn write_recovery_indirect_fifo_ctrl_1(&mut self, val: u32) {
        self.reset_recovery_fifo();
        self.generated.write_recovery_indirect_fifo_ctrl_1(val);
    }

    fn read_recovery_indirect_fifo_status_0(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::usb_combo::bits::IndirectFifoStatus0::Register,
    > {
        let empty = u32::from(self.recovery_fifo.is_empty());
        let full = u32::from(self.recovery_fifo.len() == OCP_FIFO_DEPTH_DWORDS) << 1;
        caliptra_emu_bus::ReadWriteRegister::new(empty | full)
    }

    fn read_recovery_indirect_fifo_status_1(&mut self) -> u32 {
        self.recovery_fifo_write_index
    }

    fn read_recovery_indirect_fifo_status_2(&mut self) -> u32 {
        self.recovery_fifo_read_index
    }

    fn read_recovery_indirect_fifo_status_3(&mut self) -> u32 {
        OCP_FIFO_DEPTH_DWORDS as u32
    }

    fn read_recovery_indirect_fifo_status_4(&mut self) -> u32 {
        OCP_FIFO_MAX_TRANSFER_DWORDS
    }

    fn read_recovery_indirect_fifo_data(&mut self) -> u32 {
        match self.recovery_fifo.pop_front() {
            Some(value) => {
                self.recovery_fifo_read_index =
                    (self.recovery_fifo_read_index + 1) % OCP_FIFO_DEPTH_DWORDS as u32;
                value
            }
            None => u32::MAX,
        }
    }

    fn register_event_channels(
        &mut self,
        events_to_caliptra: mpsc::Sender<Event>,
        events_from_caliptra: mpsc::Receiver<Event>,
        events_to_mcu: mpsc::Sender<Event>,
        events_from_mcu: mpsc::Receiver<Event>,
    ) {
        self.events_to_caliptra = Some(events_to_caliptra);
        self.events_from_caliptra = Some(events_from_caliptra);
        self.events_to_mcu = Some(events_to_mcu);
        self.events_from_mcu = Some(events_from_mcu);
    }

    fn poll(&mut self) {
        if let Ok(request) = self.host_requests.try_recv() {
            let result = self.handle_control_transfer(request.setup, &request.data);
            let _ = request.response.send(result);
        }

        let caliptra_events: Vec<_> = self
            .events_from_caliptra
            .as_ref()
            .map(|receiver| receiver.try_iter().collect())
            .unwrap_or_default();
        for event in caliptra_events {
            match event.dest {
                Device::RecoveryIntf => {
                    if matches!(event.event, EventData::MemoryWrite { .. }) {
                        if let Some(mirror) = &self.caliptra_event_mirror {
                            let _ = mirror.send(event.clone());
                        }
                    }
                    self.handle_caliptra_event(event);
                }
                Device::MCU
                | Device::ExternalTestSram
                | Device::McuMbox0Sram
                | Device::McuMbox1Sram => self.events_to_mcu.as_ref().unwrap().send(event).unwrap(),
                _ => {}
            }
        }

        let mcu_events: Vec<_> = self
            .events_from_mcu
            .as_ref()
            .map(|receiver| receiver.try_iter().collect())
            .unwrap_or_default();
        for event in mcu_events {
            if event.dest == Device::CaliptraCore {
                self.events_to_caliptra
                    .as_ref()
                    .unwrap()
                    .send(event)
                    .unwrap();
            }
        }
        self.progress_caliptra_fifo_read();
    }
}

pub struct UsbDev1(UsbDev1Generated);

impl UsbDev1 {
    pub fn new() -> Self {
        Self(UsbDev1Generated::default())
    }
}

impl Default for UsbDev1 {
    fn default() -> Self {
        Self::new()
    }
}

impl UsbDev1Peripheral for UsbDev1 {
    fn generated(&mut self) -> Option<&mut UsbDev1Generated> {
        Some(&mut self.0)
    }
}

pub struct UsbDev0Mem {
    state: Arc<Mutex<LpcipState>>,
}

impl UsbDev0Mem {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(LpcipState::new())),
        }
    }
}

impl Default for UsbDev0Mem {
    fn default() -> Self {
        Self::new()
    }
}

impl UsbDev0MemPeripheral for UsbDev0Mem {
    fn read_usb_dev0_mem(&mut self, index: usize) -> u32 {
        self.state.lock().unwrap().memory.read_usb_dev0_mem(index)
    }

    fn write_usb_dev0_mem(&mut self, value: u32, index: usize) {
        self.state
            .lock()
            .unwrap()
            .memory
            .write_usb_dev0_mem(value, index);
    }
}

pub struct UsbDev1Mem(UsbDev1MemGenerated);

impl UsbDev1Mem {
    pub fn new() -> Self {
        Self(UsbDev1MemGenerated::default())
    }
}

impl Default for UsbDev1Mem {
    fn default() -> Self {
        Self::new()
    }
}

impl UsbDev1MemPeripheral for UsbDev1Mem {
    fn generated(&mut self) -> Option<&mut UsbDev1MemGenerated> {
        Some(&mut self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_emu_bus::Bus;
    use caliptra_emu_types::RvSize;
    use caliptra_mcu_emulator_registers_generated::root_bus::AutoRootBus;
    use std::sync::mpsc;

    fn usb_with_event_channels() -> (
        UsbCombo,
        mpsc::Sender<Event>,
        mpsc::Receiver<Event>,
        mpsc::Sender<Event>,
        mpsc::Receiver<Event>,
    ) {
        let (events_to_caliptra, caliptra_responses) = mpsc::channel();
        let (caliptra_events, events_from_caliptra) = mpsc::channel();
        let (events_to_mcu, mcu_responses) = mpsc::channel();
        let (mcu_events, events_from_mcu) = mpsc::channel();
        let mut usb = UsbCombo::new();
        usb.register_event_channels(
            events_to_caliptra,
            events_from_caliptra,
            events_to_mcu,
            events_from_mcu,
        );
        (
            usb,
            caliptra_events,
            caliptra_responses,
            mcu_events,
            mcu_responses,
        )
    }

    #[test]
    fn mcu_bus_routes_all_usb_windows() {
        let mut bus = AutoRootBus::new(
            vec![],
            None,
            None,
            Some(Box::new(UsbCombo::new())),
            Some(Box::new(UsbDev1::new())),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(Box::new(UsbDev0Mem::new())),
            Some(Box::new(UsbDev1Mem::new())),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        for address in [0x2000_0008, 0x2000_2008] {
            bus.write(RvSize::Word, address, 0xa5a5_5a5a).unwrap();
            assert_eq!(bus.read(RvSize::Word, address).unwrap(), 0xa5a5_5a00);
        }

        for address in [0x3000_0000, 0x3000_1000] {
            bus.write(RvSize::Word, address, 0xa5a5_5a5a).unwrap();
            assert_eq!(bus.read(RvSize::Word, address).unwrap(), 0xa5a5_5a5a);
        }
    }

    #[test]
    fn recovery_events_use_usb_registers() {
        let (mut usb, caliptra_events, caliptra_responses, _, _) = usb_with_event_channels();

        caliptra_events
            .send(Event::new(
                Device::CaliptraCore,
                Device::RecoveryIntf,
                EventData::MemoryWrite {
                    start_addr: 0x40,
                    data: 0xc1_u32.to_le_bytes().to_vec(),
                },
            ))
            .unwrap();
        usb.poll();
        assert_eq!(usb.read_recovery_recovery_status().reg.get(), 0xc1);

        caliptra_events
            .send(Event::new(
                Device::CaliptraCore,
                Device::RecoveryIntf,
                EventData::MemoryRead {
                    start_addr: 4,
                    len: 4,
                },
            ))
            .unwrap();
        usb.poll();

        let response = caliptra_responses.recv().unwrap();
        assert_eq!(response.src, Device::RecoveryIntf);
        assert_eq!(response.dest, Device::CaliptraCore);
        match response.event {
            EventData::MemoryReadResponse { start_addr, data } => {
                assert_eq!(start_addr, 4);
                assert_eq!(data, 0x2050_434f_u32.to_le_bytes());
            }
            _ => panic!("unexpected USB recovery response"),
        }

        caliptra_events
            .send(Event::new(
                Device::CaliptraCore,
                Device::RecoveryIntf,
                EventData::RecoveryFifoStatusRequest,
            ))
            .unwrap();
        usb.poll();
        assert!(matches!(
            caliptra_responses.recv().unwrap().event,
            EventData::RecoveryFifoStatusResponse { status: 0 }
        ));
    }

    #[test]
    fn caliptra_fifo_reads_use_fixed_data_register() {
        let (mut usb, caliptra_events, caliptra_responses, _, _) = usb_with_event_channels();
        usb.recovery_fifo.push_back(0x1122_3344);

        caliptra_events
            .send(Event::new(
                Device::CaliptraCore,
                Device::RecoveryIntf,
                EventData::MemoryRead {
                    start_addr: 0x68,
                    len: 8,
                },
            ))
            .unwrap();
        usb.poll();
        assert!(matches!(
            caliptra_responses.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));

        usb.recovery_fifo.push_back(0x5566_7788);
        usb.poll();

        let response = caliptra_responses.recv().unwrap();
        assert!(matches!(
            response.event,
            EventData::MemoryReadResponse { data, .. }
                if data == [
                    0x44, 0x33, 0x22, 0x11,
                    0x88, 0x77, 0x66, 0x55,
                ]
        ));
        assert!(usb.recovery_fifo.is_empty());
    }

    #[test]
    fn usb_router_forwards_non_recovery_events() {
        let (mut usb, caliptra_events, _, _, mcu_responses) = usb_with_event_channels();
        caliptra_events
            .send(Event::new(
                Device::CaliptraCore,
                Device::MCU,
                EventData::MemoryRead {
                    start_addr: 0x100,
                    len: 4,
                },
            ))
            .unwrap();
        usb.poll();

        let event = mcu_responses.recv().unwrap();
        assert_eq!(event.dest, Device::MCU);
    }

    #[test]
    fn standard_control_request_is_not_claimed() {
        let mut usb = UsbCombo::new();
        let result = usb
            .handle_control_transfer([0x80, 6, 0, 1, 0, 0, 18, 0], &[])
            .unwrap();
        assert_eq!(result, UsbControlTransferResult::NotClaimed);
    }

    #[test]
    fn lpcip_host_uses_firmware_packet_memory() {
        let mut usb = UsbCombo::new();
        let host = usb.lpcip_host_controller();
        let mut memory = usb.device0_memory();

        memory.write_usb_dev0_mem(4, SETUP_DESCRIPTOR);
        memory.write_usb_dev0_mem(
            DESCRIPTOR_ACTIVE | (8 << DESCRIPTOR_NBYTES_SHIFT) | 5,
            EP0_OUT_DESCRIPTOR,
        );
        usb.write_dev0_csr_devcmdstat(caliptra_emu_bus::ReadWriteRegister::new(
            DEVCMDSTAT_DEV_EN | DEVCMDSTAT_DCON,
        ));

        let setup = [0x80, 6, 0, 1, 0, 0, 18, 0];
        host.host_setup(&setup).unwrap();
        assert_eq!(memory.read_usb_dev0_mem(0x100 / 4), 0x0100_0680);
        assert_eq!(memory.read_usb_dev0_mem(0x104 / 4), 0x0012_0000);
        assert_ne!(
            usb.read_dev0_csr_devcmdstat().reg.get() & DEVCMDSTAT_SETUP,
            0
        );

        memory.write_usb_dev0_mem(0x4433_2211, 0x180 / 4);
        memory.write_usb_dev0_mem(
            DESCRIPTOR_ACTIVE | (4 << DESCRIPTOR_NBYTES_SHIFT) | 6,
            EP0_IN_DESCRIPTOR,
        );
        assert_eq!(host.host_in().unwrap(), [0x11, 0x22, 0x33, 0x44]);
        assert_eq!(
            memory.read_usb_dev0_mem(EP0_IN_DESCRIPTOR) & DESCRIPTOR_ACTIVE,
            0
        );
        assert_ne!(usb.read_dev0_csr_intstat().reg.get() & INTSTAT_EP0IN, 0);
    }

    #[test]
    fn ocp_read_returns_recovery_register_bytes() {
        let mut usb = UsbCombo::new();
        let result = usb
            .handle_control_transfer([0xa1, 0, 0x22, 0, 0, 0, 15, 0], &[])
            .unwrap();
        let UsbControlTransferResult::Complete(data) = result else {
            panic!("OCP request was not claimed");
        };
        assert_eq!(data.len(), 15);
        assert_eq!(&data[..4], &0x2050_434f_u32.to_le_bytes());
    }

    #[test]
    fn ocp_write_updates_recovery_registers() {
        let mut usb = UsbCombo::new();
        let result = usb
            .handle_control_transfer([0x21, 0, 0x26, 0, 0, 0, 3, 0], &[0x12, 0x34, 0x56])
            .unwrap();
        assert_eq!(result, UsbControlTransferResult::Complete(Vec::new()));
        assert_eq!(usb.read_recovery_recovery_ctrl().reg.get(), 0x0056_3412);
    }

    #[test]
    fn fifo_ctrl_maps_packed_wire_image_size_to_split_registers() {
        let mut usb = UsbCombo::new();
        let payload = [3, 0, 0x78, 0x56, 0x34, 0x12];

        let result = usb
            .handle_control_transfer([0x21, 0, 0x2d, 0, 0, 0, 6, 0], &payload)
            .unwrap();
        assert_eq!(result, UsbControlTransferResult::Complete(Vec::new()));
        assert_eq!(usb.read_recovery_indirect_fifo_ctrl_0().reg.get(), 3);
        assert_eq!(usb.read_recovery_indirect_fifo_ctrl_1(), 0x1234_5678);

        let result = usb
            .handle_control_transfer([0xa1, 0, 0x2d, 0, 0, 0, 6, 0], &[])
            .unwrap();
        assert_eq!(result, UsbControlTransferResult::Complete(payload.to_vec()));
    }

    #[test]
    fn malformed_ocp_request_stalls_without_side_effects() {
        let mut usb = UsbCombo::new();
        let before = usb.read_recovery_recovery_ctrl().reg.get();
        let result = usb.handle_control_transfer([0x21, 0, 0x26, 0, 0, 0, 2, 0], &[0xaa, 0xbb]);
        assert_eq!(result, Err(UsbRecoveryError::Stall));
        assert_eq!(usb.read_recovery_recovery_ctrl().reg.get(), before);
    }

    #[test]
    fn fifo_data_is_drained_through_recovery_interface() {
        let mut usb = UsbCombo::new();
        let result = usb
            .handle_control_transfer(
                [0x21, 0, 0x2f, 0, 0, 0, 7, 0],
                &[0xde, 0xad, 0xbe, 0xef, 1, 2, 3],
            )
            .unwrap();
        assert_eq!(result, UsbControlTransferResult::Complete(Vec::new()));
        assert_eq!(usb.read_recovery_indirect_fifo_status_1(), 2);
        assert_eq!(usb.read_recovery_indirect_fifo_data(), 0xefbe_adde);
        assert_eq!(usb.read_recovery_indirect_fifo_data(), 0x0003_0201);
        assert_eq!(usb.read_recovery_indirect_fifo_status_2(), 2);
        assert_eq!(usb.read_recovery_indirect_fifo_status_0().reg.get(), 1);
    }

    #[test]
    fn fifo_status_reports_rtl_capacity_and_full_state() {
        let mut usb = UsbCombo::new();
        let payload = [0x5a; OCP_MAX_CONTROL_TRANSFER_SIZE];
        for _ in 0..4 {
            usb.handle_control_transfer(
                [
                    0x21,
                    0,
                    0x2f,
                    0,
                    0,
                    0,
                    OCP_MAX_CONTROL_TRANSFER_SIZE as u8,
                    0,
                ],
                &payload,
            )
            .unwrap();
        }

        assert_eq!(usb.read_recovery_indirect_fifo_status_0().reg.get(), 2);
        assert_eq!(usb.read_recovery_indirect_fifo_status_1(), 0);
        assert_eq!(usb.read_recovery_indirect_fifo_status_2(), 0);
        assert_eq!(usb.read_recovery_indirect_fifo_status_3(), 64);
        assert_eq!(usb.read_recovery_indirect_fifo_status_4(), 64);
        assert!(matches!(
            usb.handle_control_transfer([0x21, 0, 0x2f, 0, 0, 0, 1, 0], &[0]),
            Err(UsbRecoveryError::Stall)
        ));

        assert_eq!(usb.read_recovery_indirect_fifo_data(), 0x5a5a_5a5a);
        assert_eq!(usb.read_recovery_indirect_fifo_status_0().reg.get(), 0);
        assert_eq!(usb.read_recovery_indirect_fifo_status_2(), 1);
    }

    #[test]
    fn host_requests_are_serviced_during_poll() {
        let mut usb = UsbCombo::new();
        let host = usb.host_controller();
        let (done, result) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let response = host.control([0xa1, 0, 0x22, 0, 0, 0, 15, 0], &[]);
            done.send(response).unwrap();
        });

        loop {
            match result.try_recv() {
                Ok(Ok(UsbControlTransferResult::Complete(data))) => {
                    assert_eq!(data.len(), 15);
                    break;
                }
                Ok(response) => panic!("unexpected host response: {response:?}"),
                Err(mpsc::TryRecvError::Empty) => {
                    usb.poll();
                    std::thread::yield_now();
                }
                Err(mpsc::TryRecvError::Disconnected) => panic!("host request disconnected"),
            }
        }
    }

    #[test]
    fn host_requests_do_not_starve_caliptra_events() {
        let (mut usb, caliptra_events, _, _, _) = usb_with_event_channels();
        let host = usb.host_controller();

        let (first_response, first_result) = mpsc::sync_channel(1);
        host.requests
            .send(UsbRecoveryRequest {
                setup: [0xa1, 0, 0x2e, 0, 0, 0, 20, 0],
                data: Vec::new(),
                response: first_response,
            })
            .unwrap();
        let (second_response, second_result) = mpsc::sync_channel(1);
        host.requests
            .send(UsbRecoveryRequest {
                setup: [0xa1, 0, 0x2e, 0, 0, 0, 20, 0],
                data: Vec::new(),
                response: second_response,
            })
            .unwrap();
        caliptra_events
            .send(Event::new(
                Device::CaliptraCore,
                Device::RecoveryIntf,
                EventData::MemoryWrite {
                    start_addr: 0x30,
                    data: 3_u32.to_le_bytes().to_vec(),
                },
            ))
            .unwrap();

        usb.poll();
        assert!(first_result.try_recv().is_ok());
        assert!(matches!(
            second_result.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        assert_eq!(usb.read_recovery_device_status_0().reg.get() & 0xff, 3);
    }
}
