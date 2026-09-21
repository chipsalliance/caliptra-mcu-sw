// Licensed under the Apache-2.0 license.

use caliptra_emu_bus::{Device, Event, EventData};
use caliptra_mcu_emulator_registers_generated::{
    usb_combo::{UsbComboGenerated, UsbComboPeripheral},
    usb_dev0_mem::{UsbDev0MemGenerated, UsbDev0MemPeripheral},
    usb_dev1::{UsbDev1Generated, UsbDev1Peripheral},
    usb_dev1_mem::{UsbDev1MemGenerated, UsbDev1MemPeripheral},
};
use caliptra_mcu_ocp::protocol::RecoveryCommand;
use std::sync::mpsc;
use tock_registers::interfaces::Readable;

const OCP_RECOVERY_INTERFACE: u8 = 0;
const OCP_MAX_CONTROL_TRANSFER_SIZE: usize = 64;

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

struct UsbRecoveryRequest {
    setup: [u8; 8],
    data: Vec<u8>,
    response: mpsc::SyncSender<Result<UsbControlTransferResult, UsbRecoveryError>>,
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
    host_request_sender: mpsc::Sender<UsbRecoveryRequest>,
    host_requests: mpsc::Receiver<UsbRecoveryRequest>,
    events_to_caliptra: Option<mpsc::Sender<Event>>,
    events_from_caliptra: Option<mpsc::Receiver<Event>>,
    events_to_mcu: Option<mpsc::Sender<Event>>,
    events_from_mcu: Option<mpsc::Receiver<Event>>,
}

impl UsbCombo {
    pub fn new() -> Self {
        let (host_request_sender, host_requests) = mpsc::channel();
        Self {
            generated: UsbComboGenerated::default(),
            host_request_sender,
            host_requests,
            events_to_caliptra: None,
            events_from_caliptra: None,
            events_to_mcu: None,
            events_from_mcu: None,
        }
    }

    pub fn host_controller(&self) -> UsbRecoveryHost {
        UsbRecoveryHost {
            requests: self.host_request_sender.clone(),
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
            return Err(UsbRecoveryError::UnsupportedDataPath);
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
        let mut data = Vec::with_capacity(len);
        for address in (offset..offset + len as u32).step_by(4) {
            data.extend_from_slice(&self.read_recovery_interface(address)?.to_le_bytes());
        }
        data.truncate(len);
        Some(data)
    }

    fn write_recovery_bytes(&mut self, offset: u32, data: &[u8]) -> Result<(), UsbRecoveryError> {
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

    fn handle_caliptra_event(&mut self, event: Event) {
        match event.event {
            EventData::MemoryRead { start_addr, len } => {
                let mut data = Vec::with_capacity(len as usize);
                for addr in (start_addr..start_addr + len).step_by(4) {
                    let Some(value) = self.read_recovery_interface(addr) else {
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
                    let value = u32::from_le_bytes(bytes.try_into().unwrap());
                    if !self.write_recovery_interface(start_addr + index as u32 * 4, value) {
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
        while let Ok(request) = self.host_requests.try_recv() {
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
                Device::RecoveryIntf => self.handle_caliptra_event(event),
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

pub struct UsbDev0Mem(UsbDev0MemGenerated);

impl UsbDev0Mem {
    pub fn new() -> Self {
        Self(UsbDev0MemGenerated::default())
    }
}

impl Default for UsbDev0Mem {
    fn default() -> Self {
        Self::new()
    }
}

impl UsbDev0MemPeripheral for UsbDev0Mem {
    fn generated(&mut self) -> Option<&mut UsbDev0MemGenerated> {
        Some(&mut self.0)
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
                    start_addr: 0x70,
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
                    start_addr: 0,
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
                assert_eq!(start_addr, 0);
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
    fn malformed_ocp_request_stalls_without_side_effects() {
        let mut usb = UsbCombo::new();
        let before = usb.read_recovery_recovery_ctrl().reg.get();
        let result = usb.handle_control_transfer([0x21, 0, 0x26, 0, 0, 0, 2, 0], &[0xaa, 0xbb]);
        assert_eq!(result, Err(UsbRecoveryError::Stall));
        assert_eq!(usb.read_recovery_recovery_ctrl().reg.get(), before);
    }

    #[test]
    fn fifo_data_uses_a_separate_data_path() {
        let mut usb = UsbCombo::new();
        let result =
            usb.handle_control_transfer([0x21, 0, 0x2f, 0, 0, 0, 4, 0], &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(result, Err(UsbRecoveryError::UnsupportedDataPath));
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
}
