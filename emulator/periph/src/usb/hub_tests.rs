// Licensed under the Apache-2.0 license

use super::*;
use caliptra_emu_bus::{Bus, BusError};
use caliptra_emu_types::RvSize;
use caliptra_mcu_emulator_registers_generated::{
    usb_combo::UsbComboBus, usb_dev0_mem::UsbDev0MemBus, usb_dev1::UsbDev1Bus,
    usb_dev1_mem::UsbDev1MemBus,
};

const DEVICE_CONTROL: u32 = DEV_EN | CONNECT;
const HUB_CONTROL: u32 = 1 | CONNECT;
const GET_DESCRIPTOR: [u8; 8] = [0x80, 6, 0, 1, 0, 0, 18, 0];

struct Compound {
    csr: [Box<dyn Bus>; 2],
    memory: [Box<dyn Bus>; 2],
    device: [LpcipUsbHostController; 2],
    hub: LpcipUsbHubHostController,
}

impl Compound {
    fn new() -> Self {
        let combo = UsbCombo::new();
        let device1 = combo.device1();
        let mut fixture = Self {
            device: [combo.host_controller(), combo.device1_host_controller()],
            hub: combo.hub_host_controller(),
            memory: [
                Box::new(UsbDev0MemBus {
                    periph: Box::new(combo.device0_memory()),
                }),
                Box::new(UsbDev1MemBus {
                    periph: Box::new(combo.device1_memory()),
                }),
            ],
            csr: [
                Box::new(UsbComboBus {
                    periph: Box::new(combo),
                }),
                Box::new(UsbDev1Bus {
                    periph: Box::new(device1),
                }),
            ],
        };
        for (index, base) in [USB_DEV0_MEM_ADDR, USB_DEV1_MEM_ADDR]
            .into_iter()
            .enumerate()
        {
            fixture.write(index, 8, base);
            fixture.write(index, 12, base & 0xfffe_0000);
            fixture.memory[index]
                .write(RvSize::Word, 4, ((base & 0x1ffff) + 0x100) >> 6)
                .unwrap();
        }
        fixture.hub.set_vbus(true);
        fixture
    }

    fn write(&mut self, device: usize, offset: u32, value: u32) {
        self.csr[device].write(RvSize::Word, offset, value).unwrap();
    }

    fn read(&mut self, device: usize, offset: u32) -> u32 {
        self.csr[device].read(RvSize::Word, offset).unwrap()
    }

    fn table_offset(word: u32) -> u32 {
        0x1000 + word * 4
    }

    fn set_word(&mut self, word: u32, value: u32) {
        self.write(0, Self::table_offset(word), value);
    }

    fn word(&mut self, word: u32) -> u32 {
        self.read(0, Self::table_offset(word))
    }

    fn connect(&mut self, device: usize) {
        self.write(device, 0, DEVICE_CONTROL);
    }

    fn enable_hub(&mut self) {
        self.set_word(12, HUB_CONTROL);
        self.hub.bus_reset(LpcipUsbSpeed::High).unwrap();
    }

    fn control_at(&self, address: u8, setup: &[u8; 8]) -> Vec<u8> {
        self.hub.host_setup(address, setup).unwrap();
        if setup[0] & 0x80 == 0 || setup[6..8] == [0, 0] {
            let status = self.hub.host_in(address, 0).unwrap();
            assert!(status.is_empty());
            return status;
        }
        let requested = usize::from(u16::from_le_bytes([setup[6], setup[7]]));
        let mut data = Vec::new();
        loop {
            let packet = self.hub.host_in(address, 0).unwrap();
            let length = packet.len();
            data.extend(packet);
            if length < 64 || data.len() == requested {
                break;
            }
        }
        self.hub.host_out(address, 0, &[]).unwrap();
        data
    }

    fn configure_hub(&self) {
        self.control_at(0, &[0, 5, 10, 0, 0, 0, 0, 0]);
        self.control_at(10, &[0, 9, 1, 0, 0, 0, 0, 0]);
        assert_eq!(self.hub.device_address(), 10);
    }

    fn port_feature(&self, port: u8, feature: u8, set: bool) {
        self.control_at(
            10,
            &[0x23, if set { 3 } else { 1 }, feature, 0, port, 0, 0, 0],
        );
    }

    fn status(&self, port: u8) -> u32 {
        let bytes = self.control_at(10, &[0xa3, 0, 0, 0, port, 0, 4, 0]);
        u32::from_le_bytes(bytes.try_into().unwrap())
    }

    fn descriptor(&mut self, device: usize, physical: u32, length: u32, offset: u32, flags: u32) {
        let base = [USB_DEV0_MEM_ADDR, USB_DEV1_MEM_ADDR][device];
        let buffer = ((base & 0x1ffff) + offset) >> 6;
        self.memory[device]
            .write(RvSize::Word, physical * 8, flags | (length << 11) | buffer)
            .unwrap();
    }

    fn put_bytes(&mut self, device: usize, offset: u32, data: &[u8]) {
        for (index, chunk) in data.chunks(4).enumerate() {
            let mut word = [0; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            self.memory[device]
                .write(
                    RvSize::Word,
                    offset + index as u32 * 4,
                    u32::from_le_bytes(word),
                )
                .unwrap();
        }
    }

    fn set_device_address(&mut self, port: u8, address: u8) {
        let device = usize::from(port - 1);
        self.hub
            .port_setup(port, 0, &[0, 5, address, 0, 0, 0, 0, 0])
            .unwrap();
        self.write(device, 0, DEVICE_CONTROL | SETUP | u32::from(address));
        self.descriptor(device, 1, 0, 0x200, ACTIVE);
        assert!(self.hub.port_in(port, 0, 0).unwrap().is_empty());
        self.hub.port_setup(port, address, &GET_DESCRIPTOR).unwrap();
        assert_eq!(self.device[device].device_address(), address);
    }
}

#[test]
fn hub_is_disabled_until_firmware_enables_connect_and_vbus() {
    let mut f = Compound::new();
    assert!(!f.hub.connected());
    f.connect(0);
    assert!(f.device[0].connected());
    assert_eq!(
        f.hub.host_setup(0, &GET_DESCRIPTOR),
        Err(LpcipUsbError::Disconnected)
    );
    f.set_word(12, 1);
    assert!(!f.hub.connected());
    f.set_word(12, HUB_CONTROL);
    assert!(f.hub.connected());
    f.hub.set_vbus(false);
    assert!(!f.hub.connected());
    assert_eq!(f.word(12) & VBUS, 0);
    f.set_word(12, HUB_CONTROL | FORCE_VBUS);
    assert!(f.hub.connected());
    assert_eq!(f.word(12) & VBUS, 0);
    f.set_word(12, CONNECT);
    assert!(!f.hub.connected());
}

#[test]
fn hub_enumerates_from_rtl_reset_descriptor_and_request_tables() {
    let mut f = Compound::new();
    f.enable_hub();
    let descriptor = f.control_at(0, &GET_DESCRIPTOR);
    assert_eq!(descriptor.len(), 18);
    assert_eq!(&descriptor[..8], &[18, 1, 0x10, 2, 9, 0, 0, 64]);
    assert_eq!(&descriptor[8..12], &[0xc9, 0x1f, 0, 0xbe]);
    assert_eq!(
        f.control_at(0, &[0x80, 6, 0, 1, 0, 0, 8, 0]),
        descriptor[..8]
    );
    assert_eq!(
        f.control_at(0, &[0xa0, 6, 0, 0x29, 0, 0, 9, 0]),
        [9, 0x29, 2, 0x14, 0, 0, 0, 6, 0xff]
    );
    for (kind, length) in [(2, 25), (6, 10), (7, 25), (15, 12)] {
        let bytes = f.control_at(0, &[0x80, 6, 0, kind, 0, 0, 255, 0]);
        assert_eq!(bytes.len(), length);
        assert_eq!(bytes[1], kind);
    }
    f.configure_hub();
    assert_eq!(f.control_at(10, &[0x80, 8, 0, 0, 0, 0, 1, 0]), [1]);
}

#[test]
fn descriptor_writes_lock_only_when_enable_and_connect_are_both_set() {
    let mut f = Compound::new();
    f.set_word(12, 1);
    f.set_word(2, 0x1234_abcd);
    f.set_word(195, 0x5678);
    assert_eq!(f.word(2), 0x1234_abcd);
    assert_eq!(f.word(195), 0x5678);
    f.set_word(12, HUB_CONTROL);
    f.set_word(2, 0);
    f.set_word(195, 0);
    assert_eq!(f.word(2), 0x1234_abcd);
    assert_eq!(f.word(195), 0x5678);
    f.set_word(12, HUB_CONTROL | (1 << 18) | VBUS | (3 << 22));
    assert_eq!(f.word(17) >> 24, 0xc0);
    assert_eq!(f.word(65) >> 24, 0xc0);
    assert_eq!((f.word(12) >> 22) & 3, 1);
    f.set_word(12, 1);
    assert_eq!(f.word(17) >> 24, 0x80);
    f.set_word(2, 42);
    assert_eq!(f.word(2), 42);
}

#[test]
fn firmware_can_change_request_matching_and_descriptor_buffer_selection() {
    let mut f = Compound::new();
    f.set_word(96, 0x0180_0680);
    f.set_word(97, 0xffff_8500);
    f.set_word(98, 12 << 16);
    f.enable_hub();
    f.hub.host_setup(0, &GET_DESCRIPTOR).unwrap();
    assert_eq!(f.hub.host_in(0, 0), Err(LpcipUsbError::Stall));
    assert_eq!(
        f.control_at(0, &[0x80, 6, 0x80, 1, 0, 0, 18, 0]),
        [5, 15, 12, 0, 1, 7, 16, 2, 2, 0, 0, 0]
    );
}

#[test]
fn hub_control_packets_respect_host_length_and_terminating_zlp() {
    let mut f = Compound::new();
    for word in 16..32 {
        f.set_word(word, 0x5a5a_5a5a);
    }
    f.set_word(97, 0xffff_8100);
    f.set_word(98, 64 << 16);
    f.enable_hub();
    f.hub.host_setup(0, &[0x80, 6, 0, 1, 0, 0, 100, 0]).unwrap();
    assert_eq!(f.hub.host_in(0, 0).unwrap(), [0x5a; 64]);
    assert!(f.hub.host_in(0, 0).unwrap().is_empty());
    assert_eq!(f.hub.host_in(0, 0), Err(LpcipUsbError::Nak));
    assert_eq!(f.hub.host_out(0, 0, &[1]), Err(LpcipUsbError::DataTooLong));
    f.hub.host_out(0, 0, &[]).unwrap();
    assert_eq!(f.control_at(0, &[0x80, 6, 0, 1, 0, 0, 64, 0]), [0x5a; 64]);
}

#[test]
fn hub_address_staging_and_replaced_setup_follow_the_selected_rtl() {
    let mut f = Compound::new();
    f.enable_hub();
    f.control_at(0, &[0, 5, 10, 0, 0, 0, 0, 0]);
    assert_eq!(f.hub.device_address(), 0);
    assert_eq!(f.hub.host_in(11, 0), Err(LpcipUsbError::AddressMismatch));
    f.hub.host_setup(10, &GET_DESCRIPTOR).unwrap();
    assert_eq!(f.hub.device_address(), 10);
    assert_eq!(f.hub.host_in(0, 0), Err(LpcipUsbError::AddressMismatch));
    f.hub.host_setup(10, &[0xa0, 0, 0, 0, 0, 0, 4, 0]).unwrap();
    assert_eq!(
        f.hub.host_setup(10, &[0; 7]),
        Err(LpcipUsbError::InvalidSetup)
    );
    assert_eq!(f.hub.host_in(10, 0).unwrap(), [0; 4]);
    f.hub.host_out(10, 0, &[]).unwrap();
    f.hub
        .host_setup(10, &[0x40, 0xff, 0, 0, 0, 0, 0, 0])
        .unwrap();
    assert_eq!(f.hub.host_in(10, 0), Err(LpcipUsbError::Stall));
    assert_eq!(f.hub.host_out(10, 0, &[]), Err(LpcipUsbError::Stall));
    assert_eq!(f.control_at(10, &GET_DESCRIPTOR).len(), 18);
}

#[test]
fn port_change_notifications_persist_until_cleared_and_device1_can_connect_later() {
    let mut f = Compound::new();
    f.connect(0);
    f.enable_hub();
    f.configure_hub();
    assert_eq!(f.hub.host_in(10, 1).unwrap(), [2]);
    assert_eq!(f.hub.host_in(10, 1).unwrap(), [2]);
    assert_eq!(f.status(1) & 0xffff, 0x501);
    assert_eq!(f.status(2) & 0xffff, 0x500);
    f.port_feature(1, 16, false);
    assert_eq!(f.hub.host_in(10, 1), Err(LpcipUsbError::Nak));
    assert_eq!(
        f.hub.port_setup(1, 0, &GET_DESCRIPTOR),
        Err(LpcipUsbError::EndpointDisabled)
    );
    f.port_feature(1, 4, true);
    assert_eq!(f.status(1), 0x0010_0503);
    f.port_feature(1, 20, false);
    f.connect(1);
    assert_eq!(f.hub.host_in(10, 1).unwrap(), [4]);
    assert_eq!(
        f.hub.port_setup(2, 0, &GET_DESCRIPTOR),
        Err(LpcipUsbError::EndpointDisabled)
    );
    f.port_feature(2, 16, false);
    f.port_feature(2, 4, true);
    assert_eq!(f.status(2), 0x0010_0503);
    f.port_feature(2, 20, false);
    assert_eq!(f.hub.host_in(10, 1), Err(LpcipUsbError::Nak));
    f.write(1, 0, DEV_EN);
    assert_eq!(f.hub.host_in(10, 1).unwrap(), [4]);
    assert_eq!(f.status(2), 0x0001_0500);
    assert_eq!(f.hub.port_in(2, 0, 0), Err(LpcipUsbError::Disconnected));
}

#[test]
fn both_ports_require_independent_firmware_service_and_keep_addresses_and_payloads_isolated() {
    let mut f = Compound::new();
    f.connect(0);
    f.enable_hub();
    f.configure_hub();
    f.port_feature(1, 4, true);
    f.set_device_address(1, 4);
    f.connect(1);
    f.port_feature(2, 4, true);
    f.set_device_address(2, 7);
    for (index, address) in [4, 7].into_iter().enumerate() {
        let port = index as u8 + 1;
        assert_eq!(f.hub.port_in(port, address, 0), Err(LpcipUsbError::Nak));
        f.put_bytes(index, 0x200, &[index as u8 + 1; 8]);
        f.descriptor(index, 1, 8, 0x200, ACTIVE);
        // Publishing a response is not enough until firmware acknowledges SETUP.
        assert_eq!(f.hub.port_in(port, address, 0), Err(LpcipUsbError::Nak));
        f.write(index, 0, DEVICE_CONTROL | SETUP | u32::from(address));
        assert_eq!(
            f.hub.port_in(port, address, 0).unwrap(),
            [index as u8 + 1; 8]
        );
    }
    assert_eq!(f.hub.port_in(1, 7, 0), Err(LpcipUsbError::AddressMismatch));
    assert_eq!(f.hub.port_in(2, 4, 0), Err(LpcipUsbError::AddressMismatch));
    f.port_feature(1, 4, true);
    assert_eq!(f.device[0].device_address(), 0);
    assert_eq!(f.device[1].device_address(), 7);
    assert_eq!(f.memory[1].read(RvSize::Word, 0x200).unwrap(), 0x0202_0202);
}

#[test]
fn device1_dma_cannot_access_device0_sram_and_has_its_own_bounds() {
    let mut f = Compound::new();
    f.connect(0);
    f.connect(1);
    f.put_bytes(0, 0x200, &[0xa5; 4]);
    f.descriptor(1, 1, 1, 0x200, ACTIVE);
    f.memory[1]
        .write(RvSize::Word, 8, ACTIVE | (1 << 11) | 8)
        .unwrap();
    assert_eq!(f.device[1].host_in(0, 0), Err(LpcipUsbError::InvalidMemory));
    assert_eq!(f.memory[0].read(RvSize::Word, 0x200).unwrap(), 0xa5a5_a5a5);
    assert_ne!(f.memory[1].read(RvSize::Word, 8).unwrap() & ACTIVE, 0);
    f.descriptor(1, 1, 64, 0xffc0, ACTIVE);
    assert_eq!(f.device[1].host_in(0, 0).unwrap().len(), 64);
    f.write(1, 8, USB_DEV0_MEM_ADDR);
    assert_eq!(f.device[1].host_in(0, 0), Err(LpcipUsbError::InvalidMemory));
    assert_eq!(
        f.memory[1].read(RvSize::Word, 0x10000),
        Err(BusError::LoadAccessFault)
    );
    assert_eq!(
        f.memory[1].write(RvSize::Word, 0x10000, 1),
        Err(BusError::StoreAccessFault)
    );
    assert_eq!(
        f.memory[1].read(RvSize::Byte, 0),
        Err(BusError::LoadAddrMisaligned)
    );
}

#[test]
fn device1_setup_reset_stall_and_interrupt_state_do_not_affect_device0() {
    let mut f = Compound::new();
    f.connect(0);
    f.connect(1);
    f.write(0, 0x24, 3);
    f.write(1, 0x24, 3);
    f.descriptor(0, 1, 0, 0x200, ACTIVE);
    f.device[1].host_setup(0, &GET_DESCRIPTOR).unwrap();
    assert_eq!(f.read(0, 0) & SETUP, 0);
    assert!(f.device[0].host_in(0, 0).unwrap().is_empty());
    assert_eq!(f.read(0, 0x20), 2);
    assert_eq!(f.read(1, 0x20), 1);
    f.write(1, 0x20, 1);
    assert!(!f.device[1].interrupt_pending());
    assert!(f.device[0].interrupt_pending());
    f.write(1, 0, DEVICE_CONTROL | SETUP);
    f.descriptor(1, 1, 0, 0x200, STALL);
    assert_eq!(f.device[1].host_in(0, 0), Err(LpcipUsbError::Stall));
    assert_eq!(f.device[0].host_in(0, 0), Err(LpcipUsbError::Nak));
    f.device[1].bus_reset(LpcipUsbSpeed::Full).unwrap();
    assert_eq!(f.read(0, 0) & RESET_CHANGE, 0);
    assert_ne!(f.read(1, 0) & RESET_CHANGE, 0);
}

#[test]
fn hub_bus_reset_resets_topology_but_keeps_firmware_tables_and_sram() {
    let mut f = Compound::new();
    f.connect(0);
    f.connect(1);
    f.set_word(2, 0x5678_1234);
    f.put_bytes(1, 0x200, &[0xcc; 4]);
    f.enable_hub();
    f.configure_hub();
    f.port_feature(1, 4, true);
    f.port_feature(2, 4, true);
    f.set_device_address(1, 4);
    f.set_device_address(2, 7);
    f.hub.bus_reset(LpcipUsbSpeed::Full).unwrap();
    assert_eq!(f.hub.device_address(), 0);
    assert_eq!(f.device[0].device_address(), 0);
    assert_eq!(f.device[1].device_address(), 0);
    assert_eq!(f.word(2), 0x5678_1234);
    assert_eq!(f.memory[1].read(RvSize::Word, 0x200).unwrap(), 0xcccc_cccc);
    assert_eq!(
        f.hub.port_setup(1, 0, &GET_DESCRIPTOR),
        Err(LpcipUsbError::EndpointDisabled)
    );
    f.csr[0].warm_reset();
    assert!(!f.hub.connected());
    assert!(!f.device[0].device_enabled());
    assert!(!f.device[1].device_enabled());
    assert_eq!(f.word(2), 0xbe00_1fc9);
    assert_eq!(f.memory[1].read(RvSize::Word, 0x200).unwrap(), 0xcccc_cccc);
}

#[test]
fn invalid_hub_requests_ports_and_corrupt_tables_fail_explicitly() {
    let mut f = Compound::new();
    f.connect(0);
    f.enable_hub();
    f.configure_hub();
    for port in [0, 3, 255] {
        assert_eq!(f.hub.port_in(port, 0, 0), Err(LpcipUsbError::InvalidPort));
    }
    f.hub.host_setup(10, &[0xa3, 0, 0, 0, 3, 0, 4, 0]).unwrap();
    assert_eq!(f.hub.host_in(10, 0), Err(LpcipUsbError::Stall));
    f.hub.host_setup(10, &[0, 9, 2, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(f.hub.host_in(10, 0), Err(LpcipUsbError::Stall));
    assert_eq!(f.control_at(10, &[0x80, 8, 0, 0, 0, 0, 1, 0]), [1]);
    assert_eq!(f.hub.host_in(10, 2), Err(LpcipUsbError::InvalidEndpoint));
    f.set_word(12, 1);
    f.set_word(97, 0xffff_bf00);
    f.set_word(12, HUB_CONTROL);
    assert_eq!(
        f.hub.host_setup(10, &GET_DESCRIPTOR),
        Err(LpcipUsbError::InvalidMemory)
    );
    f.set_word(12, 1);
    let last = f.word(193);
    f.set_word(193, last & !0x80);
    f.set_word(12, HUB_CONTROL);
    assert_eq!(
        f.hub.host_setup(10, &[0x40, 0xff, 0, 0, 0, 0, 0, 0]),
        Err(LpcipUsbError::InvalidMemory)
    );
}

#[test]
fn hub_port_suspend_gates_only_its_port_and_changes_are_acknowledged_separately() {
    let mut f = Compound::new();
    f.connect(0);
    f.connect(1);
    f.enable_hub();
    f.configure_hub();
    for port in [1, 2] {
        f.port_feature(port, 4, true);
        f.port_feature(port, 16, false);
        f.port_feature(port, 20, false);
    }
    f.port_feature(2, 2, true);
    assert_ne!(f.status(2) & 4, 0);
    assert_eq!(f.hub.port_in(2, 0, 0), Err(LpcipUsbError::Nak));
    f.hub.port_setup(1, 0, &GET_DESCRIPTOR).unwrap();
    assert_ne!(f.read(0, 0) & SETUP, 0);
    assert_eq!(f.read(1, 0) & SETUP, 0);
    f.port_feature(2, 2, false);
    assert_eq!(f.status(2) & 4, 0);
    assert_eq!(f.hub.host_in(10, 1).unwrap(), [4]);
    f.port_feature(2, 18, false);
    assert_eq!(f.hub.host_in(10, 1), Err(LpcipUsbError::Nak));
}
