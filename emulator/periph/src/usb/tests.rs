// Licensed under the Apache-2.0 license

use super::*;
use caliptra_emu_bus::{Bus, BusError};
use caliptra_emu_types::RvSize;
use caliptra_mcu_emulator_registers_generated::{
    usb_combo::UsbComboBus, usb_dev0_mem::UsbDev0MemBus,
};

const CONTROL: u32 = DEV_EN | CONNECT;
const GET_DESCRIPTOR: [u8; 8] = [0x80, 6, 0, 1, 0, 0, 18, 0];
const DEVICE_DESCRIPTOR: [u8; 18] = [18, 1, 0, 2, 0, 0, 0, 64, 0x14, 0x14, 1, 0, 0, 1, 0, 0, 0, 1];

struct Fixture {
    csr: UsbComboBus,
    memory: UsbDev0MemBus,
    host: LpcipUsbHostController,
}

impl Fixture {
    fn new() -> Self {
        let device = UsbCombo::new();
        let mut fixture = Self {
            host: device.host_controller(),
            memory: UsbDev0MemBus {
                periph: Box::new(device.device0_memory()),
            },
            csr: UsbComboBus {
                periph: Box::new(device),
            },
        };
        fixture.write(8, USB_DEV0_MEM_ADDR);
        fixture.write(12, USB_DEV0_MEM_ADDR);
        fixture.descriptor(0, 1, 0, 0x100, 0);
        fixture.host.set_vbus(true);
        fixture.write(0, CONTROL);
        fixture.write(0x20, u32::MAX);
        fixture
    }

    fn write(&mut self, offset: u32, value: u32) {
        self.csr.write(RvSize::Word, offset, value).unwrap();
    }

    fn read(&mut self, offset: u32) -> u32 {
        self.csr.read(RvSize::Word, offset).unwrap()
    }

    fn descriptor(&mut self, physical: u32, bank: u32, length: u32, buffer: u32, flags: u32) {
        assert_eq!(buffer & 63, 0);
        self.memory
            .write(
                RvSize::Word,
                physical * 8 + bank * 4,
                flags | (length << 11) | (buffer >> 6),
            )
            .unwrap();
    }

    fn descriptor_word(&mut self, physical: u32, bank: u32) -> u32 {
        self.memory
            .read(RvSize::Word, physical * 8 + bank * 4)
            .unwrap()
    }

    fn put_bytes(&mut self, offset: u32, bytes: &[u8]) {
        for (index, chunk) in bytes.chunks(4).enumerate() {
            let mut word = [0; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            self.memory
                .write(
                    RvSize::Word,
                    offset + index as u32 * 4,
                    u32::from_le_bytes(word),
                )
                .unwrap();
        }
    }

    fn get_bytes(&mut self, offset: u32, length: usize) -> Vec<u8> {
        (0..length.div_ceil(4))
            .flat_map(|index| {
                self.memory
                    .read(RvSize::Word, offset + index as u32 * 4)
                    .unwrap()
                    .to_le_bytes()
            })
            .take(length)
            .collect()
    }
}

#[test]
fn enumeration_requires_firmware_owned_descriptors() {
    let mut f = Fixture::new();
    f.host.bus_reset(LpcipUsbSpeed::Full).unwrap();
    f.host.host_setup(0, &GET_DESCRIPTOR).unwrap();
    assert_eq!(f.get_bytes(0x100, 8), GET_DESCRIPTOR);
    assert_eq!(f.host.host_in(0, 0), Err(LpcipUsbError::Nak));
    f.write(0, CONTROL | SETUP);
    assert_eq!(f.host.host_in(0, 0), Err(LpcipUsbError::Nak));

    f.put_bytes(0x200, &DEVICE_DESCRIPTOR);
    f.descriptor(1, 0, 18, 0x200, ACTIVE);
    assert_eq!(f.descriptor_word(1, 0), 0x8000_9008);
    assert_eq!(f.host.host_in(0, 0).unwrap(), DEVICE_DESCRIPTOR);
    assert_eq!(f.descriptor_word(1, 0) & (ACTIVE | LENGTH_MASK), 0);
    f.descriptor(0, 0, 0, 0x300, ACTIVE);
    f.host.host_out(0, 0, &[]).unwrap();

    // Firmware services SET_ADDRESS, including its zero-length status packet.
    f.host.host_setup(0, &[0, 5, 7, 0, 0, 0, 0, 0]).unwrap();
    f.write(0, CONTROL | SETUP | 7);
    f.descriptor(1, 0, 0, 0x200, ACTIVE);
    assert!(f.host.host_in(0, 0).unwrap().is_empty());
    // Selected usb_reg_if latches the address on SETUP, not on IN completion.
    assert_eq!(f.read(0) & 0x7f, 0);
    f.host.host_setup(7, &[0, 9, 1, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(f.read(0) & 0x7f, 7);
    assert_eq!(f.host.host_in(0, 0), Err(LpcipUsbError::AddressMismatch));
    assert_eq!(f.host.host_in(7, 0), Err(LpcipUsbError::Nak));
    f.write(0, CONTROL | SETUP | 7);
    f.descriptor(1, 0, 0, 0x200, ACTIVE);
    assert!(f.host.host_in(7, 0).unwrap().is_empty());
}

#[test]
fn in_packets_update_residual_offset_and_interrupt_only_on_completion() {
    let mut f = Fixture::new();
    let data: Vec<u8> = (0..150).collect();
    f.put_bytes(0x200, &data);
    f.descriptor(3, 0, 150, 0x200, ACTIVE | TOGGLE_RESET);
    assert_eq!(f.host.host_in(0, 1).unwrap(), data[..64]);
    assert_eq!(f.descriptor_word(3, 0), ACTIVE | (86 << 11) | 9);
    assert_eq!(f.read(0x20) & (1 << 3), 0);
    assert_eq!(f.host.host_in(0, 1).unwrap(), data[64..128]);
    assert_eq!(f.host.host_in(0, 1).unwrap(), data[128..]);
    assert_eq!(f.descriptor_word(3, 0), 11);
    assert_ne!(f.read(0x20) & (1 << 3), 0);
    assert_eq!(f.host.host_in(0, 1), Err(LpcipUsbError::Nak));
}

#[test]
fn out_short_packet_returns_ownership_and_preserves_surrounding_bytes() {
    let mut f = Fixture::new();
    f.put_bytes(0x200, &[0xaa; 128]);
    f.descriptor(2, 0, 128, 0x200, ACTIVE);
    f.host.host_out(0, 1, &[1; 64]).unwrap();
    assert_ne!(f.descriptor_word(2, 0) & ACTIVE, 0);
    f.host.host_out(0, 1, &[2, 3, 4]).unwrap();
    assert_eq!(f.descriptor_word(2, 0), (61 << 11) | 10);
    assert_eq!(f.get_bytes(0x200, 64), [1; 64]);
    assert_eq!(f.get_bytes(0x240, 4), [2, 3, 4, 0xaa]);
    assert_eq!(f.host.host_out(0, 1, &[]), Err(LpcipUsbError::Nak));
}

#[test]
fn high_speed_bulk_uses_512_byte_packets_but_ep0_uses_64() {
    let mut f = Fixture::new();
    f.host.bus_reset(LpcipUsbSpeed::High).unwrap();
    assert_eq!((f.read(0) >> 22) & 3, 2);
    f.descriptor(3, 0, 600, 0x200, ACTIVE);
    assert_eq!(f.host.host_in(0, 1).unwrap().len(), 512);
    assert_eq!(f.host.host_in(0, 1).unwrap().len(), 88);
    f.descriptor(1, 0, 128, 0x200, ACTIVE);
    assert_eq!(f.host.host_in(0, 0).unwrap().len(), 64);
    f.write(0, CONTROL | (1 << 21));
    f.host.bus_reset(LpcipUsbSpeed::High).unwrap();
    assert_eq!((f.read(0) >> 22) & 3, 1);
}

#[test]
fn double_buffers_switch_only_on_completion_and_can_be_selected_by_firmware() {
    let mut f = Fixture::new();
    f.write(0x1c, 1 << 3);
    f.put_bytes(0x200, &[1; 65]);
    f.put_bytes(0x300, &[2; 4]);
    f.descriptor(3, 0, 65, 0x200, ACTIVE);
    f.descriptor(3, 1, 4, 0x300, ACTIVE);
    assert_eq!(f.host.host_in(0, 1).unwrap(), [1; 64]);
    assert_eq!(f.read(0x18), 0);
    assert_eq!(f.host.host_in(0, 1).unwrap(), [1]);
    assert_eq!(f.read(0x18), 1 << 3);
    assert_eq!(f.host.host_in(0, 1).unwrap(), [2; 4]);
    assert_eq!(f.read(0x18), 0);
    f.write(0x18, u32::MAX);
    assert_eq!(f.read(0x18), NONCONTROL_ENDPOINTS);
    f.write(0x1c, u32::MAX);
    assert_eq!(f.read(0x1c), NONCONTROL_ENDPOINTS);
}

#[test]
fn stall_and_disabled_endpoint_do_not_consume_descriptors() {
    let mut f = Fixture::new();
    f.descriptor(1, 0, 0, 0x200, STALL);
    let before = f.descriptor_word(1, 0);
    assert_eq!(f.host.host_in(0, 0), Err(LpcipUsbError::Stall));
    assert_eq!(f.descriptor_word(1, 0), before);
    f.descriptor(3, 0, 0, 0x200, ACTIVE | DISABLED);
    assert_eq!(f.host.host_in(0, 1), Err(LpcipUsbError::EndpointDisabled));
    f.descriptor(1, 0, 0, 0x200, ACTIVE | STALL);
    assert!(f.host.host_in(0, 0).unwrap().is_empty());
    assert_eq!(f.host.host_in(0, 0), Err(LpcipUsbError::Stall));
    // DISABLED is ignored on EP0 by the selected DMA.
    f.descriptor(1, 0, 0, 0x200, ACTIVE | DISABLED);
    assert!(f.host.host_in(0, 0).unwrap().is_empty());
}

#[test]
fn superseding_setup_holds_ep0_without_erasing_firmware_descriptors() {
    let mut f = Fixture::new();
    f.descriptor(1, 0, 16, 0x200, ACTIVE | STALL);
    let old = f.descriptor_word(1, 0);
    f.host.host_setup(0, &GET_DESCRIPTOR).unwrap();
    f.host.host_setup(0, &[0, 9, 1, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(f.get_bytes(0x100, 8), [0, 9, 1, 0, 0, 0, 0, 0]);
    assert_eq!(f.descriptor_word(1, 0), old);
    assert_eq!(f.host.host_in(0, 0), Err(LpcipUsbError::Nak));
    assert_eq!(f.read(0x34) & 3, 3);
    f.write(0x14, 2);
    assert_eq!(f.read(0x14), 0);
    assert_eq!(f.descriptor_word(1, 0), old & !ACTIVE);
    f.descriptor(1, 0, 0, 0x200, ACTIVE);
    assert_eq!(f.host.host_in(0, 0), Err(LpcipUsbError::Nak));
    f.write(0, CONTROL | SETUP);
    assert!(f.host.host_in(0, 0).unwrap().is_empty());
}

#[test]
fn reset_restores_address_and_toggle_but_not_sram_or_descriptors() {
    let mut f = Fixture::new();
    f.write(0, CONTROL | 23);
    f.host.host_setup(23, &GET_DESCRIPTOR).unwrap();
    f.write(0, CONTROL | SETUP | 23);
    f.descriptor(1, 0, 8, 0x200, ACTIVE | STALL);
    f.put_bytes(0x200, &[0xa5; 8]);
    let before = f.descriptor_word(1, 0);
    f.host.bus_reset(LpcipUsbSpeed::Full).unwrap();
    assert_eq!(f.host.device_address(), 0);
    assert_eq!(f.read(0x34), 0);
    assert_eq!(f.descriptor_word(1, 0), before);
    assert_eq!(f.get_bytes(0x200, 8), [0xa5; 8]);
    assert_ne!(f.read(0) & RESET_CHANGE, 0);
    assert_ne!(f.read(0x20) & DEVICE_INTERRUPT, 0);
    assert_eq!(f.host.host_in(23, 0), Err(LpcipUsbError::AddressMismatch));
}

#[test]
fn w1c_interrupt_enable_route_and_software_set() {
    let mut f = Fixture::new();
    f.write(0x28, 3 | FRAME_INTERRUPT);
    assert!(!f.host.interrupt_pending());
    f.write(0x24, 3 | FRAME_INTERRUPT);
    assert!(f.host.interrupt_pending());
    f.write(0x20, 1);
    assert_eq!(f.read(0x20), 2 | FRAME_INTERRUPT);
    f.write(0x2c, 2 | FRAME_INTERRUPT);
    assert!(!f.host.interrupt_pending());
    assert!(f.host.fast_interrupt_pending());
    f.write(0x20, 2 | FRAME_INTERRUPT);
    assert!(!f.host.fast_interrupt_pending());
    f.write(0x24, 0);
    f.host.host_sof(0xffff).unwrap();
    assert_eq!(f.read(4) & 0x7ff, 0x7ff);
    assert_eq!(f.read(0x20), FRAME_INTERRUPT);
    assert!(!f.host.interrupt_pending());
    // Change bits are independently W1C and cannot clear device enable.
    f.host.bus_reset(LpcipUsbSpeed::Full).unwrap();
    f.write(0, CONTROL | RESET_CHANGE);
    assert_eq!(f.read(0) & RESET_CHANGE, 0);
    assert!(f.host.device_enabled());
    assert_ne!(f.read(0x20) & DEVICE_INTERRUPT, 0);
}

#[test]
fn nak_interrupt_controls_are_direction_specific() {
    let mut f = Fixture::new();
    f.write(0, CONTROL | (1 << 15));
    assert_eq!(f.host.host_in(0, 0), Err(LpcipUsbError::Nak));
    assert_eq!(f.read(0x20), 2);
    assert_eq!(f.host.host_out(0, 0, &[]), Err(LpcipUsbError::Nak));
    assert_eq!(f.read(0x20), 2);
}

#[test]
fn enable_connect_vbus_and_force_vbus_are_required() {
    let mut f = Fixture::new();
    f.descriptor(1, 0, 0, 0x200, ACTIVE);
    f.host.set_vbus(false);
    assert!(!f.host.connected());
    assert_eq!(f.read(0) & VBUS, 0);
    assert_eq!(f.host.host_in(0, 0), Err(LpcipUsbError::Disconnected));
    assert_eq!(
        f.host.bus_reset(LpcipUsbSpeed::Full),
        Err(LpcipUsbError::Disconnected)
    );
    f.write(0, CONTROL | FORCE_VBUS);
    assert!(f.host.connected());
    assert_eq!(f.read(0) & VBUS, 0);
    f.write(0, DEV_EN | FORCE_VBUS);
    assert!(!f.host.connected());
    f.host.set_vbus(true);
    f.write(0, CONNECT);
    assert!(!f.host.connected());
    assert_ne!(f.read(0) & CONNECT_CHANGE, 0);
}

#[test]
fn invalid_setup_endpoint_length_and_dma_are_explicit_and_non_destructive() {
    let mut f = Fixture::new();
    assert_eq!(
        f.host.host_setup(0, &[0; 7]),
        Err(LpcipUsbError::InvalidSetup)
    );
    assert_eq!(f.host.host_in(0, 15), Err(LpcipUsbError::InvalidEndpoint));
    assert_eq!(f.host.host_in(0, 255), Err(LpcipUsbError::InvalidEndpoint));
    assert_eq!(
        f.host.host_out(0, 255, &[]),
        Err(LpcipUsbError::InvalidEndpoint)
    );
    f.descriptor(2, 0, 2, 0x200, ACTIVE);
    let before = f.descriptor_word(2, 0);
    assert_eq!(
        f.host.host_out(0, 1, &[0; 3]),
        Err(LpcipUsbError::DataTooLong)
    );
    assert_eq!(f.descriptor_word(2, 0), before);
    f.descriptor(2, 0, 100, 0x200, ACTIVE);
    assert_eq!(
        f.host.host_out(0, 1, &[0; 65]),
        Err(LpcipUsbError::DataTooLong)
    );
    f.descriptor(1, 0, 64, 0xffc0, ACTIVE);
    assert_eq!(f.host.host_in(0, 0).unwrap().len(), 64);
    f.descriptor(1, 0, 1, 0x10000, ACTIVE);
    let before = f.descriptor_word(1, 0);
    assert_eq!(f.host.host_in(0, 0), Err(LpcipUsbError::InvalidMemory));
    assert_eq!(f.descriptor_word(1, 0), before);
    f.descriptor(0, 1, 0, 0x10000, 0);
    assert_eq!(
        f.host.host_setup(0, &GET_DESCRIPTOR),
        Err(LpcipUsbError::InvalidMemory)
    );
    f.write(8, 0xffff_ffff);
    assert_eq!(f.read(8), 0xffff_ff00);
    assert_eq!(f.host.host_in(0, 0), Err(LpcipUsbError::InvalidMemory));
    f.write(8, USB_DEV0_MEM_ADDR);
    f.write(12, 0xffff_ffff);
    assert_eq!(f.read(12), 0xfffe_0000);
    assert_eq!(
        f.host.host_out(0, 1, &[1]),
        Err(LpcipUsbError::InvalidMemory)
    );
}

#[test]
fn packet_memory_bus_bounds_alignment_and_reset_preservation() {
    let mut f = Fixture::new();
    assert_eq!(
        f.memory.read(RvSize::Word, 0x10000),
        Err(BusError::LoadAccessFault)
    );
    assert_eq!(
        f.memory.write(RvSize::Word, 0x10000, 1),
        Err(BusError::StoreAccessFault)
    );
    assert_eq!(
        f.memory.read(RvSize::Word, 1),
        Err(BusError::LoadAddrMisaligned)
    );
    assert_eq!(
        f.memory.write(RvSize::Byte, 0, 1),
        Err(BusError::StoreAddrMisaligned)
    );
    f.put_bytes(0x200, &[42; 4]);
    f.csr.warm_reset();
    assert!(!f.host.device_enabled());
    assert_eq!(f.get_bytes(0x200, 4), [42; 4]);
    assert_eq!(f.read(0x20), 0);
    f.csr.update_reset();
    assert_eq!(f.read(0x24), 0);
}

#[test]
fn device1_registers_and_memory_are_independent_and_disabled_at_reset() {
    use caliptra_mcu_emulator_registers_generated::{
        usb_dev1::UsbDev1Bus, usb_dev1_mem::UsbDev1MemBus,
    };
    let combo = UsbCombo::new();
    let host = combo.device1_host_controller();
    let mut device = UsbDev1Bus {
        periph: Box::new(combo.device1()),
    };
    let mut memory = UsbDev1MemBus {
        periph: Box::new(combo.device1_memory()),
    };
    assert!(!host.device_enabled());
    assert!(!host.connected());
    assert_eq!(device.read(RvSize::Word, 0).unwrap(), 0);
    device.write(RvSize::Word, 0x28, 1).unwrap();
    assert_eq!(device.read(RvSize::Word, 0x20).unwrap(), 1);
    assert!(!combo.host_controller().interrupt_pending());
    memory.write(RvSize::Word, 0, 0x1234).unwrap();
    assert_eq!(memory.read(RvSize::Word, 0).unwrap(), 0x1234);
    let mut device0_memory = combo.device0_memory();
    assert_eq!(device0_memory.read_usb_dev0_mem(0), 0);
}

#[test]
fn unsupported_iso_is_explicit_and_interrupt_packets_use_descriptor_limits() {
    let mut f = Fixture::new();
    f.descriptor(3, 0, 100, 0x200, ACTIVE | PERIODIC);
    let before = f.descriptor_word(3, 0);
    assert_eq!(
        f.host.host_in(0, 1),
        Err(LpcipUsbError::UnsupportedTransfer)
    );
    assert_eq!(f.descriptor_word(3, 0), before);
    f.host.bus_reset(LpcipUsbSpeed::High).unwrap();
    f.descriptor(3, 0, 1025, 0x200, ACTIVE | PERIODIC | TOGGLE_VALUE);
    assert_eq!(f.host.host_in(0, 1).unwrap().len(), 1024);
    assert_eq!(f.host.host_in(0, 1).unwrap().len(), 1);
}

#[test]
fn info_error_code_and_configuration_are_hardware_owned_except_diagnostics() {
    let mut f = Fixture::new();
    assert_eq!(f.read(4) >> 24, 2);
    assert_eq!(f.read(0x30), 28 | (1 << 5) | (1 << 6) | (1 << 7));
    f.write(4, u32::MAX);
    assert_eq!(f.read(4), 0x0200_7800);
    assert_eq!(f.host.host_in(0, 0), Err(LpcipUsbError::Nak));
    assert_eq!((f.read(4) >> 11) & 15, 9);
    f.descriptor(1, 0, 0, 0x200, STALL);
    assert_eq!(f.host.host_in(0, 0), Err(LpcipUsbError::Stall));
    assert_eq!((f.read(4) >> 11) & 15, 10);
}

#[test]
fn controller_instances_do_not_share_sram_or_connection_state() {
    let mut first = Fixture::new();
    let mut second = Fixture::new();
    first.put_bytes(0x200, &[0xa5; 4]);
    assert_eq!(second.get_bytes(0x200, 4), [0; 4]);
    first.host.set_vbus(false);
    assert!(second.host.connected());
    assert_eq!(second.read(0x20), 0);
}

#[test]
fn zero_length_status_packets_do_not_dma_through_unused_buffer_pointers() {
    let mut f = Fixture::new();
    f.write(12, 0xffff_ffff);
    f.descriptor(1, 0, 0, 0, ACTIVE);
    assert!(f.host.host_in(0, 0).unwrap().is_empty());
    f.descriptor(0, 0, 0, 0, ACTIVE);
    f.host.host_out(0, 0, &[]).unwrap();
}

#[test]
fn polling_ors_legacy_and_lpcip_interrupts_on_the_shared_pic_line() {
    use caliptra_emu_bus::Clock;
    use caliptra_emu_cpu::Pic;
    use caliptra_mcu_emulator_registers_generated::usbdev::UsbdevPeripheral;
    use std::rc::Rc;

    let pic = Pic::new();
    let mut pic_regs = pic.mmio_regs(Rc::new(Clock::new()));
    let irq = crate::McuRootBus::USB_IRQ;
    pic_regs
        .write(RvSize::Word, 0x2000 + u32::from(irq) * 4, 1)
        .unwrap();
    pic_regs.write(RvSize::Word, u32::from(irq) * 4, 1).unwrap();
    let mut legacy = crate::UsbDevPeriph::new_with_irq(pic.register_irq(irq));
    let mut device = UsbCombo::new_with_irq(pic.register_irq(irq), legacy.host_controller());
    device.write_dev0_csr_intsetstat(ReadWriteRegister::new(1));
    assert_eq!(pic.highest_priority_irq(0), None);
    device.write_dev0_csr_inten(ReadWriteRegister::new(1));
    assert_eq!(pic.highest_priority_irq(0), Some(irq));
    legacy.poll();
    device.poll();
    assert_eq!(pic.highest_priority_irq(0), Some(irq));
    legacy.write_intr_enable(ReadWriteRegister::new(1));
    legacy.write_intr_test(ReadWriteRegister::new(1));
    device.write_dev0_csr_intstat(ReadWriteRegister::new(1));
    assert_eq!(pic.highest_priority_irq(0), Some(irq));
    legacy.write_intr_state(ReadWriteRegister::new(1));
    device.poll();
    assert_eq!(pic.highest_priority_irq(0), None);
    device.write_dev0_csr_introute(ReadWriteRegister::new(1));
    device.write_dev0_csr_intsetstat(ReadWriteRegister::new(1));
    assert!(device.host_controller().fast_interrupt_pending());
    assert_eq!(pic.highest_priority_irq(0), None);
    let mut device1 = device.device1();
    device1.write_inten(ReadWriteRegister::new(1));
    device1.write_intsetstat(ReadWriteRegister::new(1));
    device.poll();
    assert_eq!(pic.highest_priority_irq(0), Some(irq));
    device.write_dev0_csr_intstat(ReadWriteRegister::new(1));
    assert_eq!(pic.highest_priority_irq(0), Some(irq));
    device1.write_introute(ReadWriteRegister::new(1));
    device.poll();
    assert!(device.device1_host_controller().fast_interrupt_pending());
    assert_eq!(pic.highest_priority_irq(0), None);
    device1.write_intstat(ReadWriteRegister::new(1));
    device.poll();
    assert!(!device.device1_host_controller().fast_interrupt_pending());
}
