// Licensed under the Apache-2.0 license

use super::*;
use caliptra_emu_bus::{Bus, Device, Event, EventData};
use caliptra_emu_types::RvSize;
use caliptra_mcu_emulator_registers_generated::usb_combo::UsbComboBus;
use std::sync::mpsc;

struct Fixture {
    bus: UsbComboBus,
    host: LpcipUsbHostController,
    memory: UsbDev0Mem,
    device1: UsbDev1,
    host1: LpcipUsbHostController,
}

fn setup(command: u8, read: bool, length: u16) -> [u8; 8] {
    let [low, high] = length.to_le_bytes();
    [
        if read { 0xa1 } else { 0x21 },
        0,
        command,
        0,
        0,
        0,
        low,
        high,
    ]
}

impl Fixture {
    fn new() -> Self {
        let combo = UsbCombo::new();
        let mut f = Self {
            host: combo.host_controller(),
            memory: combo.device0_memory(),
            device1: combo.device1(),
            host1: combo.device1_host_controller(),
            bus: UsbComboBus {
                periph: Box::new(combo),
            },
        };
        f.bus
            .write(RvSize::Word, 0, DEV_EN | CONNECT | FORCE_VBUS)
            .unwrap();
        f.bus.write(RvSize::Word, 8, USB_DEV0_MEM_ADDR).unwrap();
        f.bus.write(RvSize::Word, 12, USB_DEV0_MEM_ADDR).unwrap();
        f.memory.write_usb_dev0_mem(4, 1); // Mirrored SETUP at SRAM+0x100.
        f
    }

    fn read(&mut self, offset: u32) -> u32 {
        self.bus.read(RvSize::Word, 0x800 + offset).unwrap()
    }

    fn write(&mut self, offset: u32, value: u32) {
        self.bus.write(RvSize::Word, 0x800 + offset, value).unwrap();
    }

    fn get(&self, command: u8) -> Vec<u8> {
        self.host.host_setup(0, &setup(command, true, 64)).unwrap();
        let data = self.host.host_in(0, 0).unwrap();
        self.host.host_out(0, 0, &[]).unwrap();
        data
    }

    fn put(&self, command: u8, data: &[u8]) {
        self.host
            .host_setup(0, &setup(command, false, data.len() as u16))
            .unwrap();
        self.host.host_out(0, 0, data).unwrap();
        assert!(self.host.host_in(0, 0).unwrap().is_empty());
    }

    fn image(&self, words: u32) {
        let mut data = vec![0, 1];
        data.extend(words.to_le_bytes());
        self.put(0x2d, &data);
    }
}

#[test]
fn recovery_capabilities_and_cpu_masks_follow_rdl() {
    let mut f = Fixture::new();
    assert_eq!(
        f.get(0x22),
        [b'O', b'C', b'P', b' ', b'R', b'E', b'C', b'V', 1, 1, 0x9a, 0x1a, 1, 0, 0,]
    );
    f.write(0x0c, u32::MAX);
    assert_eq!(f.read(0x0c), 0x1fff_0101);
    f.write(0x10, u32::MAX);
    assert_eq!(f.read(0x10), 0x00ff_ffff);
    f.write(0x30, u32::MAX);
    assert_eq!(f.read(0x30), 0xffff_00ff);
    f.write(0x44, u32::MAX);
    assert_eq!(f.read(0x44), 0x00ff_ff07);
    assert_eq!(f.read(0x7fc), 0);
    f.bus.write(RvSize::Word, 0x804, 0).unwrap();
    assert_eq!(f.read(4), 0x2050_434f);
}

#[test]
fn recovery_setup_is_mirrored_without_firmware_irq_or_payload_dma() {
    let mut f = Fixture::new();
    f.memory.write_usb_dev0_mem(ACTIVE | (64 << 11) | 8, 0);
    f.memory.write_usb_dev0_mem(0xdead_beef, 0x200 / 4);
    let interrupt = f.bus.read(RvSize::Word, 0x20).unwrap();
    f.image(2);
    f.put(0x2f, &[1, 2, 3, 4, 5]);
    assert_eq!(f.bus.read(RvSize::Word, 0).unwrap() & SETUP, 0);
    assert_eq!(f.bus.read(RvSize::Word, 0x20).unwrap(), interrupt);
    assert_eq!(f.memory.read_usb_dev0_mem(0), ACTIVE | (64 << 11) | 8);
    assert_eq!(f.memory.read_usb_dev0_mem(0x200 / 4), 0xdead_beef);
    assert_eq!(f.memory.read_usb_dev0_mem(0x100 / 4), 0x002f_0021);
    assert_eq!(f.read(0x68), 0x0403_0201);
    assert_eq!(f.read(0x68), 5);
}

#[test]
fn recovery_standard_setup_returns_ownership_to_firmware() {
    let mut f = Fixture::new();
    f.get(0x22);
    f.host.host_setup(0, &[0x80, 6, 0, 1, 0, 0, 18, 0]).unwrap();
    assert!(!f.host.recovery_snapshot().unwrap().claimed);
    assert_ne!(f.bus.read(RvSize::Word, 0).unwrap() & SETUP, 0);
    assert_eq!(f.memory.read_usb_dev0_mem(0x100 / 4), 0x0100_0680);
}

#[test]
fn recovery_device1_has_no_hardware_engine() {
    let mut f = Fixture::new();
    f.device1
        .write_devcmdstat(ReadWriteRegister::new(DEV_EN | CONNECT | FORCE_VBUS));
    f.device1
        .write_epliststart(ReadWriteRegister::new(USB_DEV1_MEM_ADDR));
    f.device1
        .write_databufstart(ReadWriteRegister::new(USB_DEV0_MEM_ADDR));
    {
        let mut state = f.host1.state.lock().unwrap();
        state.memory[4..8].copy_from_slice(&((0x10000u32 + 0x100) >> 6).to_le_bytes());
    }
    f.host1.host_setup(0, &setup(0x22, true, 64)).unwrap();
    assert_eq!(f.host1.recovery_snapshot(), None);
    assert_ne!(f.device1.read_devcmdstat().reg.get() & SETUP, 0);
    assert_eq!(f.host1.host_in(0, 0), Err(LpcipUsbError::Nak));
}

#[test]
fn recovery_classification_does_not_claim_other_interfaces_or_requests() {
    let f = Fixture::new();
    for (index, value) in [(0, 0x81), (0, 0xc1), (1, 1), (4, 1), (5, 1)] {
        let mut request = setup(0x22, true, 64);
        request[index] = value;
        f.host.host_setup(0, &request).unwrap();
        assert!(!f.host.recovery_snapshot().unwrap().claimed);
    }
}

#[test]
fn recovery_malformed_claims_stall_and_preserve_first_error_until_status_completes() {
    let mut f = Fixture::new();
    for (request, error) in [
        (setup(0x23, true, 64), 1),
        (setup(0x29, true, 64), 1),
        (setup(0x22, false, 15), 1),
        (setup(0x2f, true, 64), 1),
        (setup(0xff, true, 64), 1),
        (setup(0x25, false, 2), 3),
        (setup(0x2d, false, 5), 3),
        (setup(0x2f, false, 65), 3),
        (setup(0x22, true, 15), 0xff),
        ([0xa1, 0, 0x22, 1, 0, 0, 64, 0], 0xff),
    ] {
        f.host.host_setup(0, &request).unwrap();
        assert_eq!(f.host.host_in(0, 0), Err(LpcipUsbError::Stall));
        assert_eq!((f.read(0x30) >> 8) as u8, error);
        f.host.host_setup(0, &setup(0xff, true, 64)).unwrap();
        assert_eq!((f.read(0x30) >> 8) as u8, error);
        f.host.host_setup(0, &setup(0x24, true, 64)).unwrap();
        assert_eq!(f.host.host_in(0, 0).unwrap()[1], error);
        assert_eq!((f.read(0x30) >> 8) as u8, error);
        f.host.host_out(0, 0, &[]).unwrap();
        assert_eq!((f.read(0x30) >> 8) as u8, 0);
    }
}

#[test]
fn recovery_capability_gates_device_id_reset_and_vendor() {
    let mut f = Fixture::new();
    f.write(0x0c, 0);
    for command in [0x23, 0x25, 0x2c] {
        f.host.host_setup(0, &setup(command, true, 64)).unwrap();
        assert_eq!(f.host.host_in(0, 0), Err(LpcipUsbError::Stall));
        f.get(0x24);
    }
    f.write(0x0c, (1 | 8 | (1 << 10)) << 16);
    f.write(0x14, 0x1234_5678);
    assert_eq!(&f.get(0x23)[..4], &0x1234_5678u32.to_le_bytes());
    f.put(0x2c, &[0xa5]);
    assert_eq!(f.get(0x2c), [0xa5]);
}

#[test]
fn recovery_status_reset_and_activation_are_shared_with_firmware() {
    let mut f = Fixture::new();
    f.write(0x30, 0x1234_0003);
    f.write(0x40, 0x21);
    f.write(0x44, 0x0080_0004);
    assert_eq!(f.get(0x24), [3, 0, 0x34, 0x12, 0, 0, 0]);
    assert_eq!(f.get(0x27), [0x21, 0]);
    assert_eq!(f.get(0x28), [4, 0, 0x80, 0]);
    f.put(0x25, &[0x10, 0x0e, 1]);
    assert_eq!(f.read(0x38), 0x010e10);
    f.write(0x38, 0);
    assert_eq!(f.get(0x25), [0, 0, 0]);
    f.image(1);
    f.put(0x2f, &[0x89, 0xab, 0xcd]);
    assert_eq!(f.read(0x204), 5);
    f.put(0x26, &[0, 1, 0x0f]);
    assert!(f.host.recovery_snapshot().unwrap().image_activated);
    assert_eq!(f.get(0x26), [0, 1, 0x0f]);
    f.write(0x3c, 0);
    assert!(!f.host.recovery_snapshot().unwrap().image_activated);
}

#[test]
fn recovery_fifo_backpressure_wrap_completion_and_partial_final_word() {
    let mut f = Fixture::new();
    f.image(131);
    for round in 0..2 {
        for _ in 0..4 {
            f.put(0x2f, &[round + 1; 64]);
        }
        assert_eq!(f.read(0x50), 2);
        assert_eq!(f.read(0x54), u32::from(round));
        assert_eq!(f.read(0x58), u32::from(round));
        assert_eq!(f.read(0x5c), 64);
        assert_eq!(f.read(0x60), 64);
        f.host.host_setup(0, &setup(0x2f, false, 4)).unwrap();
        assert_eq!(f.host.host_out(0, 0, &[0; 4]), Err(LpcipUsbError::Nak));
        for _ in 0..64 {
            assert_eq!(f.read(0x68), u32::from_le_bytes([round + 1; 4]));
        }
        // A NAK does not consume the packet or raise the internal-overflow bit.
        assert_eq!(f.read(0x204) & 2, 0);
        f.host.host_out(0, 0, &[3; 4]).unwrap();
        f.host.host_in(0, 0).unwrap();
        if round == 0 {
            assert_eq!(f.read(0x68), 0x0303_0303);
        }
    }
    f.put(0x2f, &[4, 5, 6]);
    assert_eq!(f.read(0x54), 3);
    assert_eq!(f.host.recovery_snapshot().unwrap().accepted_words, 131);
    assert_eq!(f.read(0x204), 5);
    assert_eq!(f.read(0x68), 0x0303_0303);
    assert_eq!(f.read(0x68), 0x0006_0504);
    f.host.host_setup(0, &setup(0x2f, false, 4)).unwrap();
    assert_eq!(f.host.host_out(0, 0, &[0; 4]), Err(LpcipUsbError::Nak));
}

#[test]
fn recovery_fifo_control_full_image_size_and_status_snapshot() {
    let mut f = Fixture::new();
    f.image(0x1234_5678);
    assert_eq!(f.read(0x4c), 0x1234_5678);
    assert_eq!(f.get(0x2d), [0, 0, 0x78, 0x56, 0x34, 0x12]);
    f.put(0x2f, &[1; 64]);
    assert_eq!(f.read(0x50), 0);
    assert_eq!(f.read(0x68), 0x0101_0101);
    assert_eq!(f.read(0x54), 16);
    assert_eq!(
        f.read(0x58),
        0,
        "snapshot must retain the pre-pop read index"
    );
    f.read(0x60);
    assert_eq!(f.read(0x58), 1);
    let status = f.get(0x2e);
    assert_eq!(status.len(), 20);
    assert_eq!(&status[8..12], &1u32.to_le_bytes());
}

#[test]
fn recovery_fifo_reset_underflow_and_reserved_bits_are_observable() {
    let mut f = Fixture::new();
    f.image(1);
    f.put(0x2f, &[1; 4]);
    f.write(0x48, u32::MAX);
    assert_eq!(f.read(0x48), 0xff);
    assert_eq!(f.read(0x204), 1);
    assert_eq!(f.read(0x50), 1);
    assert_eq!(f.read(0x54), 0);
    assert_eq!(f.read(0x68), 0);
    assert_eq!(f.host.recovery_snapshot().unwrap().underflow_reads, 1);
    assert_eq!(f.read(0x4c), 1);
}

#[test]
fn recovery_interruption_flushes_unconsumed_batch_and_general_error_self_clears() {
    let mut f = Fixture::new();
    f.image(20);
    f.put(0x2f, &[7; 64]);
    f.host.host_setup(0, &setup(0x2f, false, 16)).unwrap();
    f.host.host_setup(0, &setup(0x24, true, 64)).unwrap();
    assert_eq!(f.read(0x204), 9);
    assert_eq!(f.read(0x50), 1);
    assert_eq!(f.host.recovery_snapshot().unwrap().accepted_words, 0);
    f.write(0x200, 4);
    assert_eq!(f.read(0x200), 0);
    assert_eq!(f.host.host_in(0, 0), Err(LpcipUsbError::Stall));
    assert_eq!(f.get(0x24)[1], 0xff);
    f.write(0x48, 0x100);
    assert_eq!(f.read(0x204), 1);
    f.write(0x200, 4);
    assert_eq!(f.read(0x30) & 0xff00, 0);
}

#[test]
fn recovery_disable_affects_future_claims_and_abort_hands_ep0_back() {
    let mut f = Fixture::new();
    f.host.host_setup(0, &setup(0x22, true, 64)).unwrap();
    f.write(0x200, 1);
    assert_eq!(f.host.host_in(0, 0).unwrap().len(), 15);
    f.host.host_out(0, 0, &[]).unwrap();
    f.host.host_setup(0, &setup(0xff, true, 64)).unwrap();
    assert!(!f.host.recovery_snapshot().unwrap().claimed);
    assert_ne!(f.bus.read(RvSize::Word, 0).unwrap() & SETUP, 0);
    assert_eq!(f.host.host_in(0, 0), Err(LpcipUsbError::Nak));
    f.write(0x200, 0);
    f.image(16);
    f.host.host_setup(0, &setup(0x2f, false, 64)).unwrap();
    f.write(0x200, 3);
    assert_eq!(f.read(0x200), 1);
    assert!(!f.host.recovery_snapshot().unwrap().claimed);
    assert_eq!(f.read(0x204), 9);
}

#[test]
fn recovery_bus_reset_aborts_transfer_but_preserves_registers() {
    let mut f = Fixture::new();
    f.image(32);
    f.put(0x2f, &[1; 64]);
    f.host.host_setup(0, &setup(0x2f, false, 64)).unwrap();
    f.host.bus_reset(LpcipUsbSpeed::High).unwrap();
    assert_eq!(f.read(0x204), 9);
    assert_eq!(f.read(0x4c), 32);
    assert_eq!(f.read(0x50), 1);
    f.bus.warm_reset();
    assert_eq!(f.read(0x204), 0);
    assert_eq!(f.read(0x4c), 0);
    assert_eq!(f.read(0x0c), 0x1a9a_0101);
    assert_eq!(f.host1.recovery_snapshot(), None);
}

#[test]
fn recovery_wrong_data_length_stalls_without_committing_payload() {
    let mut f = Fixture::new();
    f.image(2);
    f.host.host_setup(0, &setup(0x2f, false, 8)).unwrap();
    assert_eq!(f.host.host_out(0, 0, &[1; 4]), Err(LpcipUsbError::Stall));
    assert_eq!(f.read(0x50), 1);
    assert_eq!(f.get(0x24)[1], 3);
}

#[test]
fn recovery_replacement_setup_after_committed_data_does_not_abort_the_batch() {
    let mut f = Fixture::new();
    f.image(1);
    f.host.host_setup(0, &setup(0x2f, false, 4)).unwrap();
    f.host.host_out(0, 0, &[1, 2, 3, 4]).unwrap();
    // Supersede only the status stage: DATA has already drained into the FIFO.
    assert_eq!(f.get(0x27), [0, 0]);
    assert_eq!(f.read(0x204), 5);
    assert_eq!(f.host.recovery_snapshot().unwrap().accepted_words, 1);
    assert_eq!(f.read(0x68), 0x0403_0201);
}

#[test]
fn recovery_event_adapter_does_not_mix_dma_data_across_fifo_reset() {
    let mut f = Fixture::new();
    let (to_core, responses) = mpsc::channel();
    let (core, from_core) = mpsc::channel();
    let (to_mcu, _mcu_responses) = mpsc::channel();
    let (_mcu, from_mcu) = mpsc::channel();
    f.bus
        .periph
        .register_event_channels(to_core, from_core, to_mcu, from_mcu);
    f.image(128);
    core.send(Event::new(
        Device::CaliptraCore,
        Device::RecoveryIntf,
        EventData::MemoryRead {
            start_addr: 0x68,
            len: 512,
        },
    ))
    .unwrap();
    for _ in 0..4 {
        f.put(0x2f, &[1; 64]);
    }
    f.bus.poll();
    assert!(responses.try_recv().is_err());
    f.write(0x48, 0x100);
    f.bus.poll();
    assert_eq!(f.host.recovery_snapshot().unwrap().aborted_dma_reads, 1);
    for _ in 0..4 {
        f.put(0x2f, &[2; 64]);
    }
    f.bus.poll();
    assert!(
        responses.try_recv().is_err(),
        "must not fabricate a mixed-image DMA completion"
    );
}
