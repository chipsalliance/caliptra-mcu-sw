// Licensed under the Apache-2.0 license

extern crate std;
use super::*;

fn driver() -> UsbStressDriver {
    let params = super::super::tests::params();
    let mut driver = UsbStressDriver::new(params);
    driver.driver.initialized = true;
    driver.driver.address = 7;
    driver.driver.configuration = 1;
    driver
        .driver
        .params
        .registers
        .dev0_csr_devcmdstat
        .set(KEEP_CLOCK | (1 << 7) | (1 << 16) | (1 << 28) | (2 << 22));
    driver
}

fn setup(raw: [u8; 8]) -> SetupPacket {
    zerocopy::transmute!(raw)
}

#[test]
fn secondary_initialization_leaves_shared_recovery_hub_and_phy_untouched() {
    #[repr(align(131072))]
    struct AlignedMemory(usb_dev0_mem::regs::UsbDev0Mem);
    let memory = std::boxed::Box::leak(std::boxed::Box::new(AlignedMemory(unsafe {
        core::mem::zeroed()
    })));
    let mut params = super::super::tests::params();
    params.packet_memory = unsafe { StaticRef::new(&memory.0) };
    params.shared_phy_owner = false;
    let registers = params.registers;
    registers.recovery_caliptra_ctrl.set(0);
    registers.hub_control.set(0x1234);
    registers.hub_ulpidebug.set(0x5678);
    let mut driver = UsbStressDriver::new(params);
    assert_eq!(driver.initialize(), Err(UsbError::UnsupportedPhyInterface));
    assert_eq!(registers.recovery_caliptra_ctrl.get(), 0);
    assert_eq!(registers.hub_control.get(), 0x1234);
    assert_eq!(registers.hub_ulpidebug.get(), 0x5678);
    driver.driver.params.enable_hub = true;
    assert_eq!(driver.driver.validate(), Err(UsbError::InvalidParameters));
}

#[test]
fn stress_descriptors_keep_ep0_64_and_select_bulk_packet_size_by_speed() {
    let mut driver = driver();
    for (speed, packet) in [(1, 64u16), (2, 512)] {
        let register = &driver.driver.params.registers.dev0_csr_devcmdstat;
        register.set((register.get() & !(3 << 22)) | (speed << 22));
        for (kind, size) in [(2, packet), (7, 576 - packet)] {
            assert!(matches!(
                driver.request(&setup([0x80, 6, 0, kind, 0, 0, 255, 0])),
                Ok(Response::Read(41))
            ));
            assert_eq!(driver.data[13], 0);
            assert_eq!(driver.data[22], 2);
            assert_eq!(u16::from_le_bytes([driver.data[31], driver.data[32]]), size);
            assert_eq!(u16::from_le_bytes([driver.data[38], driver.data[39]]), size);
        }
        driver
            .request(&setup([0x80, 6, 0, 1, 0, 0, 18, 0]))
            .unwrap();
        assert_eq!(driver.data[7], 64);
    }
}

#[test]
fn source_sink_and_short_loopback_use_distinct_nonoverlapping_buffers() {
    let mut driver = driver();
    driver.alternate = 1;
    driver.poll_bulk().unwrap();
    assert!(driver.armed.iter().all(|&armed| armed));
    assert_eq!(
        (driver.driver.read_word(BULK_IN).unwrap() >> 11) & 0x7fff,
        512
    );
    let mut data = [1; 512];
    driver.buffer_read(BULK_IN_BUFFER, &mut data).unwrap();
    assert_eq!(data, [0; 512]);

    driver.armed = [false; 2];
    driver.mode = 1;
    driver
        .driver
        .write_word(BULK_OUT, DISABLED | TOGGLE_RESET)
        .unwrap();
    driver
        .driver
        .write_word(BULK_IN, DISABLED | TOGGLE_RESET)
        .unwrap();
    driver.poll_bulk().unwrap();
    assert_eq!(driver.armed, [true, false]);
    assert_eq!(driver.driver.read_word(BULK_IN).unwrap() & DISABLED, 0);
    driver.buffer_write(BULK_OUT_BUFFER, b"short").unwrap();
    driver.driver.write_word(BULK_OUT, (512 - 5) << 11).unwrap();
    driver.poll_bulk().unwrap();
    assert_eq!(driver.armed, [false, true]);
    let mut data = [0; 5];
    driver.buffer_read(BULK_IN_BUFFER, &mut data).unwrap();
    assert_eq!(&data, b"short");
    assert_eq!(driver.in_length, 5);
    assert_eq!(driver.counters[0], 5);
    driver.driver.write_word(BULK_IN, 0).unwrap();
    driver.poll_bulk().unwrap();
    assert_eq!(driver.counters[1], 5);
    assert!(driver.armed[0]);
}

#[test]
fn clear_halt_resets_data0_without_disarming_a_nonhalted_transfer() {
    let mut driver = driver();
    driver.alternate = 1;
    driver.poll_bulk().unwrap();
    let before = driver.driver.read_word(BULK_IN).unwrap() | TOGGLE;
    driver.driver.write_word(BULK_IN, before).unwrap();
    driver
        .apply(ControlAction::Halt {
            input: true,
            halted: false,
        })
        .unwrap();
    let after = driver.driver.read_word(BULK_IN).unwrap();
    assert_ne!(after & ACTIVE, 0);
    assert_ne!(after & TOGGLE_RESET, 0);
    assert_eq!(after & TOGGLE, 0);
    assert_eq!(
        after & !(TOGGLE | TOGGLE_RESET),
        before & !(TOGGLE | TOGGLE_RESET)
    );
}

#[test]
fn unsupported_vendor_requests_and_oversized_control_writes_stall() {
    let mut driver = driver();
    for raw in [
        [0x40, 0x5b, 0, 0, 0, 0, 1, 4],
        [0x40, 0x5e, 2, 0, 0, 0, 0, 0],
        [0xc0, 0x22, 0, 0, 0, 0, 16, 0],
    ] {
        assert!(matches!(
            driver.request(&setup(raw)),
            Err(UsbError::UnsupportedRequest)
        ));
    }
    driver
        .request(&setup([0xc0, 0x5d, 0, 0, 0, 0, 16, 0]))
        .unwrap();
    assert_eq!(&driver.data[..4], b"CST1");
    assert_eq!(u16::from_le_bytes([driver.data[8], driver.data[9]]), 512);
}

#[test]
fn control_write_is_committed_only_after_status_and_continuations_keep_toggle() {
    let mut driver = driver();
    driver.stored[..3].copy_from_slice(b"old");
    driver.stored_length = 3;
    driver.control = ControlStage::Write {
        total: 65,
        received: 0,
        armed: 64,
    };
    driver.buffer_write(OUT_OFFSET, &[0x5a; 64]).unwrap();
    driver.driver.write_word(0, 0).unwrap();
    driver.poll_control().unwrap();
    assert_eq!(&driver.stored[..3], b"old");
    assert_eq!(driver.driver.read_word(0).unwrap() & TOGGLE_RESET, 0);
    driver.buffer_write(OUT_OFFSET, &[0x99]).unwrap();
    driver.driver.write_word(0, 0).unwrap();
    driver.poll_control().unwrap();
    assert_eq!(&driver.stored[..3], b"old");
    driver.driver.write_word(2, 0).unwrap();
    driver.poll_control().unwrap();
    assert_eq!(driver.stored_length, 65);
    assert_eq!(&driver.stored[..64], &[0x5a; 64]);
    assert_eq!(driver.stored[64], 0x99);
}
