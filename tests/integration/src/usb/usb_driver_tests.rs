// Licensed under the Apache-2.0 license

use caliptra_emu_bus::Bus;
use caliptra_emu_types::RvSize;
use caliptra_mcu_builder::{rom_build, CaliptraBuildArgs};
use caliptra_mcu_emulator_periph::{LpcipUsbError, LpcipUsbSpeed};
use caliptra_mcu_hw_model::{InitParams, McuHwModel, ModelEmulated};
use std::sync::OnceLock;

const LIMIT: usize = 500_000;

fn model(vbus: bool) -> ModelEmulated {
    static ROM: OnceLock<Vec<u8>> = OnceLock::new();
    let rom = ROM.get_or_init(|| {
        let path = rom_build(&CaliptraBuildArgs {
            features: Some("test-lpcip-usb-enumeration"),
            ..Default::default()
        })
        .unwrap();
        std::fs::read(path).unwrap()
    });
    let mut model = ModelEmulated::new_unbooted(InitParams {
        mcu_rom: rom,
        check_booted_to_runtime: false,
        ..Default::default()
    })
    .unwrap();
    model.lpcip_usb_host_controller.set_vbus(vbus);
    model.boot().unwrap();
    model
}

fn advance(model: &mut ModelEmulated, steps: usize) {
    for _ in 0..steps {
        model.step();
        // Stop before the emulator ROM's exiter terminates the host process.
        if model
            .output()
            .peek()
            .contains("[usb-enumeration-test] configured")
        {
            return;
        }
    }
}

fn connected(model: &mut ModelEmulated) {
    let host = model.lpcip_usb_host_controller.clone();
    for _ in 0..LIMIT {
        model.step();
        assert!(
            !model.output().peek().contains("initialization failed"),
            "{}",
            model.output().peek()
        );
        if host.connected() {
            let phy = host.phy().snapshot();
            assert_eq!(phy.function_control, 0x40);
            assert_eq!(phy.otg_control, 0);
            assert_eq!(phy.completed_accesses, 8);
            assert_eq!(
                model
                    .mcu_bus_for_test()
                    .read(RvSize::Word, 0x2000_0000)
                    .unwrap()
                    & (1 << 9),
                1 << 9
            );
            assert!(
                !model.lpcip_usb_hub_host_controller.connected(),
                "Device 0 initialization must not select hub topology"
            );
            host.bus_reset(LpcipUsbSpeed::High).unwrap();
            advance(model, 2000);
            return;
        }
    }
    panic!(
        "shared ROM driver did not connect: {}",
        model.output().peek()
    );
}

fn input(model: &mut ModelEmulated, address: u8) -> Result<Vec<u8>, LpcipUsbError> {
    for _ in 0..LIMIT {
        match model.lpcip_usb_host_controller.host_in(address, 0) {
            Err(LpcipUsbError::Nak) => model.step(),
            result => return result,
        }
    }
    panic!("EP0 IN timed out: {}", model.output().peek());
}

fn output(model: &mut ModelEmulated, address: u8, data: &[u8]) -> Result<(), LpcipUsbError> {
    for _ in 0..LIMIT {
        match model.lpcip_usb_host_controller.host_out(address, 0, data) {
            Err(LpcipUsbError::Nak) => model.step(),
            result => return result,
        }
    }
    panic!("EP0 OUT timed out: {}", model.output().peek());
}

fn read(model: &mut ModelEmulated, address: u8, setup: [u8; 8]) -> Vec<u8> {
    model
        .lpcip_usb_host_controller
        .host_setup(address, &setup)
        .unwrap();
    let data = input(model, address).unwrap();
    output(model, address, &[]).unwrap();
    advance(model, 1000);
    data
}

fn address(model: &mut ModelEmulated, address: u8) {
    model
        .lpcip_usb_host_controller
        .host_setup(0, &[0, 5, address, 0, 0, 0, 0, 0])
        .unwrap();
    advance(model, 2000);
    assert_eq!(model.lpcip_usb_host_controller.device_address(), 0);
    assert_eq!(
        model.lpcip_usb_host_controller.host_in(address, 0),
        Err(LpcipUsbError::AddressMismatch)
    );
    assert!(input(model, 0).unwrap().is_empty());
    advance(model, 2000);
    // The selected RTL commits on the next SETUP token, not a CSR write.
    assert_eq!(model.lpcip_usb_host_controller.device_address(), 0);
}

#[test]
fn test_lpcip_shared_driver_enumerates_the_intended_descriptor_tree() {
    let mut model = model(true);
    connected(&mut model);
    assert_eq!(
        read(&mut model, 0, [0x80, 6, 0, 1, 0, 0, 8, 0]),
        [18, 1, 0, 2, 0, 0, 0, 64]
    );
    address(&mut model, 7);
    let device = read(&mut model, 7, [0x80, 6, 0, 1, 0, 0, 255, 0]);
    assert_eq!(
        device,
        [18, 1, 0, 2, 0, 0, 0, 64, 0xff, 0xff, 0xff, 0xff, 0, 1, 0, 0, 0, 1]
    );
    assert_eq!(model.lpcip_usb_host_controller.device_address(), 7);
    let header = read(&mut model, 7, [0x80, 6, 0, 2, 0, 0, 9, 0]);
    assert_eq!(header, [9, 2, 28, 0, 1, 1, 0, 0xc0, 0]);
    let tree = read(&mut model, 7, [0x80, 6, 0, 2, 0, 0, 255, 0]);
    assert_eq!(tree.len(), 28);
    assert_eq!(
        &tree[9..],
        &[9, 4, 0, 0, 0, 0xef, 8, 1, 1, 10, 0x24, 1, 0, 64, 0, 64, 0, 1, 1]
    );
    assert_eq!(
        read(&mut model, 7, [0x80, 6, 0, 3, 0, 0, 255, 0]),
        [4, 3, 9, 4]
    );
    let string = read(&mut model, 7, [0x80, 6, 1, 3, 9, 4, 255, 0]);
    assert_eq!(string.len(), 58);
    let decoded: Vec<_> = string[2..]
        .chunks_exact(2)
        .map(|word| u16::from_le_bytes([word[0], word[1]]))
        .collect();
    assert_eq!(
        String::from_utf16(&decoded).unwrap(),
        "OCP Secure Firmware Recovery"
    );
    assert_eq!(
        read(&mut model, 7, [0x80, 6, 0, 6, 0, 0, 255, 0]),
        [10, 6, 0, 2, 0, 0, 0, 64, 1, 0]
    );
    let other = read(&mut model, 7, [0x80, 6, 0, 7, 0, 0, 255, 0]);
    assert_eq!(other[1], 7);
    assert_eq!(&other[2..], &tree[2..]);
    assert_eq!(read(&mut model, 7, [0x80, 8, 0, 0, 0, 0, 1, 0]), [0]);
    assert_eq!(read(&mut model, 7, [0x80, 0, 0, 0, 0, 0, 2, 0]), [1, 0]);
    model
        .lpcip_usb_host_controller
        .host_setup(7, &[0, 9, 1, 0, 0, 0, 0, 0])
        .unwrap();
    advance(&mut model, 2000);
    assert!(!model
        .output()
        .peek()
        .contains("[usb-enumeration-test] configured"));
    assert!(input(&mut model, 7).unwrap().is_empty());
    advance(&mut model, 3000);
    assert!(model
        .output()
        .peek()
        .contains("[usb-enumeration-test] configured"));
}

#[test]
fn test_lpcip_shared_driver_stalls_invalid_requests_and_recovers_on_setup() {
    let mut model = model(true);
    connected(&mut model);
    for setup in [
        [0x80, 6, 1, 1, 0, 0, 18, 0],
        [0x80, 6, 0, 1, 1, 0, 18, 0],
        [0x81, 6, 0, 1, 0, 0, 18, 0],
        [0, 5, 128, 0, 0, 0, 0, 0],
        [0, 3, 1, 0, 0, 0, 0, 0],
    ] {
        model
            .lpcip_usb_host_controller
            .host_setup(0, &setup)
            .unwrap();
        assert_eq!(input(&mut model, 0), Err(LpcipUsbError::Stall));
        assert_eq!(read(&mut model, 0, [0x80, 6, 0, 1, 0, 0, 8, 0]).len(), 8);
    }
    model
        .lpcip_usb_host_controller
        .host_setup(0, &[0x80, 6, 0, 1, 0, 0, 18, 0])
        .unwrap();
    assert_eq!(input(&mut model, 0).unwrap().len(), 18);
    output(&mut model, 0, &[1]).unwrap();
    advance(&mut model, 2000);
    assert_eq!(
        model.lpcip_usb_host_controller.host_in(0, 0),
        Err(LpcipUsbError::Stall)
    );
    assert_eq!(read(&mut model, 0, [0x80, 6, 0, 1, 0, 0, 8, 0]).len(), 8);
}

#[test]
fn test_lpcip_shared_driver_setup_and_reset_cancel_pending_address_changes() {
    let mut model = model(true);
    connected(&mut model);
    model
        .lpcip_usb_host_controller
        .host_setup(0, &[0, 5, 9, 0, 0, 0, 0, 0])
        .unwrap();
    advance(&mut model, 2000);
    read(&mut model, 0, [0x80, 6, 0, 1, 0, 0, 8, 0]);
    assert_eq!(
        model
            .lpcip_usb_host_controller
            .host_setup(9, &[0x80, 6, 0, 1, 0, 0, 8, 0]),
        Err(LpcipUsbError::AddressMismatch)
    );
    address(&mut model, 7);
    read(&mut model, 7, [0x80, 6, 0, 1, 0, 0, 8, 0]);
    model
        .lpcip_usb_host_controller
        .bus_reset(LpcipUsbSpeed::Full)
        .unwrap();
    advance(&mut model, 2000);
    assert_eq!(read(&mut model, 0, [0x80, 6, 0, 1, 0, 0, 8, 0]).len(), 8);
    assert_eq!(model.lpcip_usb_host_controller.device_address(), 0);
}

#[test]
fn test_lpcip_shared_driver_standard_enumeration_coexists_with_hardware_ocp() {
    let mut model = model(true);
    connected(&mut model);
    read(&mut model, 0, [0x80, 6, 0, 1, 0, 0, 8, 0]);
    let caps = read(&mut model, 0, [0xa1, 0, 0x22, 0, 0, 0, 64, 0]);
    assert_eq!(&caps[..8], b"OCP RECV");
    assert_eq!(caps.len(), 15);
    assert_eq!(read(&mut model, 0, [0x80, 6, 0, 2, 0, 0, 9, 0]).len(), 9);
    assert!(model.lpcip_usb_host_controller.connected());
}

#[test]
fn test_lpcip_shared_driver_reports_phy_and_vbus_failures_without_connecting() {
    for (fault, reason) in [
        (0, "PhyAccessTimeout"),
        (1, "PhyIdentityMismatch"),
        (2, "VbusTimeout"),
    ] {
        let mut model = model(fault != 2);
        let host = model.lpcip_usb_host_controller.clone();
        match fault {
            0 => host.phy().set_access_stalled(true),
            1 => host.phy().set_identity_for_test([0x34, 0x12, 0x78, 0x56]),
            _ => {}
        }
        let mut reported = false;
        for _ in 0..LIMIT {
            model.step();
            assert!(!host.connected(), "driver connected despite {reason}");
            if model.output().peek().contains(reason) {
                reported = true;
                break;
            }
        }
        assert!(
            reported,
            "initialization error was not reported: {}",
            model.output().peek()
        );
        assert_eq!(
            model
                .mcu_bus_for_test()
                .read(RvSize::Word, 0x2000_0000)
                .unwrap()
                & (1 << 9),
            1 << 9
        );
    }
}
