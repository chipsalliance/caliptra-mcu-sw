// Licensed under the Apache-2.0 license

extern crate std;

use super::*;
use std::boxed::Box;

fn params() -> UsbParams {
    // Generated blocks contain only MMIO words, padding and PhantomData.
    // Pure descriptor/validation tests never depend on hardware side effects.
    let registers = Box::leak(Box::new(unsafe { core::mem::zeroed() }));
    let memory = Box::leak(Box::new(unsafe { core::mem::zeroed() }));
    UsbParams {
        registers: unsafe { StaticRef::new(registers) },
        packet_memory: unsafe { StaticRef::new(memory) },
        vendor_id: 0x1234,
        product_id: 0x5678,
        device_revision: 0x0210,
        self_powered: true,
        max_power_2ma: 5,
        remote_wakeup: false,
        force_full_speed: false,
        enable_hub: false,
        enable_logs: false,
        poll_limit: 100,
    }
}

fn setup(raw: [u8; 8]) -> SetupPacket {
    zerocopy::transmute!(raw)
}

#[test]
fn hub_is_selected_disconnected_then_connected_without_forcing_vbus_or_lpm() {
    let mut params = params();
    params.enable_hub = true;
    let registers = params.registers;
    let driver = LpcipUsbDriver::new(params);
    registers.hub_descriptor_high[1].set(0x8000_0000);
    registers.hub_descriptor_high[2].set(250);
    registers.hub_descriptor_high[49].set(0x8000_0000);
    registers.hub_descriptor_high[50].set(250);
    driver.configure_hub(false).unwrap();
    assert!(registers.hub_control.is_set(Control::Enable));
    assert!(!registers.hub_control.is_set(Control::Dcon));
    assert!(!registers.hub_control.is_set(Control::ForceVbus));
    assert!(!registers.hub_control.is_set(Control::LpmSup));
    for (attributes, power) in [(1, 2), (49, 50)] {
        assert_eq!(registers.hub_descriptor_high[attributes].get() >> 24, 0xc0);
        assert_eq!(registers.hub_descriptor_high[power].get() & 0xff, 5);
    }
    let before = registers.hub_descriptor_high[1].get();
    driver.configure_hub(true).unwrap();
    assert!(registers.hub_control.is_set(Control::Dcon));
    assert_eq!(registers.hub_descriptor_high[1].get(), before);
}

#[test]
fn direct_device_initialization_does_not_change_hub_policy() {
    let params = params();
    let registers = params.registers;
    registers.hub_control.set(0x1234_5678);
    let mut driver = LpcipUsbDriver::new(params);
    assert_eq!(driver.initialize(), Err(UsbError::UnsupportedPhyInterface));
    assert_eq!(registers.hub_control.get(), 0x1234_5678);
}

fn bytes(params: &UsbParams, raw: [u8; 8]) -> ([u8; 64], usize) {
    let response = request(params, &setup(raw), 7, 1).unwrap();
    (response.data, response.length)
}

#[test]
fn verbose_logs_are_opt_in_and_do_not_change_initialization_errors() {
    use std::string::String;
    use std::sync::{Arc, Mutex};

    struct Capture(Arc<Mutex<String>>);
    impl core::fmt::Write for Capture {
        fn write_str(&mut self, text: &str) -> core::fmt::Result {
            self.0.lock().unwrap().push_str(text);
            Ok(())
        }
    }

    // Other driver tests leave enable_logs false, so only this test uses
    // romtime's global writer.
    let output = Arc::new(Mutex::new(String::new()));
    caliptra_mcu_romtime::set_printer(Box::leak(Box::new(Capture(output.clone()))));
    for enabled in [false, true] {
        output.lock().unwrap().clear();
        let mut params = params();
        params.enable_hub = true;
        params.enable_logs = enabled;
        let mut driver = LpcipUsbDriver::new(params);
        assert_eq!(driver.initialize(), Err(UsbError::UnsupportedPhyInterface));
        let output = output.lock().unwrap();
        if enabled {
            assert!(output.contains("[usb] Initializing Device 0: hub=true"));
            assert!(output.contains("[usb] Hub enabled, connected=false, HUB_CONTROL="));
        } else {
            assert!(output.is_empty(), "{output}");
        }
    }
}

#[test]
fn identity_is_supplied_by_the_caller_not_the_phy() {
    let params = params();
    let (data, length) = bytes(&params, [0x80, 6, 0, 1, 0, 0, 255, 0]);
    assert_eq!(length, 18);
    assert_eq!(&data[8..14], &[0x34, 0x12, 0x78, 0x56, 0x10, 0x02]);
    assert_eq!(&data[14..18], &[0, 0, 0, 1]);
}

#[test]
fn configuration_reports_parameterized_power_and_hardware_transfer_limits() {
    let mut params = params();
    for (self_powered, expected) in [(true, 0xc0), (false, 0x80)] {
        params.self_powered = self_powered;
        let (data, length) = bytes(&params, [0x80, 6, 0, 2, 0, 0, 255, 0]);
        assert_eq!(length, 28);
        assert_eq!(&data[..9], &[9, 2, 28, 0, 1, 1, 0, expected, 5]);
        assert_eq!(&data[9..18], &[9, 4, 0, 0, 0, 0xef, 8, 1, 1]);
        assert_eq!(&data[18..28], &[10, 0x24, 1, 0, 64, 0, 64, 0, 1, 1]);
        let (status, length) = bytes(&params, [0x80, 0, 0, 0, 0, 0, 2, 0]);
        assert_eq!(length, 2);
        assert_eq!(&status[..2], &[u8::from(self_powered), 0]);
    }
}

#[test]
fn descriptor_lengths_are_truncated_to_wlength() {
    let params = params();
    for length in [0u8, 1, 8, 18, 19, 64, 255] {
        let (_, actual) = bytes(&params, [0x80, 6, 0, 1, 0, 0, length, 0]);
        assert_eq!(actual, usize::from(length).min(18));
    }
    assert!(matches!(
        Reply::read(&[0; PACKET_SIZE + 1], 255),
        Err(UsbError::InvalidDescriptor)
    ));
}

#[test]
fn strings_qualifier_and_other_speed_have_correct_shapes() {
    let mut params = params();
    let (data, length) = bytes(&params, [0x80, 6, 0, 3, 0, 0, 255, 0]);
    assert_eq!(&data[..length], &[4, 3, 9, 4]);
    let (data, length) = bytes(&params, [0x80, 6, 1, 3, 9, 4, 255, 0]);
    assert_eq!(length, 58);
    assert_eq!(&data[..6], &[58, 3, b'O', 0, b'C', 0]);
    let (data, length) = bytes(&params, [0x80, 6, 0, 6, 0, 0, 255, 0]);
    assert_eq!(&data[..length], &[10, 6, 0, 2, 0, 0, 0, 64, 1, 0]);
    let (data, length) = bytes(&params, [0x80, 6, 0, 7, 0, 0, 255, 0]);
    assert_eq!(length, 28);
    assert_eq!(data[1], 7);
    params.force_full_speed = true;
    for kind in [6, 7] {
        assert!(matches!(
            request(&params, &setup([0x80, 6, 0, kind, 0, 0, 10, 0]), 7, 1),
            Err(UsbError::UnsupportedRequest)
        ));
    }
}

#[test]
fn malformed_standard_requests_and_unimplemented_features_are_rejected() {
    let params = params();
    for raw in [
        [0x81, 6, 0, 1, 0, 0, 18, 0],
        [0x80, 6, 1, 1, 0, 0, 18, 0],
        [0x80, 6, 0, 1, 1, 0, 18, 0],
        [0x80, 6, 2, 3, 9, 4, 64, 0],
        [0x80, 6, 1, 3, 0, 0, 64, 0],
        [0, 5, 128, 0, 0, 0, 0, 0],
        [0, 5, 7, 1, 0, 0, 0, 0],
        [0, 5, 7, 0, 0, 0, 1, 0],
        [0, 9, 2, 0, 0, 0, 0, 0],
        [0x80, 8, 0, 0, 0, 0, 2, 0],
        [0x81, 10, 0, 0, 1, 0, 1, 0],
        [1, 11, 1, 0, 0, 0, 0, 0],
        [0, 3, 1, 0, 0, 0, 0, 0],
        [0x82, 0, 0, 0, 1, 0, 2, 0],
        [0xa1, 0, 0x22, 0, 0, 0, 64, 0],
        [0xc0, 0x99, 0, 0, 0, 0, 1, 0],
    ] {
        assert!(
            matches!(
                request(&params, &setup(raw), 7, 1),
                Err(UsbError::UnsupportedRequest)
            ),
            "{raw:?}"
        );
    }
}

#[test]
fn address_configuration_and_interface_actions_are_deferred_to_status_ack() {
    let params = params();
    let address = setup([0, 5, 7, 0, 0, 0, 0, 0]);
    assert!(matches!(
        request(&params, &address, 0, 0).unwrap().action,
        Some(Action::Address(7))
    ));
    assert!(request(&params, &address, 7, 1).is_err());
    let configure = setup([0, 9, 1, 0, 0, 0, 0, 0]);
    assert!(request(&params, &configure, 0, 0).is_err());
    assert!(matches!(
        request(&params, &configure, 7, 0).unwrap().action,
        Some(Action::Configuration(1))
    ));
    let interface = setup([0x81, 10, 0, 0, 0, 0, 1, 0]);
    assert!(request(&params, &interface, 7, 0).is_err());
    assert_eq!(request(&params, &interface, 7, 1).unwrap().data[0], 0);
}

#[test]
fn packet_offsets_and_length_encoding_are_bounded_and_aligned() {
    assert_eq!(encode_descriptor(SETUP_OFFSET, 0), Ok(4));
    assert_eq!(encode_descriptor(OUT_OFFSET, 64), Ok(5 | (64 << 11)));
    assert_eq!(
        encode_descriptor(0x10000 + IN_OFFSET, 18),
        Ok(0x406 | (18 << 11))
    );
    for (offset, length) in [(1, 0), (0x20000, 0), (IN_OFFSET, 65)] {
        assert_eq!(
            encode_descriptor(offset, length),
            Err(UsbError::InvalidPacketMemory)
        );
    }
}

#[test]
fn zlp_only_terminates_short_full_packet_transfers() {
    assert!(needs_zlp(0, 64));
    assert!(needs_zlp(64, 65));
    assert!(!needs_zlp(64, 64));
    assert!(!needs_zlp(18, 64));
    assert!(!needs_zlp(0, 0));
}

#[test]
fn unsupported_power_features_and_zero_wait_budgets_are_explicit_errors() {
    let mut driver = LpcipUsbDriver::new(params());
    driver.params.remote_wakeup = true;
    assert_eq!(driver.validate(), Err(UsbError::UnsupportedRemoteWakeup));
    driver.params.remote_wakeup = false;
    driver.params.max_power_2ma = 251;
    assert_eq!(driver.validate(), Err(UsbError::InvalidParameters));
    driver.params.max_power_2ma = 0;
    driver.params.poll_limit = 0;
    assert_eq!(driver.validate(), Err(UsbError::InvalidParameters));
    assert_eq!(driver.poll(), Err(UsbError::NotInitialized));
}
