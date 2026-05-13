// Licensed under the Apache-2.0 license

//! Integration tests for the USB OCP Recovery boot path.
//!
//! These tests build the emulator ROM with the `test-usb-ocp-recovery` feature
//! and drive OCP Secure Firmware Recovery v1.1 commands via the emulated USB
//! host controller.

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use mcu_hw_model::usb_ctrl::*;
    use mcu_hw_model::McuHwModel;
    use ocp::protocol::device_status::{DeviceStatusValue, ProtocolError};
    use ocp::protocol::prot_cap::{self, RecoveryProtocolCapabilities};
    use ocp::protocol::recovery_status::DeviceRecoveryStatus;
    use ocp::protocol::RecoveryCommand;
    use random_port::PortPicker;
    use std::sync::atomic::Ordering;

    const TIMEOUT: usize = 1_000_000;

    /// Start the emulator with the USB OCP recovery feature and enumerate USB.
    /// Returns the hw model with USB already enumerated.
    fn start_usb_ocp_recovery() -> mcu_hw_model::DefaultHwModel {
        let mut hw = start_runtime_hw_model(TestParams {
            rom_feature: Some("test-usb-ocp-recovery"),
            i3c_port: PortPicker::new().pick().ok(),
            flash_boot: true,
            rom_only: true,
            ..Default::default()
        });

        let host = hw.usb_host_controller.clone();

        // Wait for firmware to enable USB.
        // The ROM does USB init early in the test-usb-ocp-recovery boot path,
        // but the emulated CPU needs to execute through startup assembly and
        // initial setup first.
        // USB init happens inside OcpImageProvider::image_ready(), which is called
        // deep in the cold boot recovery flow. Step until the firmware enables USB.
        for _ in 0..50_000_000 {
            hw.step();
            if host.device_enabled() {
                break;
            }
        }
        assert!(host.device_enabled(), "firmware did not enable USB device");

        // Trigger bus reset so firmware proceeds past its LinkReset wait.
        host.bus_reset();

        // Complete USB enumeration.
        enumerate(&mut hw, &host, TIMEOUT);

        hw
    }

    /// Happy path: Read PROT_CAP and DEVICE_STATUS to verify the OCP state
    /// machine is running and responding to commands.
    #[test]
    fn test_usb_ocp_recovery_prot_cap_and_status() {
        let lock = TEST_LOCK.lock().unwrap();

        let mut hw = start_usb_ocp_recovery();
        let host = hw.usb_host_controller.clone();

        // Read PROT_CAP
        let setup = ocp_read(RecoveryCommand::ProtCap, prot_cap::RESPONSE_LEN as u16);
        poll_setup(&mut hw, &host, &setup, TIMEOUT);
        let prot_cap = poll_in(&mut hw, &host, TIMEOUT);
        poll_out(&mut hw, &host, &[], TIMEOUT);

        // Verify capabilities: identification, device_status, push_c_image_support,
        // recovery_memory_access, and fifo_cms_support should be set.
        assert_eq!(prot_cap.len(), prot_cap::RESPONSE_LEN);
        let caps_byte_low = prot_cap[10];
        let mut expected_caps = RecoveryProtocolCapabilities(0);
        expected_caps.set_identification(true);
        expected_caps.set_device_status(true);
        expected_caps.set_push_c_image_support(true);
        expected_caps.set_recovery_memory_access(true);
        expected_caps.set_fifo_cms_support(true);
        let expected_low = (expected_caps.0 & 0xFF) as u8;
        assert_eq!(
            caps_byte_low, expected_low,
            "PROT_CAP capabilities low byte mismatch"
        );

        // Read DEVICE_STATUS — should show RecoveryMode (set by OcpImageProvider)
        let setup = ocp_read(RecoveryCommand::DeviceStatus, 7);
        poll_setup(&mut hw, &host, &setup, TIMEOUT);
        let status = poll_in(&mut hw, &host, TIMEOUT);
        poll_out(&mut hw, &host, &[], TIMEOUT);

        assert_eq!(
            status[0],
            DeviceStatusValue::RecoveryMode as u8,
            "device should be in RecoveryMode"
        );

        lock.fetch_add(1, Ordering::Relaxed);
    }

    /// Verify that RECOVERY_STATUS shows AwaitingImage after the device enters
    /// recovery mode.
    #[test]
    fn test_usb_ocp_recovery_awaiting_image() {
        let lock = TEST_LOCK.lock().unwrap();

        let mut hw = start_usb_ocp_recovery();
        let host = hw.usb_host_controller.clone();

        // Read RECOVERY_STATUS
        let setup = ocp_read(RecoveryCommand::RecoveryStatus, 2);
        poll_setup(&mut hw, &host, &setup, TIMEOUT);
        let status = poll_in(&mut hw, &host, TIMEOUT);
        poll_out(&mut hw, &host, &[], TIMEOUT);

        assert_eq!(
            status[0] & 0x0F,
            DeviceRecoveryStatus::AwaitingImage as u8,
            "recovery status should be AwaitingImage"
        );

        lock.fetch_add(1, Ordering::Relaxed);
    }

    /// Verify that an unsupported read command (Vendor) returns an empty
    /// response and sets a protocol error (NoopVendorHandler).
    #[test]
    fn test_usb_ocp_recovery_unsupported_command_sets_error() {
        let lock = TEST_LOCK.lock().unwrap();

        let mut hw = start_usb_ocp_recovery();
        let host = hw.usb_host_controller.clone();

        // Vendor read returns empty (0 bytes) since NoopVendorHandler doesn't
        // advertise vendor_command capability. The state machine records
        // UnsupportedCommand in the protocol error field.
        let setup = ocp_read(RecoveryCommand::Vendor, 4);
        poll_setup(&mut hw, &host, &setup, TIMEOUT);
        let resp = poll_in(&mut hw, &host, TIMEOUT);
        assert!(resp.is_empty() || resp.iter().all(|&b| b == 0));
        poll_out(&mut hw, &host, &[], TIMEOUT);

        // Read DEVICE_STATUS to verify protocol error was set.
        let setup = ocp_read(RecoveryCommand::DeviceStatus, 7);
        poll_setup(&mut hw, &host, &setup, TIMEOUT);
        let status = poll_in(&mut hw, &host, TIMEOUT);
        poll_out(&mut hw, &host, &[], TIMEOUT);

        // Byte 1 is the protocol error field; UnsupportedCommand = 0x04.
        assert_eq!(
            status[1],
            ProtocolError::UnsupportedCommand as u8,
            "protocol error should be UnsupportedCommand"
        );

        lock.fetch_add(1, Ordering::Relaxed);
    }
}
