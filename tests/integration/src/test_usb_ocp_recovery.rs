// Licensed under the Apache-2.0 license

//! Integration tests for the USB OCP Recovery boot path.
//!
//! These tests build the emulator ROM with the `test-usb-ocp-recovery` feature
//! and drive OCP Secure Firmware Recovery v1.1 commands via the emulated USB
//! host controller.

#[cfg(test)]
mod test {
    use crate::test::{build_test_binaries, start_runtime_hw_model, TestParams, TEST_LOCK};
    use caliptra_mcu_emulator_periph::UsbHostController;
    use caliptra_mcu_hw_model::usb_ctrl::*;
    use caliptra_mcu_hw_model::{DefaultHwModel, McuHwModel};
    use caliptra_mcu_ocp::protocol::device_status::{DeviceStatusValue, ProtocolError};
    use caliptra_mcu_ocp::protocol::prot_cap::{self, RecoveryProtocolCapabilities};
    use caliptra_mcu_ocp::protocol::recovery_status::DeviceRecoveryStatus;
    use caliptra_mcu_ocp::protocol::RecoveryCommand;
    use caliptra_mcu_romtime::McuBootMilestones;
    use random_port::PortPicker;
    use std::sync::atomic::Ordering;

    /// Timeout for quick USB transactions (enumeration, reads).
    const TIMEOUT: usize = 1_000_000;

    /// Timeout for image load operations.  Between recovery stages Caliptra
    /// must process the previous image, which can take many emulator cycles.
    /// The poll_* retry loops step the emulator while waiting, giving both
    /// the MCU ROM and Caliptra core time to progress.
    const IMAGE_LOAD_TIMEOUT: usize = 6_000_000;

    /// Build all binaries needed for the load-image tests in a single
    /// compilation pass and return both the hw model and the recovery
    /// images (caliptra_fw, soc_manifest, mcu_runtime).
    fn build_and_start_usb_ocp_recovery() -> (DefaultHwModel, Vec<u8>, Vec<u8>, Vec<u8>) {
        let bins = build_test_binaries(&TestParams {
            rom_feature: Some("test-usb-ocp-recovery"),
            ..Default::default()
        });

        let mut hw = start_runtime_hw_model(TestParams {
            rom_feature: Some("test-usb-ocp-recovery"),
            custom_mcu_rom: Some(bins.mcu_rom),
            i3c_port: Some(PortPicker::new().pick().unwrap()),
            flash_boot: true,
            rom_only: true,
            ..Default::default()
        });

        let images = (bins.caliptra_fw, bins.soc_manifest, bins.mcu_runtime);
        start_usb_ocp_recovery_enumerate(&mut hw);
        (hw, images.0, images.1, images.2)
    }

    /// Start the emulator with the USB OCP recovery feature and enumerate USB.
    /// Returns the hw model with USB already enumerated.
    fn start_usb_ocp_recovery() -> DefaultHwModel {
        let mut hw = start_runtime_hw_model(TestParams {
            rom_feature: Some("test-usb-ocp-recovery"),
            i3c_port: Some(PortPicker::new().pick().unwrap()),
            flash_boot: true,
            rom_only: true,
            ..Default::default()
        });
        start_usb_ocp_recovery_enumerate(&mut hw);
        hw
    }

    /// Wait for the firmware to enable USB and complete enumeration.
    fn start_usb_ocp_recovery_enumerate(hw: &mut DefaultHwModel) {
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
        enumerate(hw, &host, TIMEOUT);
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

        expect_recovery_status(&mut hw, &host, DeviceRecoveryStatus::AwaitingImage);

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

        expect_protocol_error(&mut hw, &host, ProtocolError::UnsupportedCommand);

        lock.fetch_add(1, Ordering::Relaxed);
    }

    // ---- Image load helpers ------------------------------------------------

    /// Push a complete image via the indirect (memory-window) interface and
    /// activate.
    ///
    /// Selects CMS 0 with IMO 0, writes image data in 64-byte chunks via
    /// INDIRECT_DATA, then sends RECOVERY_CTRL to activate.
    fn send_image_indirect(hw: &mut DefaultHwModel, host: &UsbHostController, image: &[u8]) {
        ocp_select_indirect_cms(hw, host, 0, 0, IMAGE_LOAD_TIMEOUT);
        for chunk in image.chunks(64) {
            ocp_write_indirect_data(hw, host, chunk, IMAGE_LOAD_TIMEOUT);
        }
        ocp_activate_recovery(hw, host, 0, IMAGE_LOAD_TIMEOUT);
    }

    /// Stream a complete image via the FIFO interface and activate.
    ///
    /// Selects CMS 1 and declares the image size in 4-byte units via
    /// INDIRECT_FIFO_CTRL, writes image data in 64-byte chunks via
    /// INDIRECT_FIFO_DATA, then sends RECOVERY_CTRL to activate.
    fn send_image_fifo(hw: &mut DefaultHwModel, host: &UsbHostController, image: &[u8]) {
        assert!(image.len() % 4 == 0, "image must be 4-byte aligned");
        let image_size_4b = (image.len() / 4) as u32;

        ocp_select_fifo_cms(hw, host, 1, image_size_4b, IMAGE_LOAD_TIMEOUT);
        for chunk in image.chunks(64) {
            ocp_write_fifo_data(hw, host, chunk, IMAGE_LOAD_TIMEOUT);
        }
        ocp_activate_recovery(hw, host, 1, IMAGE_LOAD_TIMEOUT);
    }

    /// Assert the device is in RecoveryMode and AwaitingImage.
    fn assert_awaiting_image(hw: &mut DefaultHwModel, host: &UsbHostController) {
        let status = ocp_read_data(hw, host, RecoveryCommand::DeviceStatus, 7, TIMEOUT);
        assert_eq!(
            status[0],
            DeviceStatusValue::RecoveryMode as u8,
            "device should be in RecoveryMode"
        );
        expect_recovery_status(hw, host, DeviceRecoveryStatus::AwaitingImage);
    }

    /// Read DEVICE_STATUS and assert the protocol error byte matches.  This
    /// read also clears the protocol error register (clear-on-read).
    fn expect_protocol_error(
        hw: &mut DefaultHwModel,
        host: &UsbHostController,
        expected: ProtocolError,
    ) {
        let status = ocp_read_data(hw, host, RecoveryCommand::DeviceStatus, 7, TIMEOUT);
        assert_eq!(
            status[1], expected as u8,
            "expected protocol error {:?} (0x{:02x}), got 0x{:02x}",
            expected, expected as u8, status[1]
        );
    }

    /// Read RECOVERY_STATUS and assert the lower nibble matches the expected
    /// status value.
    fn expect_recovery_status(
        hw: &mut DefaultHwModel,
        host: &UsbHostController,
        expected: DeviceRecoveryStatus,
    ) {
        let rec_status = ocp_read_data(hw, host, RecoveryCommand::RecoveryStatus, 2, TIMEOUT);
        assert_eq!(
            rec_status[0] & 0x0F,
            expected as u8,
            "expected recovery status {:?} (0x{:02x}), got 0x{:02x}",
            expected,
            expected as u8,
            rec_status[0] & 0x0F
        );
    }

    // We cannot use finish_runtime_hw_model() / step_until_exit_success() here
    // because the emulator's EmuCtrl exit handler calls std::process::exit(),
    // which would kill the entire test runner process instead of just this test.
    fn wait_for_boot_complete(hw: &mut DefaultHwModel) {
        hw.step_until(|m| {
            m.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
        });
    }

    /// Send all three recovery stages (caliptra_fw, soc_manifest, mcu_runtime)
    /// via the indirect (memory-window) interface and wait for boot completion.
    fn complete_recovery_indirect(
        hw: &mut DefaultHwModel,
        host: &UsbHostController,
        caliptra_fw: &[u8],
        soc_manifest: &[u8],
        mcu_runtime: &[u8],
    ) {
        for image in [caliptra_fw, soc_manifest, mcu_runtime] {
            send_image_indirect(hw, host, image);
        }
        wait_for_boot_complete(hw);
    }

    /// Send all three recovery stages via the FIFO interface and wait for boot
    /// completion.  Each image must be 4-byte aligned.
    fn complete_recovery_fifo(
        hw: &mut DefaultHwModel,
        host: &UsbHostController,
        caliptra_fw: &[u8],
        soc_manifest: &[u8],
        mcu_runtime: &[u8],
    ) {
        for image in [caliptra_fw, soc_manifest, mcu_runtime] {
            send_image_fifo(hw, host, image);
        }
        wait_for_boot_complete(hw);
    }

    // ---- Image load tests --------------------------------------------------

    /// Pad a byte vector to 4-byte alignment.
    fn pad_to_4b(data: &mut Vec<u8>) {
        while data.len() % 4 != 0 {
            data.push(0);
        }
    }

    /// Load recovery images via the indirect (memory-window) interface and
    /// verify the ROM completes the recovery boot flow.
    ///
    /// Sends the three recovery images (caliptra_fw, soc_manifest,
    /// mcu_runtime) as separate stages, matching the streaming boot path.
    #[test]
    fn test_usb_ocp_recovery_load_image_indirect() {
        let lock = TEST_LOCK.lock().unwrap();

        let (mut hw, caliptra_fw, soc_manifest, mcu_runtime) = build_and_start_usb_ocp_recovery();
        let host = hw.usb_host_controller.clone();

        assert_awaiting_image(&mut hw, &host);
        complete_recovery_indirect(&mut hw, &host, &caliptra_fw, &soc_manifest, &mcu_runtime);

        lock.fetch_add(1, Ordering::Relaxed);
    }

    /// Load recovery images via the FIFO interface and verify the ROM
    /// completes the recovery boot flow.
    ///
    /// Sends the three recovery images (caliptra_fw, soc_manifest,
    /// mcu_runtime) as separate stages via FIFO streaming.
    #[test]
    fn test_usb_ocp_recovery_load_image_fifo() {
        let lock = TEST_LOCK.lock().unwrap();

        let (mut hw, mut caliptra_fw, mut soc_manifest, mut mcu_runtime) =
            build_and_start_usb_ocp_recovery();

        pad_to_4b(&mut caliptra_fw);
        pad_to_4b(&mut soc_manifest);
        pad_to_4b(&mut mcu_runtime);

        let host = hw.usb_host_controller.clone();

        assert_awaiting_image(&mut hw, &host);
        complete_recovery_fifo(&mut hw, &host, &caliptra_fw, &soc_manifest, &mcu_runtime);

        lock.fetch_add(1, Ordering::Relaxed);
    }
}
