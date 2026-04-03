// Licensed under the Apache-2.0 license

//! Integration tests for MCTP VDM (Vendor Defined Messages) commands.
//!
//! This module tests the VDM responder implementation by sending various
//! VDM commands and verifying the responses match expected values.

#[cfg(test)]
pub mod test {
    use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TestParams, TEST_LOCK};
    use log::{info, LevelFilter};
    use mctp_vdm_common::codec::VdmCodec;
    use mctp_vdm_common::message::device_capabilities::{
        DeviceCapabilitiesRequest, DeviceCapabilitiesResponse,
    };
    use mctp_vdm_common::message::device_id::{DeviceIdRequest, DeviceIdResponse};
    use mctp_vdm_common::message::device_info::{DeviceInfoRequest, DeviceInfoResponse};
    use mctp_vdm_common::message::firmware_version::{
        FirmwareVersionRequest, FirmwareVersionResponse,
    };
    use mctp_vdm_common::protocol::header::VdmCompletionCode;
    use mcu_hw_model::McuHwModel;
    use mcu_mbox_common::config;
    use mcu_testing_common::mctp_vdm_transport::{
        MctpVdmSocket, MctpVdmTransport, VdmClient, VdmTransportError,
    };
    use mcu_testing_common::{wait_for_runtime_start, MCU_RUNNING};
    use random_port::PortPicker;
    use simple_logger::SimpleLogger;
    use std::process::exit;
    use std::sync::atomic::Ordering;

    /// Maximum buffer size for encoding VDM requests.
    const MAX_REQUEST_BUF_SIZE: usize = 1024;

    /// Test runner for VDM command tests.
    pub struct VdmCmdTest {
        client: VdmClient,
    }

    impl VdmCmdTest {
        /// Create a new VDM command test instance.
        pub fn new(socket: MctpVdmSocket) -> Self {
            Self {
                client: VdmClient::new(socket),
            }
        }

        /// Send a request and expect a successful response.
        ///
        /// Encodes the request, sends it, checks for success completion code,
        /// and decodes the response. Returns the decoded response on success.
        fn send_request_expect_success<Req, Resp>(
            &mut self,
            request: &Req,
        ) -> Result<Resp, VdmTransportError>
        where
            Req: VdmCodec,
            Resp: VdmCodec,
        {
            let mut request_buf = [0u8; MAX_REQUEST_BUF_SIZE];
            let size = request
                .encode(&mut request_buf)
                .map_err(|_| VdmTransportError::CodecError)?;

            let response_bytes = self.client.send_raw(&request_buf[..size])?;
            VdmClient::check_success(&response_bytes)?;

            Resp::decode(&response_bytes).map_err(|_| VdmTransportError::CodecError)
        }

        /// Send a request and expect a specific error completion code.
        ///
        /// Encodes the request, sends it, and verifies the response contains
        /// the expected completion code.
        fn send_request_expect_error<Req>(
            &mut self,
            request: &Req,
            expected_code: VdmCompletionCode,
        ) -> Result<(), VdmTransportError>
        where
            Req: VdmCodec,
        {
            let mut request_buf = [0u8; MAX_REQUEST_BUF_SIZE];
            let size = request
                .encode(&mut request_buf)
                .map_err(|_| VdmTransportError::CodecError)?;

            let response_bytes = self.client.send_raw(&request_buf[..size])?;
            let code = VdmClient::parse_completion_code(&response_bytes)?;

            if code != expected_code {
                info!("Expected {:?}, got {:?}", expected_code, code);
                return Err(VdmTransportError::InvalidResponse);
            }
            Ok(())
        }

        /// Helper to log and compare values, returning error on mismatch.
        fn assert_eq<T: PartialEq + core::fmt::Debug>(
            actual: &T,
            expected: &T,
            field_name: &str,
        ) -> Result<(), VdmTransportError> {
            if actual != expected {
                info!(
                    "{} mismatch: expected {:?}, got {:?}",
                    field_name, expected, actual
                );
                return Err(VdmTransportError::InvalidResponse);
            }
            Ok(())
        }

        // ============== Command Tests ==============

        /// Test Get Firmware Version command.
        fn test_get_firmware_version(&mut self) -> Result<(), VdmTransportError> {
            info!("Testing Get Firmware Version command...");

            for index in 0..3u32 {
                let request = FirmwareVersionRequest::new(index);
                let response: FirmwareVersionResponse =
                    self.send_request_expect_success(&request)?;

                let expected = config::TEST_FIRMWARE_VERSIONS[index as usize];
                // Find end of null-terminated string
                let len = response
                    .version
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(response.version.len());
                let received_str = core::str::from_utf8(&response.version[..len])
                    .map_err(|_| VdmTransportError::InvalidResponse)?;

                Self::assert_eq(
                    &received_str,
                    &expected,
                    &format!("Firmware version index {}", index),
                )?;
                info!(
                    "  Index {}: version = '{}' (matches expected)",
                    index, received_str
                );
            }

            // Test invalid index
            let request = FirmwareVersionRequest::new(99);
            self.send_request_expect_error(&request, VdmCompletionCode::InvalidData)?;
            info!("  Invalid index correctly returns InvalidData");

            Ok(())
        }

        /// Test Get Device ID command.
        fn test_get_device_id(&mut self) -> Result<(), VdmTransportError> {
            info!("Testing Get Device ID command...");

            let request = DeviceIdRequest::new();
            let response: DeviceIdResponse = self.send_request_expect_success(&request)?;

            // Copy fields from packed struct to avoid alignment issues
            let vendor_id = response.vendor_id;
            let device_id = response.device_id;
            let subsystem_vendor_id = response.subsystem_vendor_id;
            let subsystem_id = response.subsystem_id;

            let expected = &config::TEST_DEVICE_ID;
            Self::assert_eq(&vendor_id, &expected.vendor_id, "vendor_id")?;
            Self::assert_eq(&device_id, &expected.device_id, "device_id")?;
            Self::assert_eq(
                &subsystem_vendor_id,
                &expected.subsystem_vendor_id,
                "subsystem_vendor_id",
            )?;
            Self::assert_eq(&subsystem_id, &expected.subsystem_id, "subsystem_id")?;

            info!(
                "  Device ID: vendor=0x{:04x}, device=0x{:04x}, subsystem_vendor=0x{:04x}, subsystem=0x{:04x}",
                vendor_id,
                device_id,
                subsystem_vendor_id,
                subsystem_id
            );

            Ok(())
        }

        /// Test Get Device Info command.
        fn test_get_device_info(&mut self) -> Result<(), VdmTransportError> {
            info!("Testing Get Device Info command...");

            // Test index 0 (UID)
            let request = DeviceInfoRequest::new(0);
            let response: DeviceInfoResponse = self.send_request_expect_success(&request)?;

            let expected_uid = &config::TEST_UID;
            let data_size = response.header.data_size as usize;
            let response_uid = &response.data[..data_size];
            Self::assert_eq(&response_uid, &expected_uid.as_slice(), "UID")?;
            info!("  UID: {:?} (matches expected)", response_uid);

            // Test invalid index
            let request = DeviceInfoRequest::new(99);
            self.send_request_expect_error(&request, VdmCompletionCode::InvalidData)?;
            info!("  Invalid index correctly returns InvalidData");

            Ok(())
        }

        /// Test Get Device Capabilities command.
        fn test_get_device_capabilities(&mut self) -> Result<(), VdmTransportError> {
            info!("Testing Get Device Capabilities command...");

            let request = DeviceCapabilitiesRequest::new();
            let response: DeviceCapabilitiesResponse =
                self.send_request_expect_success(&request)?;

            // Convert TestDeviceCapabilities to raw bytes for comparison
            let expected = &config::TEST_DEVICE_CAPABILITIES;
            let expected_bytes: &[u8] = zerocopy::IntoBytes::as_bytes(expected);
            Self::assert_eq(
                &response.caps.as_slice(),
                &expected_bytes,
                "Device capabilities",
            )?;
            info!("  Capabilities: {:?} (matches expected)", response.caps);

            Ok(())
        }

        /// Test unsupported command.
        fn test_unsupported_command(&mut self) -> Result<(), VdmTransportError> {
            info!("Testing unsupported command handling...");

            // Send a command with an invalid/unsupported command code
            let response_bytes = self.client.send_command(0xFF)?;
            let code = VdmClient::parse_completion_code(&response_bytes)?;
            if code != VdmCompletionCode::UnsupportedCommand {
                info!(
                    "Expected UnsupportedCommand for invalid command, got {:?}",
                    code
                );
                return Err(VdmTransportError::InvalidResponse);
            }
            info!("  Unsupported command correctly returns UnsupportedCommand");

            Ok(())
        }

        /// Run all VDM command tests.
        pub fn run_all_tests(&mut self) -> Result<(), VdmTransportError> {
            self.test_get_firmware_version()?;
            self.test_get_device_id()?;
            self.test_get_device_info()?;
            self.test_get_device_capabilities()?;
            self.test_unsupported_command()?;
            Ok(())
        }

        /// Spawn test thread and run tests.
        pub fn run(socket: MctpVdmSocket, debug_level: LevelFilter) {
            std::thread::spawn(move || {
                wait_for_runtime_start();
                if !MCU_RUNNING.load(Ordering::Relaxed) {
                    exit(-1);
                }

                // Initialize logger
                let _ = SimpleLogger::new().with_level(debug_level).init();

                info!("Running MCTP VDM Command Tests");
                let mut test = VdmCmdTest::new(socket);

                if let Err(e) = test.run_all_tests() {
                    info!("VDM test failed: {:?}", e);
                    exit(-1);
                } else {
                    info!("All VDM tests passed!");
                    MCU_RUNNING.store(false, Ordering::Relaxed);
                    exit(0);
                }
            });
        }
    }

    /// Start VDM command test with the given feature.
    pub fn start_vdm_test(feature: &str, debug_level: LevelFilter) {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let feature = feature.replace("_", "-");
        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some(&feature),
            i3c_port: Some(PortPicker::new().random(true).pick().unwrap()),
            ..Default::default()
        });

        hw.start_i3c_controller();

        let vdm_transport =
            MctpVdmTransport::new(hw.i3c_port().unwrap(), hw.i3c_address().unwrap().into());
        let vdm_socket = vdm_transport.create_socket().unwrap();
        VdmCmdTest::run(vdm_socket, debug_level);

        let test = finish_runtime_hw_model(&mut hw);

        assert_eq!(0, test);
        MCU_RUNNING.store(false, Ordering::Relaxed);

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_mctp_vdm_cmds() {
        start_vdm_test("test-mctp-vdm-cmds", LevelFilter::Info);
    }
}
