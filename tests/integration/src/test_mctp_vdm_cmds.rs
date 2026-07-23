// Licensed under the Apache-2.0 license

//! Integration tests for MCTP VDM (Vendor Defined Messages) commands.
//!
//! This module tests the VDM responder implementation by sending various
//! VDM commands and verifying the responses match expected values.

#[cfg(test)]
pub mod test {
    use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TestParams, TEST_LOCK};
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_mbox_common::config;
    use caliptra_mcu_mctp_vdm_common::codec::VdmCodec;
    use caliptra_mcu_mctp_vdm_common::message::clear_debug_log::{
        ClearDebugLogRequest, ClearDebugLogResponse,
    };
    use caliptra_mcu_mctp_vdm_common::message::device_capabilities::{
        DeviceCapabilitiesRequest, DeviceCapabilitiesResponse,
    };
    use caliptra_mcu_mctp_vdm_common::message::firmware_version::{
        FirmwareVersionRequest, FirmwareVersionResponse,
    };
    use caliptra_mcu_mctp_vdm_common::message::get_debug_log::{
        GetDebugLogRequest, GetDebugLogResponse,
    };
    use caliptra_mcu_mctp_vdm_common::protocol::header::VdmCompletionCode;
    use caliptra_mcu_testing_common::mctp_vdm_transport::{
        MctpVdmSocket, MctpVdmTransport, VdmClient, VdmTransportError,
    };
    use caliptra_mcu_testing_common::wait_for_runtime_start;
    use log::{info, LevelFilter};
    use random_port::PortPicker;
    use simple_logger::SimpleLogger;
    use std::process::exit;

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
            self.send_request_expect_error(&request, VdmCompletionCode::InvalidParameter)?;
            info!("  Invalid index correctly returns InvalidParameter");

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
            if code != VdmCompletionCode::UnsupportedOperation {
                info!(
                    "Expected UnsupportedOperation for invalid command, got {:?}",
                    code
                );
                return Err(VdmTransportError::InvalidResponse);
            }
            info!("  Unsupported command correctly returns UnsupportedOperation");

            Ok(())
        }

        fn test_get_debug_log_drain(&mut self) -> Result<(), VdmTransportError> {
            info!("Testing GetDebugLog drain (multi-call)...");

            let expected: Vec<u8> = config::TEST_DEBUG_LOG_ENTRIES
                .iter()
                .flat_map(|e| e.iter().copied())
                .collect();

            let mut accumulated: Vec<u8> = Vec::with_capacity(expected.len());
            let mut iterations = 0;
            let mut saw_more_data = false;
            loop {
                iterations += 1;
                if iterations > 10 {
                    info!("GetDebugLog did not converge within 10 iterations");
                    return Err(VdmTransportError::InvalidResponse);
                }

                let request = GetDebugLogRequest::new();
                let response: GetDebugLogResponse = self.send_request_expect_success(&request)?;
                let chunk = response.data();
                accumulated.extend_from_slice(chunk);
                info!(
                    "  iter {}: bytes={} more_data={}",
                    iterations,
                    chunk.len(),
                    response.more_data()
                );

                if response.more_data() {
                    saw_more_data = true;
                } else {
                    break;
                }
            }

            // Ensure at least one chunked iteration was seen — otherwise the
            // fixture is too small to exercise `more_data`.
            if !saw_more_data {
                info!(
                    "Expected at least one GetDebugLog with more_data=1 \
                     (fixture size {} ≥ MCTP VDM cap)",
                    expected.len()
                );
                return Err(VdmTransportError::InvalidResponse);
            }

            Self::assert_eq(&accumulated.len(), &expected.len(), "drained log size")?;
            if accumulated != expected {
                info!(
                    "  drained log content mismatch: first diff at byte {}",
                    accumulated
                        .iter()
                        .zip(expected.iter())
                        .position(|(a, b)| a != b)
                        .unwrap_or(0),
                );
                return Err(VdmTransportError::InvalidResponse);
            }
            info!(
                "  drained {} bytes matching seeded fixture (took {} iterations)",
                accumulated.len(),
                iterations
            );
            Ok(())
        }

        fn test_clear_debug_log(&mut self) -> Result<(), VdmTransportError> {
            info!("Testing ClearDebugLog...");

            let clear_req = ClearDebugLogRequest::new();
            let clear_resp: ClearDebugLogResponse = self.send_request_expect_success(&clear_req)?;
            let cc = clear_resp.completion_code;
            Self::assert_eq(
                &cc,
                &(VdmCompletionCode::Success as u32),
                "ClearDebugLog completion code",
            )?;
            info!("  ClearDebugLog: success");

            // Verify log is empty after clear.
            let get_req = GetDebugLogRequest::new();
            let get_resp: GetDebugLogResponse = self.send_request_expect_success(&get_req)?;
            Self::assert_eq(&get_resp.data_size(), &0usize, "post-clear data size")?;
            Self::assert_eq(&get_resp.more_data(), &false, "post-clear more_data")?;
            info!("  GetDebugLog after ClearDebugLog: empty (expected)");
            Ok(())
        }

        /// Run all VDM command tests.
        pub fn run_all_tests(&mut self) -> Result<(), VdmTransportError> {
            self.test_get_firmware_version()?;
            self.test_get_device_capabilities()?;
            // Log tests must run before any other test that might mutate the
            // mock's debug-log cursor (none today, but order matters once
            // production logging lands).
            self.test_get_debug_log_drain()?;
            self.test_clear_debug_log()?;
            self.test_unsupported_command()?;
            Ok(())
        }

        fn test_production_backend(&mut self) -> Result<(), VdmTransportError> {
            info!("Testing production CaliptraCmdBackend dispatch...");
            let request = FirmwareVersionRequest::new(0);
            self.send_request_expect_error(&request, VdmCompletionCode::UnsupportedOperation)
        }

        /// Spawn test thread and run tests.
        pub fn run(socket: MctpVdmSocket, debug_level: LevelFilter, production_backend: bool) {
            caliptra_mcu_testing_common::spawn_with_emulator_state(move || {
                wait_for_runtime_start();
                if !caliptra_mcu_testing_common::is_emulator_running() {
                    exit(-1);
                }

                // Initialize logger
                let _ = SimpleLogger::new().with_level(debug_level).init();

                info!("Running MCTP VDM Command Tests");
                let mut test = VdmCmdTest::new(socket);

                let result = if production_backend {
                    test.test_production_backend()
                } else {
                    test.run_all_tests()
                };
                if let Err(e) = result {
                    info!("VDM test failed: {:?}", e);
                    exit(-1);
                }

                info!("All VDM tests passed!");
                caliptra_mcu_testing_common::stop_emulator();
                exit(0);
            });
        }
    }

    /// Start VDM command test with the given feature.
    pub fn start_vdm_test(feature: &str, debug_level: LevelFilter, production_backend: bool) {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let feature = feature.replace("_", "-");
        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some(&feature),
            i3c_port: Some(PortPicker::new().random(true).pick().unwrap()),
            seeded_log_entries: Some(config::TEST_DEBUG_LOG_ENTRIES),
            ..Default::default()
        });

        hw.start_i3c_controller();

        // FPGA-only setup:
        //   1. MCU flash I/O goes via mcu_mbox0 to ImaginaryFlashController,
        //      independent of emulator's primary_flash. Seed the file directly.
        //   2. Sync with the user-space VDM responder before sending the first
        //      Private Write, otherwise the request races the responder's
        //      subscribe and is dropped (MctpUtil sends each request only once).
        #[cfg(feature = "fpga_realtime")]
        {
            use caliptra_mcu_config_emulator::flash::LOGGING_PARTITION;
            let seeded = caliptra_mcu_testing_common::logging_seed::splice_logging_partition_into_flash_image(
                None,
                config::TEST_DEBUG_LOG_ENTRIES,
                LOGGING_PARTITION.offset,
                LOGGING_PARTITION.size,
                256,
            );
            let mci_ptr = hw.base.mmio.mci().unwrap().ptr as u64;
            crate::test_fpga_flash_ctrl::test::run_imaginary_flash_controller_service_with_init(
                mci_ptr,
                Some(seeded),
            );

            hw.step_until_output_contains("Starting MCTP VDM service for integration tests")
                .expect("MCU did not enter MCTP VDM service");
            // Let the executor schedule the responder and subscribe.
            std::thread::sleep(std::time::Duration::from_millis(200));
        }

        let vdm_transport =
            MctpVdmTransport::new(hw.i3c_port().unwrap(), hw.i3c_address().unwrap().into());
        let vdm_socket = vdm_transport.create_socket().unwrap();
        VdmCmdTest::run(vdm_socket, debug_level, production_backend);

        let test = finish_runtime_hw_model(&mut hw);

        assert_eq!(0, test);
        caliptra_mcu_testing_common::stop_emulator();

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_mctp_vdm_cmds() {
        start_vdm_test("test-mctp-vdm-cmds", LevelFilter::Info, false);
    }

    #[test]
    fn test_mctp_vdm_production_backend() {
        start_vdm_test("test-mctp-vdm-production", LevelFilter::Info, true);
    }
}
