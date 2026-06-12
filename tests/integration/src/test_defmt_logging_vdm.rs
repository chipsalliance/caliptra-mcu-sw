// Licensed under the Apache-2.0 license

//! E2E test for the host library's defmt round-trip over MCTP VDM.
//!
//! Boots the device with `test-defmt-logging-vdm` (which loads the userspace
//! defmt logger and emits a fixed set of frames at startup), then runs
//! `caliptra-mcu-core-mctp-vdm-client::Validator` configured with a
//! `DefmtRoundTripCheck`. The validator drains the device debug log via
//! `VdmClient::drain_debug_log` and decodes the accumulated frames against
//! the user-app ELF using `decode_defmt_stream`.
//!
//! This exercises the full host-library E2E path that the `mctp-vdm-client
//! get-log --elf` CLI ships:
//!   device defmt::* → flash log → VDM GetDebugLog → drain_debug_log →
//!   decode_defmt_stream(elf) → human-readable messages
//!
//! Runs on both the emulator and FPGA.

#[cfg(test)]
mod test {
    use crate::test::{
        compile_runtime, finish_runtime_hw_model, start_runtime_hw_model, TestParams, TEST_LOCK,
    };
    use caliptra_mctp_vdm_client::{
        DefmtRoundTripCheck, DynamicI3cAddress, TestConfig, Validator,
    };
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_testing_common::wait_for_runtime_start;
    use random_port::PortPicker;
    use std::process::exit;
    use std::sync::atomic::Ordering;

    const FEATURE: &str = "test-defmt-logging-vdm";

    /// Decoded messages the user app emits at startup (see `defmt_test.rs`).
    /// Kept in sync with `test_defmt_logging_mailbox::EXPECTED_MESSAGES`.
    const EXPECTED_MESSAGES: &[&str] = &[
        "defmt userspace logging round-trip 12648430",
        "defmt second frame value=48879",
        "defmt third frame label=caliptra",
        "defmt trace frame byte=42",
        "defmt debug frame flag=true",
        "defmt signed frame delta=-12345",
        "defmt small signed frame s=-7",
        "defmt hex frame addr=deadbeef",
        "defmt char frame c=C",
        "defmt multi frame a=1 b=513",
        "defmt slice frame data=[222, 173, 190, 239]",
        // The oversized frame (320-byte slice) is dropped by the logger, so the
        // only drop seen here is that one frame.
        "defmt dropped count=1",
    ];

    /// Substring that must NOT appear in any decoded message. Asserts the
    /// oversized frame was dropped by the logger without desyncing the rest.
    const DROPPED_FRAME_MARKER: &str = "oversized";

    /// Read the user-app ELF that the device booted with. The `.defmt` section
    /// holds the interned format strings the decoder needs.
    ///
    /// Tries the firmware bundle first (works on FPGA where the host has no
    /// access to the build tree), then falls back to the build's on-disk path
    /// (typical emulator runs).
    fn user_app_elf() -> Vec<u8> {
        if let Ok(binaries) = caliptra_mcu_builder::FirmwareBinaries::from_env() {
            if let Some(bytes) = binaries.test_user_app_elf(FEATURE) {
                return bytes.to_vec();
            }
        }

        let path = caliptra_mcu_builder::target_dir()
            .join(caliptra_mcu_builder::TARGET)
            .join("devel")
            .join("user-app");
        if !path.exists() {
            let _ = compile_runtime(Some(FEATURE), false);
        }
        std::fs::read(&path)
            .unwrap_or_else(|e| panic!("failed to read user-app ELF {}: {}", path.display(), e))
    }

    /// Run the validator in-process against the device. Mirrors the pattern
    /// in `test_mctp_vdm_validator::run_validator_in_process` but adds the
    /// `DefmtRoundTripCheck` so the run also exercises the host library's
    /// defmt drain + decode path.
    fn run_validator_in_process(i3c_port: u16, i3c_address: DynamicI3cAddress) {
        let elf = user_app_elf();
        caliptra_mcu_testing_common::spawn_with_emulator_state(move || {
            wait_for_runtime_start();
            if !caliptra_mcu_testing_common::is_emulator_running() {
                exit(-1);
            }

            let config = TestConfig {
                network: caliptra_mctp_vdm_client::NetworkConfig {
                    default_server_address: format!("127.0.0.1:{}", i3c_port),
                    target_i3c_address: i3c_address.into(),
                },
                ..TestConfig::default()
            };
            let defmt_check = DefmtRoundTripCheck::new(
                elf,
                EXPECTED_MESSAGES.iter().map(|s| s.to_string()).collect(),
            )
            .with_forbidden_substring(DROPPED_FRAME_MARKER);

            let validator = Validator::new(&config)
                .expect("Failed to create validator")
                .set_verbose(true)
                .with_defmt_round_trip(defmt_check);

            match validator.start() {
                Ok(results) => {
                    let all_passed = results.iter().all(|r| r.passed);
                    if all_passed {
                        println!("✓ Caliptra MCTP VDM validator (with defmt round-trip) PASSED");
                        caliptra_mcu_testing_common::stop_emulator();
                    } else {
                        println!("✗ Caliptra MCTP VDM validator FAILED");
                        for r in &results {
                            if !r.passed {
                                println!("  FAIL: {} — {:?}", r.test_name, r.error_message);
                            }
                        }
                        exit(-1);
                    }
                }
                Err(e) => {
                    println!("✗ Caliptra MCTP VDM validator error: {:#}", e);
                    exit(-1);
                }
            }
        });
    }

    #[test]
    fn test_defmt_logging_vdm() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        let i3c_port = PortPicker::new().random(true).pick().unwrap();

        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some(FEATURE),
            i3c_port: Some(i3c_port),
            ..Default::default()
        });

        hw.start_i3c_controller();

        // FPGA-only setup: bring up the imaginary flash controller (the
        // device-side userlog drain task writes through mcu_mbox0 to it) and
        // wait for the VDM responder before the test thread races subscribe.
        // The log starts empty; the runtime fills it from defmt::* call sites.
        #[cfg(feature = "fpga_realtime")]
        {
            use caliptra_mcu_config_emulator::flash::LOGGING_PARTITION;
            let seeded = caliptra_mcu_testing_common::logging_seed::splice_logging_partition_into_flash_image(
                None,
                &[],
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
            std::thread::sleep(std::time::Duration::from_millis(200));
        }

        let i3c_address = hw.i3c_address().unwrap();
        run_validator_in_process(i3c_port, i3c_address.into());

        let test = finish_runtime_hw_model(&mut hw);
        assert_eq!(0, test);

        caliptra_mcu_testing_common::stop_emulator();

        lock.fetch_add(1, Ordering::Relaxed);
    }
}
