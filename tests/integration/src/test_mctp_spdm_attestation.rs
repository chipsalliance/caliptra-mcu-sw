// Licensed under the Apache-2.0 license

//! This module executes SPDM attestation tests over MCTP transport

#[cfg(test)]
pub(crate) mod test {
    use crate::test::{
        finish_runtime_hw_model, run_imaginary_flash_controller_service,
        start_attestation_standalone_runtime, start_runtime_hw_model, TestParams, TEST_LOCK,
    };
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_pldm_fw_pkg::FirmwareManifest;
    use caliptra_mcu_pldm_ua::daemon::{Options, PldmDaemon};
    use caliptra_mcu_pldm_ua::transport::{EndpointId, PldmSocket, PldmTransport};
    use caliptra_mcu_pldm_ua::{discovery_sm, update_sm};
    use caliptra_mcu_testing_common::i3c::DynamicI3cAddress;
    use caliptra_mcu_testing_common::i3c_socket::BufferedStream;
    use caliptra_mcu_testing_common::mctp_transport::MctpTransport as PldmMctpTransport;
    use caliptra_mcu_testing_common::spdm_responder_validator::mctp::MctpTransport;
    use caliptra_mcu_testing_common::spdm_responder_validator::{
        execute_spdm_attestation_with_port, SpdmValidatorRunner, SERVER_LISTENING,
    };
    use caliptra_mcu_testing_common::wait_for_runtime_start;
    use random_port::PortPicker;
    use std::io::Write;
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::process::exit;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc};
    use std::thread;
    use std::time::{Duration, Instant};

    const ATTESTATION_EVIDENCE_READY: &str = "ATTESTATION_EVIDENCE_READY";
    const MCI_BASE_AXI_ADDRESS: u64 = 0xA800_0000;

    /// Emitted by the MCU ROM when it re-enters after the firmware device
    /// self-activates the staged image. Proves the hitless update was applied
    /// rather than merely accepted.
    const MCU_HITLESS_UPDATE_BANNER: &str = "Starting firmware hitless update flow";

    /// Number of PLDM payload bytes actually transferred during the hitless
    /// update. Matches the firmware-update "fast" tests.
    const PLDM_FAST_TRANSFER_BYTES: usize = 1024;

    #[ignore]
    #[test]
    fn test_mctp_spdm_attestation() {
        run_test("test-mctp-spdm-attestation", "MCTP-SPDM-ATTESTATION");
    }

    #[ignore]
    #[test]
    fn test_mctp_spdm_attestation_tcb() {
        run_test(
            "test-mctp-spdm-attestation-tcb",
            "MCTP-SPDM-ATTESTATION-TCB",
        );
    }

    #[ignore]
    #[test]
    fn test_mctp_spdm_attestation_mixed() {
        run_test(
            "test-mctp-spdm-attestation-mixed",
            "MCTP-SPDM-ATTESTATION-MIXED",
        );
    }

    #[ignore]
    #[test]
    fn test_mctp_spdm_attestation_hitless() {
        run_hitless_test(
            "test-mctp-spdm-attestation-hitless",
            "MCTP-SPDM-ATTESTATION-HITLESS",
        );
    }

    #[ignore]
    #[test]
    fn test_mctp_spdm_attestation_hitless_tcb() {
        run_hitless_test(
            "test-mctp-spdm-attestation-hitless-tcb",
            "MCTP-SPDM-ATTESTATION-HITLESS-TCB",
        );
    }

    #[ignore]
    #[test]
    fn test_mctp_spdm_attestation_hitless_mixed() {
        run_hitless_test(
            "test-mctp-spdm-attestation-hitless-mixed",
            "MCTP-SPDM-ATTESTATION-HITLESS-MIXED",
        );
    }

    fn run_test(feature: &'static str, test_name: &'static str) {
        if std::env::var("SPDM_VALIDATOR_DIR").is_err() {
            println!("SPDM_VALIDATOR_DIR environment variable is not set. Skipping test");
            return;
        }
        remove_spdm_attestation_artifacts();
        std::env::set_var(
            "CPTRA_EMULATOR_SS_MCI_OFFSET",
            format!("0x{:016x}", MCI_BASE_AXI_ADDRESS),
        );

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some(feature),
            seed_primary_flash_image: true,
            i3c_port: Some(PortPicker::new().random(true).pick().unwrap()),
            use_strap_secrets: true,
            ..Default::default()
        });

        hw.start_i3c_controller();

        run_imaginary_flash_controller_service(&mut hw);
        hw.step_until_output_contains(ATTESTATION_EVIDENCE_READY)
            .unwrap();

        run_mctp_spdm_attestation_test(
            hw.i3c_port().unwrap(),
            hw.i3c_address().unwrap().into(),
            PortPicker::new().random(true).pick().unwrap(),
            Duration::from_secs(9000),
            test_name,
        );

        let test = finish_runtime_hw_model(&mut hw);

        assert_eq!(0, test);
        assert_spdm_attestation_artifacts();

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn run_hitless_test(feature: &'static str, test_name: &'static str) {
        if std::env::var("SPDM_VALIDATOR_DIR").is_err() {
            println!("SPDM_VALIDATOR_DIR environment variable is not set. Skipping test");
            return;
        }
        remove_spdm_attestation_artifacts();
        if let Some(validator_dir) = spdm_validator_dir() {
            let _ = std::fs::remove_dir_all(validator_dir.join(COLD_BOOT_EVIDENCE_DIR));
        }
        std::env::set_var(
            "CPTRA_EMULATOR_SS_MCI_OFFSET",
            format!("0x{:016x}", MCI_BASE_AXI_ADDRESS),
        );

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut runtime = start_attestation_standalone_runtime(feature);
        runtime
            .wait_for_next_output_contains(ATTESTATION_EVIDENCE_READY, Duration::from_secs(9000))
            .unwrap();

        let i3c_port = runtime.i3c_port();
        let i3c_addr = runtime.i3c_address();
        // `pick()` only tests a port, it never reserves it, and the default
        // (non-random) strategy returns the first free port from 1024 up. This
        // test picks a validator port twice, and the first validator has exited
        // by the time the second pick runs, so a first-free scan would hand back
        // the port it just released, still in TIME_WAIT. Pick randomly, and
        // exclude the cold-boot port so reuse is impossible rather than merely
        // unlikely.
        let cold_boot_validator_port = PortPicker::new().random(true).pick().unwrap();
        let cold_done = run_mctp_spdm_attestation_test_until_done(
            i3c_port,
            i3c_addr,
            cold_boot_validator_port,
            Duration::from_secs(9000),
            test_name,
            false,
            session_nonce("SPDM_NONCE_COLD_BOOT"),
        );
        cold_done
            .recv_timeout(Duration::from_secs(9000))
            .expect("cold-boot SPDM attestation did not complete");

        // Keep the cold-boot evidence instead of discarding it: the workflow
        // appraises it against the cold-boot reference values, and the second
        // SPDM session below reuses the same fixed output filenames.
        preserve_spdm_attestation_artifacts(COLD_BOOT_EVIDENCE_DIR);
        let update_agent = run_successful_pldm_update(feature, i3c_port, i3c_addr);
        runtime
            .wait_for_next_output_contains(MCU_HITLESS_UPDATE_BANNER, Duration::from_secs(9000))
            .expect("MCU did not reboot into the staged firmware");
        runtime
            .wait_for_next_output_contains(ATTESTATION_EVIDENCE_READY, Duration::from_secs(9000))
            .expect("updated firmware did not re-publish attestation evidence");
        update_agent
            .activated
            .recv_timeout(Duration::from_secs(30))
            .expect("PLDM update agent did not reach firmware activation");
        update_agent.shutdown();

        let hitless_validator_port = PortPicker::new()
            .random(true)
            .execlude_add(cold_boot_validator_port)
            .pick()
            .unwrap();
        let hitless_done = run_mctp_spdm_attestation_test_until_done(
            i3c_port,
            i3c_addr,
            hitless_validator_port,
            Duration::from_secs(9000),
            test_name,
            false,
            session_nonce("SPDM_NONCE_POST_UPDATE"),
        );
        hitless_done
            .recv_timeout(Duration::from_secs(9000))
            .expect("hitless SPDM attestation did not complete");
        runtime.stop().expect("failed to stop standalone emulator");
        assert_spdm_attestation_artifacts();
        assert_preserved_artifacts_differ(COLD_BOOT_EVIDENCE_DIR);

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn remove_spdm_attestation_artifacts() {
        for artifact in spdm_attestation_artifact_paths() {
            let _ = std::fs::remove_file(artifact);
        }
    }

    /// Moves the artifacts the SPDM requester just wrote into
    /// `<SPDM_VALIDATOR_DIR>/<subdir>/`, leaving the fixed output filenames free
    /// for the next session. The requester always writes
    /// `measurement_block_fd.bin`/`certificate_chain_slot_00.der`, so without
    /// this the second session would overwrite the first session's evidence.
    pub(crate) fn preserve_spdm_attestation_artifacts(subdir: &str) {
        let Some(validator_dir) = spdm_validator_dir() else {
            return;
        };
        let dest_dir = validator_dir.join(subdir);
        std::fs::create_dir_all(&dest_dir)
            .unwrap_or_else(|err| panic!("failed to create {}: {err}", dest_dir.display()));
        for artifact in spdm_attestation_artifact_paths() {
            let file_name = artifact
                .file_name()
                .expect("artifact path always has a file name");
            std::fs::rename(&artifact, dest_dir.join(file_name))
                .unwrap_or_else(|err| panic!("failed to preserve {}: {err}", artifact.display()));
        }
    }

    pub(crate) fn assert_spdm_attestation_artifacts() {
        if let Err(err) = validate_spdm_attestation_artifacts() {
            panic!("{err}");
        }
    }

    /// Asserts that the evidence preserved under `subdir` is present and
    /// non-empty, and that its measurement block differs from the one currently
    /// in the validator directory. A hitless update that changes a measured SoC
    /// component must produce different evidence; identical blocks would mean
    /// the second appraisal is not actually testing anything new.
    fn assert_preserved_artifacts_differ(subdir: &str) {
        let Some(validator_dir) = spdm_validator_dir() else {
            return;
        };
        let preserved = validator_dir.join(subdir).join(MEASUREMENT_BLOCK_NAME);
        let current = validator_dir.join(MEASUREMENT_BLOCK_NAME);
        let preserved_bytes = std::fs::read(&preserved)
            .unwrap_or_else(|err| panic!("{} missing: {err}", preserved.display()));
        let current_bytes = std::fs::read(&current)
            .unwrap_or_else(|err| panic!("{} missing: {err}", current.display()));
        assert!(
            !preserved_bytes.is_empty(),
            "{} must not be empty",
            preserved.display()
        );
        assert_ne!(
            preserved_bytes, current_bytes,
            "post-update evidence is identical to cold-boot evidence; the hitless \
             update did not change any measured value, so appraising twice is a no-op"
        );
    }

    fn validate_spdm_attestation_artifacts() -> Result<(), String> {
        let Some(measurement_block) = spdm_measurement_block_path() else {
            return Ok(());
        };
        let metadata = std::fs::metadata(&measurement_block)
            .map_err(|err| format!("{} missing: {err}", measurement_block.display()))?;
        if metadata.len() == 0 {
            return Err(format!("{} must not be empty", measurement_block.display()));
        }
        Ok(())
    }

    fn spdm_measurement_block_path() -> Option<std::path::PathBuf> {
        spdm_validator_dir().map(|validator_dir| validator_dir.join(MEASUREMENT_BLOCK_NAME))
    }

    /// Fixed output filenames used by `spdm_requester_emu`.
    const MEASUREMENT_BLOCK_NAME: &str = "measurement_block_fd.bin";
    const CERTIFICATE_CHAIN_NAME: &str = "certificate_chain_slot_00.der";

    /// Subdirectory of `SPDM_VALIDATOR_DIR` holding the cold-boot evidence
    /// after the hitless update has overwritten the live artifacts. Consumed by
    /// the attestation workflow's first appraisal.
    pub(crate) const COLD_BOOT_EVIDENCE_DIR: &str = "cold-boot";

    fn spdm_validator_dir() -> Option<std::path::PathBuf> {
        std::env::var("SPDM_VALIDATOR_DIR")
            .ok()
            .map(std::path::PathBuf::from)
    }

    fn spdm_attestation_artifact_paths() -> Vec<std::path::PathBuf> {
        let Some(validator_dir) = spdm_validator_dir() else {
            return Vec::new();
        };
        vec![
            validator_dir.join(MEASUREMENT_BLOCK_NAME),
            validator_dir.join(CERTIFICATE_CHAIN_NAME),
        ]
    }

    /// Reads a per-session nonce from `var`, falling back to the job-wide
    /// `SPDM_NONCE`. Distinct nonces per session make each appraisal bind to its
    /// own freshness challenge instead of both replaying the same one.
    fn session_nonce(var: &str) -> Option<String> {
        std::env::var(var)
            .ok()
            .or_else(|| std::env::var("SPDM_NONCE").ok())
    }

    pub fn run_mctp_spdm_attestation_test(
        port: u16,
        target_addr: DynamicI3cAddress,
        spdm_port: u16,
        test_timeout_seconds: Duration,
        test_name: &'static str,
    ) {
        let _ = run_mctp_spdm_attestation_test_until_done(
            port,
            target_addr,
            spdm_port,
            test_timeout_seconds,
            test_name,
            true,
            session_nonce("SPDM_NONCE_COLD_BOOT"),
        );
    }

    fn run_mctp_spdm_attestation_test_until_done(
        port: u16,
        target_addr: DynamicI3cAddress,
        spdm_port: u16,
        test_timeout_seconds: Duration,
        test_name: &'static str,
        exit_on_success: bool,
        nonce: Option<String>,
    ) -> mpsc::Receiver<()> {
        let (done_tx, done_rx) = mpsc::channel();
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let stream = TcpStream::connect(addr).unwrap();
        let transport = MctpTransport::new(BufferedStream::new(stream), target_addr.into(), 1);
        SERVER_LISTENING.store(false, Ordering::Relaxed);

        caliptra_mcu_testing_common::spawn_with_emulator_state(move || {
            thread::sleep(test_timeout_seconds);
            println!(
                "[{}] TIMED OUT AFTER {:?} SECONDS",
                test_name,
                test_timeout_seconds.as_secs()
            );
            exit(-1);
        });

        caliptra_mcu_testing_common::spawn_with_emulator_state(move || {
            wait_for_runtime_start();

            if !caliptra_mcu_testing_common::is_emulator_running() {
                exit(-1);
            }
            thread::sleep(Duration::from_secs(5)); // give time for the app to be loaded and ready
            if !caliptra_mcu_testing_common::is_emulator_running() {
                exit(-1);
            }
            let listener = TcpListener::bind(("127.0.0.1", spdm_port))
                .expect("Could not bind to the SPDM listener port");
            println!(
                "[{}]: Spdm Server Listening on port {}",
                test_name, spdm_port
            );
            SERVER_LISTENING.store(true, Ordering::Relaxed);

            if let Some(spdm_stream) = listener.incoming().next() {
                let mut spdm_stream = spdm_stream.expect("Failed to accept connection");

                let mut test = SpdmValidatorRunner::new(Box::new(transport), test_name);
                test.run_test(&mut spdm_stream);
                if !test.is_passed() {
                    println!("[{}]: Spdm Attestation Test Failed", test_name);
                    exit(-1);
                } else {
                    if let Err(err) = validate_spdm_attestation_artifacts() {
                        println!(
                            "[{}]: Spdm Attestation Artifact Check Failed: {err}",
                            test_name
                        );
                        exit(-1);
                    }
                    println!("[{}]: Spdm Attestation Test Passed", test_name);
                    let _ = done_tx.send(());
                    if exit_on_success {
                        exit(0);
                    }
                }
            }
        });

        caliptra_mcu_testing_common::spawn_with_emulator_state(move || {
            execute_spdm_attestation_with_port("MCTP", Some(spdm_port), nonce);
        });
        done_rx
    }

    /// Drives a full PLDM firmware update against the running device.
    ///
    /// The returned handle's `activated` receiver fires once the update agent
    /// has driven the session through activation; `shutdown` stops the agent and
    /// waits for it to release the I3C socket.
    fn run_successful_pldm_update(
        feature: &'static str,
        port: u16,
        target_addr: DynamicI3cAddress,
    ) -> PldmUpdateAgent {
        let (activated_tx, activated_rx) = mpsc::channel();
        let (stopped_tx, stopped_rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let agent_stop = stop.clone();
        caliptra_mcu_testing_common::spawn_with_emulator_state(move || {
            wait_for_runtime_start();
            if !caliptra_mcu_testing_common::is_emulator_running() {
                exit(-1);
            }

            let pldm_transport = PldmMctpTransport::new(port, target_addr);
            let pldm_socket = pldm_transport
                .create_socket(EndpointId(8), EndpointId(0))
                .expect("failed to create PLDM socket");
            let socket_handle = PldmSocket::clone(&pldm_socket);
            let pldm_fw_pkg = feature_pldm_package(feature);
            let mut daemon = PldmDaemon::run(
                pldm_socket,
                Options {
                    caliptra_mcu_pldm_fw_pkg: Some(pldm_fw_pkg),
                    discovery_sm_actions: discovery_sm::DefaultActions {},
                    update_sm_actions: update_sm::DefaultActions {},
                    fd_tid: 0x01,
                    rerun_count: 0,
                },
            )
            .expect("failed to start PLDM update daemon");

            let deadline = Instant::now() + Duration::from_secs(1800);
            while Instant::now() < deadline && !agent_stop.load(Ordering::Relaxed) {
                if update_agent_activated(&daemon.get_update_sm_state()) {
                    let _ = activated_tx.send(());
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
            while !agent_stop.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(100));
            }
            daemon.stop();
            socket_handle.disconnect();
            let _ = stopped_tx.send(());
        });
        PldmUpdateAgent {
            activated: activated_rx,
            stopped: stopped_rx,
            stop,
        }
    }

    /// Handle to the background PLDM update agent.
    struct PldmUpdateAgent {
        activated: mpsc::Receiver<()>,
        stopped: mpsc::Receiver<()>,
        stop: Arc<AtomicBool>,
    }

    impl PldmUpdateAgent {
        /// Stops the agent and waits for it to release the I3C socket. The
        /// emulator serves a single I3C client at a time, so the next MCTP
        /// client cannot be accepted until this returns.
        fn shutdown(self) {
            self.stop.store(true, Ordering::Relaxed);
            self.stopped
                .recv_timeout(Duration::from_secs(60))
                .expect("PLDM update agent did not release the I3C socket");
        }
    }

    /// The firmware device self-activates and reboots without coming back up as
    /// a PLDM responder, so the update agent never receives the post-activation
    /// `GetStatus` reply that would advance it to `Done`. `Activate` is the last
    /// state observable from the agent side and is only reached once every
    /// component has been downloaded, verified, applied and accepted for
    /// activation.
    fn update_agent_activated(state: &update_sm::States) -> bool {
        matches!(state, update_sm::States::Activate | update_sm::States::Done)
    }

    fn feature_pldm_package(feature: &str) -> FirmwareManifest {
        let pldm_data = caliptra_mcu_builder::FirmwareBinaries::from_env()
            .expect("CPTRA_FIRMWARE_BUNDLE not set")
            .test_pldm_fw_pkg(feature)
            .unwrap_or_else(|_| panic!("prebuilt PLDM package not found for {feature}"));
        let mut pldm_file =
            tempfile::NamedTempFile::new().expect("failed to create PLDM package temp file");
        pldm_file
            .write_all(&pldm_data)
            .expect("failed to write PLDM package temp file");
        let mut manifest = FirmwareManifest::decode_firmware_package(
            &pldm_file.path().to_string_lossy().to_string(),
            None,
        )
        .expect("failed to decode PLDM package");

        // The staging flash is pre-seeded with the full update image by
        // `start_attestation_standalone_runtime`, so only a token payload has to
        // travel over PLDM. This keeps the emulated transfer short while still
        // exercising the real download/verify/apply/activate state machine.
        for component in manifest.component_image_information.iter_mut() {
            if let Some(image_data) = component.image_data.as_mut() {
                image_data.truncate(PLDM_FAST_TRANSFER_BYTES);
                component.size = image_data.len() as u32;
            }
        }
        manifest
    }
}
