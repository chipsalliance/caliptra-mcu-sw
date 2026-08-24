// Licensed under the Apache-2.0 license

//! Integration test for Caliptra VDM commands over SPDM vendor-defined messages.
//!
//! These tests spawn the `caliptra-spdm-validator` binary (from
//! caliptra-spdm-vdm-client) against the MCU's SPDM responder in two shapes:
//!
//! - the command suite (ExportAttestedCsr, GetAttestation), which needs no
//!   provisioned fuses;
//! - one isolated fuse suite per test, selected with `--fuse-suite`. Each runs
//!   alone against inactive slot 1 in its own disposable emulator model,
//!   because the operations are destructive and order-dependent.

#[cfg(test)]
mod test {
    use crate::test::{
        compile_runtime, start_runtime_hw_model, CustomCaliptraFw, TestParams, TEST_LOCK,
    };
    use caliptra_api::SocManager;
    use caliptra_mcu_builder::{CaliptraBuildArgs, CaliptraBuilder, FirmwareBinaries};
    use caliptra_mcu_debug_unlock_signer::DebugUnlockKeys;
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_testing_common::i3c::DynamicI3cAddress;
    use caliptra_mcu_testing_common::i3c_socket::BufferedStream;
    use caliptra_mcu_testing_common::spdm_responder_validator::mctp::MctpTransport;
    use caliptra_mcu_testing_common::spdm_responder_validator::SpdmValidatorRunner;
    use caliptra_mcu_testing_common::{
        is_emulator_running, spawn_with_emulator_state, wait_for_runtime_start,
    };
    use random_port::PortPicker;
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;
    use zerocopy::IntoBytes;

    const TEST_NAME: &str = "SPDM-VDM";
    const TEST_FEATURE: &str = "test-caliptra-util-host-spdm-vdm-validator";

    fn caliptra_fw_svn7() -> CustomCaliptraFw {
        if let Ok(binaries) = FirmwareBinaries::from_env() {
            return CustomCaliptraFw {
                fw_bytes: binaries.caliptra_fw_svn7.clone(),
                vendor_pk_hash: binaries.vendor_pk_hash().unwrap(),
                soc_manifest: binaries.test_soc_manifest(TEST_FEATURE).unwrap().clone(),
            };
        }

        let runtime = compile_runtime(Some(TEST_FEATURE), false);
        let mut builder = CaliptraBuilder::new(&CaliptraBuildArgs {
            svn: Some(7),
            mcu_firmware: Some(runtime),
            ..Default::default()
        });
        let fw_bytes = std::fs::read(builder.get_caliptra_fw().unwrap()).unwrap();
        let vendor_pk_hash: [u8; 48] = hex::decode(builder.get_vendor_pk_hash().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let soc_manifest = std::fs::read(builder.get_soc_manifest(None).unwrap()).unwrap();
        CustomCaliptraFw {
            fw_bytes,
            vendor_pk_hash,
            soc_manifest,
        }
    }

    /// Reusable test harness for running the caliptra-spdm-validator binary against
    /// the MCU HW model's SPDM responder.
    ///
    /// This function:
    /// 1. Connects to the MCU's I3C port as an MCTP transport
    /// 2. Starts a bridge (SpdmValidatorRunner) on a random port
    /// 3. Spawns the caliptra-spdm-validator binary connecting to the bridge
    /// 4. Waits for completion or timeout
    fn run_spdm_vdm_test(
        i3c_port: u16,
        target_addr: DynamicI3cAddress,
        test_timeout: Duration,
        validator_args: &[&str],
    ) -> (Arc<AtomicBool>, Arc<AtomicBool>) {
        let bridge_port = PortPicker::new().pick().unwrap();
        let addr = SocketAddr::from(([127, 0, 0, 1], i3c_port));
        let stream = TcpStream::connect(addr).unwrap();
        let transport = MctpTransport::new(BufferedStream::new(stream), target_addr.into(), 1);

        // Timeout watchdog. The completion flag prevents a finished suite's
        // watchdog from terminating a later isolated emulator instance.
        let completed = Arc::new(AtomicBool::new(false));
        let failed = Arc::new(AtomicBool::new(false));
        let watchdog_completed = completed.clone();
        let watchdog_failed = failed.clone();
        thread::spawn(move || {
            thread::sleep(test_timeout);
            if !watchdog_completed.load(Ordering::Relaxed) {
                println!(
                    "[{}] TIMED OUT AFTER {:?} SECONDS",
                    TEST_NAME,
                    test_timeout.as_secs()
                );
                watchdog_failed.store(true, Ordering::Relaxed);
                watchdog_completed.store(true, Ordering::Relaxed);
            }
        });

        let validator_args: Vec<String> = validator_args.iter().map(|s| s.to_string()).collect();
        let bridge_port_copy = bridge_port;
        let bridge_completed = completed.clone();
        let bridge_failed = failed.clone();
        let server_listening = Arc::new(AtomicBool::new(false));
        let bridge_listening = server_listening.clone();

        // Bridge thread: uses spawn_with_emulator_state so it inherits the
        // ModelEmulated's per-instance state and can call wait_for_runtime_start
        // / is_emulator_running without panicking.
        spawn_with_emulator_state(move || {
            wait_for_runtime_start();
            if !is_emulator_running() {
                bridge_failed.store(true, Ordering::Relaxed);
                bridge_completed.store(true, Ordering::Relaxed);
                return;
            }
            thread::sleep(Duration::from_secs(5));
            if !is_emulator_running() {
                bridge_failed.store(true, Ordering::Relaxed);
                bridge_completed.store(true, Ordering::Relaxed);
                return;
            }

            let bridge_addr = format!("127.0.0.1:{}", bridge_port_copy);
            let listener =
                TcpListener::bind(&bridge_addr).expect("Could not bind to the SPDM bridge port");
            println!("[{}]: Bridge listening on {}", TEST_NAME, bridge_addr);
            bridge_listening.store(true, Ordering::Relaxed);

            if let Some(spdm_stream) = listener.incoming().next() {
                let mut spdm_stream = spdm_stream.expect("Failed to accept connection");
                let mut runner = SpdmValidatorRunner::new(Box::new(transport), TEST_NAME);
                runner.run_test(&mut spdm_stream);

                if runner.is_passed() {
                    println!("[{}]: Bridge completed successfully", TEST_NAME);
                } else {
                    println!("[{}]: Bridge reported failure", TEST_NAME);
                    bridge_failed.store(true, Ordering::Relaxed);
                }
            }
            bridge_completed.store(true, Ordering::Relaxed);
        });

        // Requester subprocess (uses spawn_with_emulator_state to inherit
        // per-instance state for is_emulator_running()-style checks).
        let requester_completed = completed.clone();
        let requester_failed = failed.clone();
        spawn_with_emulator_state(move || {
            println!("[{}]: Waiting for bridge to start...", TEST_NAME);
            while !server_listening.load(Ordering::Relaxed) {
                if requester_completed.load(Ordering::Relaxed) {
                    return;
                }
                thread::sleep(Duration::from_millis(200));
            }
            thread::sleep(Duration::from_millis(500));

            if let Err(error) = execute_spdm_validator(bridge_port, &validator_args) {
                println!("[{}]: {}", TEST_NAME, error);
                requester_failed.store(true, Ordering::Relaxed);
                requester_completed.store(true, Ordering::Relaxed);
            }
        });
        (completed, failed)
    }

    /// Spawn the caliptra-spdm-validator binary as a subprocess.
    fn execute_spdm_validator(bridge_port: u16, extra_args: &[String]) -> Result<(), String> {
        let bridge_addr = format!("127.0.0.1:{}", bridge_port);
        let binary_path = find_spdm_validator_binary()?;
        println!(
            "[{}]: Spawning caliptra-spdm-validator at: {:?}",
            TEST_NAME, binary_path
        );

        let mut cmd = Command::new(&binary_path);
        cmd.arg("--server").arg(&bridge_addr);

        for arg in extra_args {
            cmd.arg(arg);
        }

        let mut child = cmd
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| format!("Failed to spawn caliptra-spdm-validator: {error:#}"))?;

        while is_emulator_running() {
            match child.try_wait() {
                Ok(Some(status)) => {
                    println!(
                        "[{}]: caliptra-spdm-validator exited with status: {:?}",
                        TEST_NAME, status
                    );
                    if !status.success() {
                        return Err(format!(
                            "caliptra-spdm-validator failed with status {status}"
                        ));
                    }
                    return Ok(());
                }
                Ok(None) => {}
                Err(error) => return Err(format!("Error waiting for validator: {error:?}")),
            }
            thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        Err("emulator stopped before caliptra-spdm-validator completed".to_string())
    }

    /// Find the caliptra-spdm-validator binary from SPDM_VALIDATOR_BIN env var.
    fn find_spdm_validator_binary() -> Result<String, String> {
        match std::env::var("SPDM_VALIDATOR_BIN") {
            Ok(path) => Ok(path),
            Err(_) => Err(
                "SPDM_VALIDATOR_BIN env var not set. \
                     Build with: cd caliptra-util-host && cargo xtask build\n\
                     Then set: export SPDM_VALIDATOR_BIN=<repo>/target/caliptra-util-host/debug/caliptra-spdm-validator"
                    .to_string(),
            ),
        }
    }

    // --- Test cases ---

    /// Path to test-config.toml relative to the repository root.
    fn test_config_path() -> String {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let repo_root = std::path::Path::new(manifest_dir)
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        repo_root
            .join("caliptra-util-host/apps/spdm/test-config.toml")
            .to_string_lossy()
            .to_string()
    }

    fn debug_unlock_material(unlock_level: u8) -> (Vec<([u8; 96], [u8; 2592])>, DebugUnlockKeys) {
        use caliptra_image_fake_keys::{
            VENDOR_ECC_KEY_0_PRIVATE, VENDOR_ECC_KEY_0_PUBLIC, VENDOR_MLDSA_KEY_0_PRIVATE,
            VENDOR_MLDSA_KEY_0_PUBLIC,
        };
        use caliptra_image_types::{ECC384_SCALAR_BYTE_SIZE, ECC384_SCALAR_WORD_SIZE};

        let mut ecc_pub_key_u32 = [0u32; ECC384_SCALAR_WORD_SIZE * 2];
        ecc_pub_key_u32[..12].copy_from_slice(&VENDOR_ECC_KEY_0_PUBLIC.x);
        ecc_pub_key_u32[12..].copy_from_slice(&VENDOR_ECC_KEY_0_PUBLIC.y);
        let ecc_pub_key_bytes: [u8; 96] = ecc_pub_key_u32.as_bytes().try_into().unwrap();

        let mldsa_pub_key_u32: Vec<u32> = VENDOR_MLDSA_KEY_0_PUBLIC
            .0
            .as_bytes()
            .chunks(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect();
        let mldsa_pub_key_bytes: [u8; 2592] = mldsa_pub_key_u32.as_bytes().try_into().unwrap();

        let mut prod_dbg_keypairs = vec![([0u8; 96], [0u8; 2592]); 8];
        prod_dbg_keypairs[(unlock_level - 1) as usize] = (ecc_pub_key_bytes, mldsa_pub_key_bytes);

        let mut ecc_private_key_bytes = [0u8; ECC384_SCALAR_BYTE_SIZE];
        for (index, word) in VENDOR_ECC_KEY_0_PRIVATE.iter().enumerate() {
            ecc_private_key_bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }

        let keys = DebugUnlockKeys {
            ecc_private_key_bytes,
            ecc_public_key: ecc_pub_key_u32,
            mldsa_private_key_bytes: VENDOR_MLDSA_KEY_0_PRIVATE.0.as_bytes().to_vec(),
            mldsa_public_key: mldsa_pub_key_u32.try_into().unwrap(),
        };
        (prod_dbg_keypairs, keys)
    }

    /// Exercises the non-fuse command suite: ExportAttestedCsr and
    /// GetAttestation. The fuse-suite tests below cannot cover these, because
    /// `--fuse-suite` makes the validator run that suite alone.
    ///
    #[ignore]
    #[test]
    fn test_caliptra_util_host_spdm_vdm_validator_commands() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let unlock_level = 1u8;
        let (prod_dbg_unlock_keypairs, debug_unlock_keys) = debug_unlock_material(unlock_level);
        let keys_file = tempfile::NamedTempFile::new().expect("Failed to create temp file");
        debug_unlock_keys
            .save_to_file(keys_file.path())
            .expect("Failed to write debug unlock keys");
        let keys_path = keys_file.path().to_str().unwrap().to_string();

        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some(TEST_FEATURE),
            i3c_port: Some(PortPicker::new().pick().unwrap()),
            debug_intent: true,
            lifecycle_controller_state: Some(caliptra_mcu_hw_model::LifecycleControllerState::Prod),
            prod_dbg_unlock_keypairs,
            use_strap_secrets: true,
            ..Default::default()
        });

        hw.start_i3c_controller();
        hw.caliptra_soc_manager()
            .soc_ifc()
            .ss_dbg_manuf_service_reg_req()
            .write(|w| w.prod_dbg_unlock_req(true));

        let config_path = test_config_path();
        let (completed, failed) = run_spdm_vdm_test(
            hw.i3c_port().unwrap(),
            hw.i3c_address().unwrap().into(),
            Duration::from_secs(600),
            &[
                "--config",
                &config_path,
                "--key-ids",
                "1,2,3",
                "--algorithm",
                "1",
                "--debug-unlock-keys-file",
                &keys_path,
                "--unlock-level",
                &unlock_level.to_string(),
            ],
        );

        while !completed.load(Ordering::Relaxed) {
            hw.step();
        }
        assert!(!failed.load(Ordering::Relaxed), "SPDM validator failed");

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn run_isolated_fuse_suite(suite: &str) {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let unlock_level = 1u8;
        let (prod_dbg_keypairs, debug_unlock_keys) = debug_unlock_material(unlock_level);
        let keys_file = tempfile::NamedTempFile::new().expect("Failed to create temp file");
        debug_unlock_keys
            .save_to_file(keys_file.path())
            .expect("Failed to write debug unlock keys");
        let keys_path = keys_file.path().to_str().unwrap().to_string();

        // --- Start hw_model with keys provisioned in fuses ---
        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some(TEST_FEATURE),
            custom_caliptra_fw: Some(caliptra_fw_svn7()),
            i3c_port: Some(PortPicker::new().pick().unwrap()),
            dot_enabled: true,
            use_strap_secrets: true,
            debug_intent: true,
            lifecycle_controller_state: Some(caliptra_mcu_hw_model::LifecycleControllerState::Prod),
            prod_dbg_unlock_keypairs: prod_dbg_keypairs,
            ..Default::default()
        });

        hw.start_i3c_controller();

        // Set the prod_dbg_unlock_req bit before the SPDM VDM test runs.
        // This is required for Caliptra RT to accept debug unlock commands.
        hw.caliptra_soc_manager()
            .soc_ifc()
            .ss_dbg_manuf_service_reg_req()
            .write(|w| w.prod_dbg_unlock_req(true));

        let config_path = test_config_path();
        let (completed, failed) = run_spdm_vdm_test(
            hw.i3c_port().unwrap(),
            hw.i3c_address().unwrap().into(),
            Duration::from_secs(600),
            &[
                "--config",
                &config_path,
                "--key-ids",
                "1,2,3",
                "--algorithm",
                "1",
                "--debug-unlock-keys-file",
                &keys_path,
                "--unlock-level",
                &unlock_level.to_string(),
                "--fuse-suite",
                suite,
            ],
        );

        while !completed.load(Ordering::Relaxed) {
            hw.step();
        }
        assert!(!failed.load(Ordering::Relaxed), "SPDM validator failed");

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    macro_rules! isolated_fuse_suite_test {
        ($name:ident, $suite:literal) => {
            #[ignore]
            #[test]
            fn $name() {
                run_isolated_fuse_suite($suite);
            }
        };
    }

    isolated_fuse_suite_test!(
        test_caliptra_util_host_spdm_vdm_validator_authorization,
        "authorization"
    );
    isolated_fuse_suite_test!(test_caliptra_util_host_spdm_vdm_validator_dot, "dot");
    isolated_fuse_suite_test!(
        test_caliptra_util_host_spdm_vdm_validator_provision_vendor_pk_hash,
        "provision-vendor-pk-hash"
    );
    isolated_fuse_suite_test!(
        test_caliptra_util_host_spdm_vdm_validator_provision_owner_pk_hash,
        "provision-owner-pk-hash"
    );
    isolated_fuse_suite_test!(
        test_caliptra_util_host_spdm_vdm_validator_increase_min_svn,
        "increase-min-svn"
    );
    isolated_fuse_suite_test!(
        test_caliptra_util_host_spdm_vdm_validator_fuse_lock_partition,
        "fuse-lock-partition"
    );
    isolated_fuse_suite_test!(
        test_caliptra_util_host_spdm_vdm_validator_revoke_vendor_pub_key,
        "revoke-vendor-pub-key"
    );
    isolated_fuse_suite_test!(
        test_caliptra_util_host_spdm_vdm_validator_revoke_vendor_pk_hash,
        "revoke-vendor-pk-hash"
    );
}
