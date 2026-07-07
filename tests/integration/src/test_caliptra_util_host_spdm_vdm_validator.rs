// Licensed under the Apache-2.0 license

//! Integration test for Caliptra VDM commands over SPDM vendor-defined messages.
//!
//! This test spawns the `caliptra-spdm-validator` binary (from caliptra-spdm-vdm-client) which
//! runs all Caliptra VDM commands against the MCU's SPDM responder.

#[cfg(test)]
mod test {
    use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TestParams, TEST_LOCK};
    use caliptra_api::SocManager;
    use caliptra_mcu_debug_unlock_signer::DebugUnlockKeys;
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_testing_common::i3c::DynamicI3cAddress;
    use caliptra_mcu_testing_common::i3c_socket::BufferedStream;
    use caliptra_mcu_testing_common::spdm_responder_validator::mctp::MctpTransport;
    use caliptra_mcu_testing_common::spdm_responder_validator::{
        SpdmValidatorRunner, SERVER_LISTENING,
    };
    use caliptra_mcu_testing_common::{
        is_emulator_running, spawn_with_emulator_state, wait_for_runtime_start,
    };
    use random_port::PortPicker;
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::process::{exit, Command, Stdio};
    use std::sync::atomic::Ordering;
    use std::thread;
    use std::time::Duration;
    use zerocopy::IntoBytes;

    const TEST_NAME: &str = "SPDM-VDM";

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
    ) {
        let bridge_port = PortPicker::new().pick().unwrap();
        let addr = SocketAddr::from(([127, 0, 0, 1], i3c_port));
        let stream = TcpStream::connect(addr).unwrap();
        let transport = MctpTransport::new(BufferedStream::new(stream), target_addr.into(), 1);

        // Timeout watchdog
        thread::spawn(move || {
            thread::sleep(test_timeout);
            println!(
                "[{}] TIMED OUT AFTER {:?} SECONDS",
                TEST_NAME,
                test_timeout.as_secs()
            );
            exit(-1);
        });

        let validator_args: Vec<String> = validator_args.iter().map(|s| s.to_string()).collect();
        let bridge_port_copy = bridge_port;

        // Bridge thread: uses spawn_with_emulator_state so it inherits the
        // ModelEmulated's per-instance state and can call wait_for_runtime_start
        // / is_emulator_running without panicking.
        spawn_with_emulator_state(move || {
            wait_for_runtime_start();
            if !is_emulator_running() {
                exit(-1);
            }
            thread::sleep(Duration::from_secs(5));
            if !is_emulator_running() {
                exit(-1);
            }

            let bridge_addr = format!("127.0.0.1:{}", bridge_port_copy);
            let listener =
                TcpListener::bind(&bridge_addr).expect("Could not bind to the SPDM bridge port");
            println!("[{}]: Bridge listening on {}", TEST_NAME, bridge_addr);
            SERVER_LISTENING.store(true, Ordering::Relaxed);

            if let Some(spdm_stream) = listener.incoming().next() {
                let mut spdm_stream = spdm_stream.expect("Failed to accept connection");
                let mut runner = SpdmValidatorRunner::new(Box::new(transport), TEST_NAME);
                runner.run_test(&mut spdm_stream);

                if runner.is_passed() {
                    println!("[{}]: Bridge completed successfully", TEST_NAME);
                    exit(0);
                } else {
                    println!("[{}]: Bridge reported failure", TEST_NAME);
                    exit(-1);
                }
            }
        });

        // Requester subprocess (uses spawn_with_emulator_state to inherit
        // per-instance state for is_emulator_running()-style checks).
        spawn_with_emulator_state(move || {
            println!("[{}]: Waiting for bridge to start...", TEST_NAME);
            while !SERVER_LISTENING.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(200));
            }
            thread::sleep(Duration::from_millis(500));

            execute_spdm_validator(bridge_port, &validator_args);
        });
    }

    /// Spawn the caliptra-spdm-validator binary as a subprocess.
    fn execute_spdm_validator(bridge_port: u16, extra_args: &[String]) {
        let bridge_addr = format!("127.0.0.1:{}", bridge_port);
        let binary_path = find_spdm_validator_binary();
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
            .unwrap_or_else(|e| {
                println!(
                    "[{}]: Failed to spawn caliptra-spdm-validator: {:#}",
                    TEST_NAME, e
                );
                exit(-1);
            });

        while is_emulator_running() {
            match child.try_wait() {
                Ok(Some(status)) => {
                    println!(
                        "[{}]: caliptra-spdm-validator exited with status: {:?}",
                        TEST_NAME, status
                    );
                    if !status.success() {
                        exit(-1);
                    }
                    return;
                }
                Ok(None) => {}
                Err(e) => {
                    println!(
                        "[{}]: Error waiting for caliptra-spdm-validator: {:?}",
                        TEST_NAME, e
                    );
                    exit(-1);
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
    }

    /// Find the caliptra-spdm-validator binary from SPDM_VALIDATOR_BIN env var.
    fn find_spdm_validator_binary() -> String {
        match std::env::var("SPDM_VALIDATOR_BIN") {
            Ok(path) => path,
            Err(_) => {
                println!(
                    "[{}]: SPDM_VALIDATOR_BIN env var not set. \
                     Build with: cd caliptra-util-host && cargo xtask build\n\
                     Then set: export SPDM_VALIDATOR_BIN=<repo>/target/caliptra-util-host/debug/caliptra-spdm-validator",
                    TEST_NAME
                );
                exit(-1);
            }
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

    #[ignore]
    #[test]
    fn test_caliptra_util_host_spdm_vdm_validator() {
        use caliptra_image_fake_keys::{
            VENDOR_ECC_KEY_0_PRIVATE, VENDOR_ECC_KEY_0_PUBLIC, VENDOR_MLDSA_KEY_0_PRIVATE,
            VENDOR_MLDSA_KEY_0_PUBLIC,
        };
        use caliptra_image_types::{ECC384_SCALAR_BYTE_SIZE, ECC384_SCALAR_WORD_SIZE};

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let unlock_level = 1u8;

        // --- Prepare ECC public key in hardware format (big-endian u32 words) ---
        let mut ecc_pub_key_u32 = [0u32; ECC384_SCALAR_WORD_SIZE * 2];
        ecc_pub_key_u32[..12].copy_from_slice(&VENDOR_ECC_KEY_0_PUBLIC.x);
        ecc_pub_key_u32[12..].copy_from_slice(&VENDOR_ECC_KEY_0_PUBLIC.y);
        let ecc_pub_key_bytes: [u8; 96] = ecc_pub_key_u32.as_bytes().try_into().unwrap();

        // --- Prepare MLDSA public key in hardware format (little-endian u32 words) ---
        let mldsa_pub_key_raw = VENDOR_MLDSA_KEY_0_PUBLIC.0.as_bytes();
        let mldsa_pub_key_u32: Vec<u32> = mldsa_pub_key_raw
            .chunks(4)
            .map(|chunk| {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(chunk);
                u32::from_le_bytes(arr)
            })
            .collect();
        let mldsa_pub_key_bytes: [u8; 2592] = mldsa_pub_key_u32.as_bytes().try_into().unwrap();

        // --- Set up keypairs for fuse provisioning ---
        let mut prod_dbg_keypairs: Vec<([u8; 96], [u8; 2592])> = vec![([0u8; 96], [0u8; 2592]); 8];
        prod_dbg_keypairs[(unlock_level - 1) as usize] = (ecc_pub_key_bytes, mldsa_pub_key_bytes);

        // --- Prepare ECC private key bytes for signing ---
        let mut be_ecc_priv_key_bytes = [0u8; ECC384_SCALAR_BYTE_SIZE];
        for (i, word) in VENDOR_ECC_KEY_0_PRIVATE.iter().enumerate() {
            be_ecc_priv_key_bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }

        // --- Prepare MLDSA private key bytes for signing ---
        let mldsa_priv_key_bytes: Vec<u8> = VENDOR_MLDSA_KEY_0_PRIVATE.0.as_bytes().to_vec();

        // --- Build DebugUnlockKeys and write to temp file for the validator binary ---
        let debug_unlock_keys = DebugUnlockKeys {
            ecc_private_key_bytes: be_ecc_priv_key_bytes,
            ecc_public_key: ecc_pub_key_u32,
            mldsa_private_key_bytes: mldsa_priv_key_bytes,
            mldsa_public_key: <[u32; 648]>::try_from(mldsa_pub_key_u32.as_slice()).unwrap(),
        };
        let keys_file = tempfile::NamedTempFile::new().expect("Failed to create temp file");
        debug_unlock_keys
            .save_to_file(keys_file.path())
            .expect("Failed to write debug unlock keys");
        let keys_path = keys_file.path().to_str().unwrap().to_string();

        // --- Start hw_model with keys provisioned in fuses ---
        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some("test-caliptra-util-host-spdm-vdm-validator"),
            i3c_port: Some(PortPicker::new().pick().unwrap()),
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
        run_spdm_vdm_test(
            hw.i3c_port().unwrap(),
            hw.i3c_address().unwrap().into(),
            Duration::from_secs(120),
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

        let test = finish_runtime_hw_model(&mut hw);
        assert_eq!(0, test);

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[ignore]
    #[test]
    fn test_caliptra_util_host_spdm_vdm_validator_mfg_mode() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some("test-caliptra-util-host-spdm-vdm-validator"),
            i3c_port: Some(PortPicker::new().pick().unwrap()),
            use_strap_secrets: true,
            lifecycle_controller_state: Some(caliptra_mcu_hw_model::LifecycleControllerState::Dev),
            ..Default::default()
        });

        hw.start_i3c_controller();

        let config_path = test_config_path();
        run_spdm_vdm_test(
            hw.i3c_port().unwrap(),
            hw.i3c_address().unwrap().into(),
            Duration::from_secs(120),
            &["--config", &config_path, "--mode", "manufacturing"],
        );

        let test = finish_runtime_hw_model(&mut hw);
        assert_eq!(0, test);

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
