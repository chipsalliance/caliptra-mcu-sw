// Licensed under the Apache-2.0 license

//! Firmware integration test for SPDM SET_CERTIFICATE.
//!
//! The test boots MCU runtime firmware with the SPDM responder enabled, bridges
//! `ocp_dev_identity_provision_tool` to the firmware over MCTP, sends
//! SET_CERTIFICATE, verifies the full Owner slot chain through GET_CERTIFICATE,
//! and performs Owner-slot CHALLENGE attestation.

#[cfg(test)]
mod test {
    use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TestParams, TEST_LOCK};
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
    use std::path::{Path, PathBuf};
    use std::process::{exit, Command, Stdio};
    use std::sync::atomic::Ordering;
    use std::thread;
    use std::time::Duration;

    const TEST_NAME: &str = "MCTP-SPDM-SET-CERTIFICATE";
    const FIRMWARE_FEATURE: &str = "test-mctp-spdm-set-certificate";

    #[ignore]
    #[test]
    fn test_mctp_spdm_set_certificate_with_ocp_provision_tool() {
        let tool_bin = find_ocp_provisioning_tool();
        let cert_chain = test_owner_certchain_path();
        let vendor_trust_anchor = test_vendor_root_path();
        assert!(
            cert_chain.is_file(),
            "test owner certificate chain not found: {}",
            cert_chain.display()
        );
        assert!(
            vendor_trust_anchor.is_file(),
            "test vendor root certificate not found: {}",
            vendor_trust_anchor.display()
        );

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some(FIRMWARE_FEATURE),
            i3c_port: Some(PortPicker::new().pick().unwrap()),
            use_strap_secrets: true,
            ..Default::default()
        });

        hw.start_i3c_controller();
        run_provisioning_test(
            hw.i3c_port().unwrap(),
            hw.i3c_address().unwrap().into(),
            Duration::from_secs(120),
            &tool_bin,
            &cert_chain,
            &vendor_trust_anchor,
        );

        let test = finish_runtime_hw_model(&mut hw);
        assert_eq!(0, test);

        lock.fetch_add(1, Ordering::Relaxed);
    }

    fn run_provisioning_test(
        i3c_port: u16,
        target_addr: DynamicI3cAddress,
        test_timeout: Duration,
        tool_bin: &Path,
        cert_chain: &Path,
        vendor_trust_anchor: &Path,
    ) {
        SERVER_LISTENING.store(false, Ordering::Relaxed);

        let bridge_port = PortPicker::new().pick().unwrap();
        let addr = SocketAddr::from(([127, 0, 0, 1], i3c_port));
        let stream = TcpStream::connect(addr).unwrap();
        let transport = MctpTransport::new(BufferedStream::new(stream), target_addr.into(), 1);

        thread::spawn(move || {
            thread::sleep(test_timeout);
            println!(
                "[{}] TIMED OUT AFTER {:?} SECONDS",
                TEST_NAME,
                test_timeout.as_secs()
            );
            exit(-1);
        });

        let bridge_port_copy = bridge_port;
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
            let listener = TcpListener::bind(&bridge_addr).expect("Could not bind SPDM bridge");
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

        let tool_bin = tool_bin.to_path_buf();
        let cert_chain = cert_chain.to_path_buf();
        let vendor_trust_anchor = vendor_trust_anchor.to_path_buf();
        spawn_with_emulator_state(move || {
            println!("[{}]: Waiting for bridge to start...", TEST_NAME);
            while !SERVER_LISTENING.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(200));
            }
            thread::sleep(Duration::from_millis(500));

            let bridge_addr = format!("127.0.0.1:{}", bridge_port);
            let mut child = Command::new(&tool_bin)
                .arg("--server")
                .arg(&bridge_addr)
                .arg("--cert-chain")
                .arg(&cert_chain)
                .arg("--vendor-trust-anchor")
                .arg(&vendor_trust_anchor)
                .arg("--verify-get-certificate")
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap_or_else(|e| {
                    println!(
                        "[{}]: Failed to spawn {}: {:#}",
                        TEST_NAME,
                        tool_bin.display(),
                        e
                    );
                    exit(-1);
                });

            while is_emulator_running() {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        println!(
                            "[{}]: provisioning tool exited with status: {:?}",
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
                            "[{}]: Error waiting for provisioning tool: {:?}",
                            TEST_NAME, e
                        );
                        exit(-1);
                    }
                }
                thread::sleep(Duration::from_millis(100));
            }
            let _ = child.kill();
        });
    }

    fn find_ocp_provisioning_tool() -> PathBuf {
        if let Ok(path) = std::env::var("OCP_DEV_IDENTITY_PROVISION_TOOL_BIN") {
            let path = PathBuf::from(path);
            assert!(
                path.is_file(),
                "OCP_DEV_IDENTITY_PROVISION_TOOL_BIN does not point to a file: {}",
                path.display()
            );
            return path;
        }

        let binary_name = if cfg!(windows) {
            "ocp_dev_identity_provision_tool.exe"
        } else {
            "ocp_dev_identity_provision_tool"
        };
        let current_exe = std::env::current_exe().expect("failed to get current test executable");
        let deps_dir = current_exe
            .parent()
            .expect("test executable has no parent directory");
        let profile_dir = deps_dir
            .parent()
            .expect("test executable deps directory has no parent directory");

        let candidates = vec![
            profile_dir.join(binary_name),
            repo_root()
                .join("target")
                .join("caliptra-util-host")
                .join(profile_dir.file_name().unwrap_or_default())
                .join(binary_name),
        ];

        if let Some(candidate) = find_existing_candidate(&candidates) {
            return candidate;
        }

        let searched = candidates
            .iter()
            .map(|path| format!("  - {}", path.display()))
            .collect::<Vec<_>>()
            .join("\n");
        panic!(
            "OCP_DEV_IDENTITY_PROVISION_TOOL_BIN env var not set and {binary_name} was not found.\n\
             Searched:\n{searched}\n\
             Build it with: cd caliptra-util-host && cargo build -p caliptra-spdm-vdm-client --bin ocp_dev_identity_provision_tool\n\
             Or with: cd caliptra-util-host && cargo xtask build\n\
             Then set OCP_DEV_IDENTITY_PROVISION_TOOL_BIN to the built binary path"
        );
    }

    fn find_existing_candidate(candidates: &[PathBuf]) -> Option<PathBuf> {
        candidates
            .iter()
            .find(|candidate| candidate.is_file())
            .cloned()
    }

    fn test_owner_certchain_path() -> PathBuf {
        repo_root().join("caliptra-util-host/apps/spdm/certs/test_owner_certchain.der")
    }

    fn test_vendor_root_path() -> PathBuf {
        repo_root().join("caliptra-util-host/apps/spdm/certs/test_vendor_root.der")
    }

    fn repo_root() -> &'static Path {
        static REPO_ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
        REPO_ROOT
            .get_or_init(|| {
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .expect("tests/integration has no parent")
                    .parent()
                    .expect("tests has no parent")
                    .to_path_buf()
            })
            .as_path()
    }
}
