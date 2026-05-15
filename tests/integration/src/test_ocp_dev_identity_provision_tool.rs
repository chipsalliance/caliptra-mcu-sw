// Licensed under the Apache-2.0 license

//! Integration test for OCP device identity provisioning over SPDM SET_CERTIFICATE.
//!
//! The requester side is implemented by the `ocp_dev_identity_provision_tool` binary. The test
//! bridges that requester to the MCU HW model's SPDM responder over MCTP, sends
//! SET_CERTIFICATE, and verifies the installed chain through GET_CERTIFICATE.

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
    use caliptra_mcu_testing_common::{wait_for_runtime_start, MCU_RUNNING};
    use random_port::PortPicker;
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::process::{exit, Command, Stdio};
    use std::sync::atomic::Ordering;
    use std::thread;
    use std::time::Duration;

    const TEST_NAME: &str = "OCP-DEV-IDENTITY-PROVISION";

    #[ignore]
    #[test]
    fn test_ocp_dev_identity_provision_tool_set_certificate_end_to_end() {
        let tool_bin = match std::env::var("OCP_DEV_IDENTITY_PROVISION_TOOL_BIN") {
            Ok(path) => path,
            Err(_) => {
                println!(
                    "[{}]: OCP_DEV_IDENTITY_PROVISION_TOOL_BIN env var not set. \
                     Build with: cd caliptra-util-host && cargo xtask build\n\
                     Then set: export OCP_DEV_IDENTITY_PROVISION_TOOL_BIN=<repo>/target/caliptra-util-host/debug/ocp_dev_identity_provision_tool",
                    TEST_NAME
                );
                return;
            }
        };

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
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
        );

        let test = finish_runtime_hw_model(&mut hw);
        assert_eq!(0, test);

        lock.fetch_add(1, Ordering::Relaxed);
    }

    fn run_provisioning_test(
        i3c_port: u16,
        target_addr: DynamicI3cAddress,
        test_timeout: Duration,
        tool_bin: &str,
    ) {
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
        thread::spawn(move || {
            wait_for_runtime_start();
            if !MCU_RUNNING.load(Ordering::Relaxed) {
                exit(-1);
            }
            thread::sleep(Duration::from_secs(5));
            if !MCU_RUNNING.load(Ordering::Relaxed) {
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

        let tool_bin = tool_bin.to_string();
        thread::spawn(move || {
            println!("[{}]: Waiting for bridge to start...", TEST_NAME);
            while !SERVER_LISTENING.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(200));
            }
            thread::sleep(Duration::from_millis(500));

            let bridge_addr = format!("127.0.0.1:{}", bridge_port);
            let mut child = Command::new(&tool_bin)
                .arg("--server")
                .arg(&bridge_addr)
                .arg("--verify-get-certificate")
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap_or_else(|e| {
                    println!("[{}]: Failed to spawn {}: {:#}", TEST_NAME, tool_bin, e);
                    exit(-1);
                });

            while MCU_RUNNING.load(Ordering::Relaxed) {
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
}
