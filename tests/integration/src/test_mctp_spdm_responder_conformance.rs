//! Licensed under the Apache-2.0 license

//! This module executes SPDM Responder conformance tests

#[cfg(test)]
mod test {
    use crate::test::{
        finish_runtime_hw_model, run_imaginary_flash_controller_service, start_runtime_hw_model,
        TestParams, TEST_LOCK,
    };
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_testing_common::i3c::DynamicI3cAddress;
    use caliptra_mcu_testing_common::i3c_socket::BufferedStream;
    use caliptra_mcu_testing_common::spdm_responder_validator::mctp::MctpTransport;
    use caliptra_mcu_testing_common::spdm_responder_validator::{
        execute_spdm_responder_validator, SpdmValidatorRunner, SERVER_LISTENING,
    };
    use caliptra_mcu_testing_common::{
        wait_for_runtime_start, wait_for_spdm_responder_ready, SpdmResponderTransport,
    };
    use random_port::PortPicker;
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::Ordering;
    use std::sync::mpsc::{self, Receiver};
    use std::time::Duration;

    const TEST_NAME: &str = "MCTP-SPDM-RESPONDER-VALIDATOR";

    #[test]
    fn test_mctp_spdm_responder_conformance() {
        if std::env::var("SPDM_VALIDATOR_DIR").is_err() {
            println!("SPDM_VALIDATOR_DIR environment variable is not set. Skipping test");
            return;
        }

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some("test-mctp-spdm-responder-conformance"),
            i3c_port: Some(PortPicker::new().pick().unwrap()),
            use_strap_secrets: true,
            ..Default::default()
        });

        hw.start_i3c_controller();

        run_imaginary_flash_controller_service(&mut hw);

        let conformance_result = run_mctp_spdm_conformance_test(
            hw.i3c_port().unwrap(),
            hw.i3c_address().unwrap().into(),
            Duration::from_secs(9000), // timeout in seconds
        );

        let test = finish_runtime_hw_model(&mut hw);
        let conformance_result = conformance_result
            .recv_timeout(Duration::from_secs(10))
            .expect("SPDM conformance worker did not report a result");

        assert_eq!(0, test);
        conformance_result.expect("SPDM responder conformance failed");

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn run_mctp_spdm_conformance_test(
        port: u16,
        target_addr: DynamicI3cAddress,
        test_timeout: Duration,
    ) -> Receiver<Result<(), String>> {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let stream = TcpStream::connect(addr).unwrap();
        let transport = MctpTransport::new(BufferedStream::new(stream), target_addr.into(), 1);
        let (result_tx, result_rx) = mpsc::channel();
        let (timeout_cancel_tx, timeout_cancel_rx) = mpsc::channel();

        let timeout_result_tx = result_tx.clone();
        caliptra_mcu_testing_common::spawn_with_emulator_state(move || {
            if timeout_cancel_rx.recv_timeout(test_timeout).is_err() {
                let message = format!(
                    "{TEST_NAME} timed out after {} seconds",
                    test_timeout.as_secs()
                );
                println!("[{TEST_NAME}] {message}");
                let _ = timeout_result_tx.send(Err(message));
                caliptra_mcu_testing_common::stop_emulator();
            }
        });

        SERVER_LISTENING.store(false, Ordering::Relaxed);
        let validator = execute_spdm_responder_validator("MCTP");
        caliptra_mcu_testing_common::spawn_with_emulator_state(move || {
            wait_for_runtime_start();
            if !caliptra_mcu_testing_common::is_emulator_running() {
                return;
            }
            wait_for_spdm_responder_ready(SpdmResponderTransport::Mctp);
            if !caliptra_mcu_testing_common::is_emulator_running() {
                return;
            }

            let result = (|| -> Result<(), String> {
                let listener = TcpListener::bind("127.0.0.1:2323")
                    .map_err(|err| format!("could not bind SPDM listener: {err}"))?;
                println!("[{TEST_NAME}]: SPDM server listening on port 2323");
                SERVER_LISTENING.store(true, Ordering::Relaxed);

                let (mut spdm_stream, _) = listener
                    .accept()
                    .map_err(|err| format!("failed to accept SPDM connection: {err}"))?;
                let mut test = SpdmValidatorRunner::new(Box::new(transport), TEST_NAME);
                test.run_test(&mut spdm_stream);

                let validator_passed = validator
                    .join()
                    .map_err(|_| "SPDM validator worker panicked".to_string())?;
                if !test.is_passed() {
                    return Err("SPDM transport bridge failed".to_string());
                }
                if !validator_passed {
                    return Err("SPDM validator exited unsuccessfully".to_string());
                }

                println!("[{TEST_NAME}]: SPDM responder conformance passed");
                Ok(())
            })();

            let _ = timeout_cancel_tx.send(());
            let _ = result_tx.send(result);
            caliptra_mcu_testing_common::stop_emulator();
        });

        result_rx
    }
}
