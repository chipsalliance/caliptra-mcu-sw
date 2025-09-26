//! Licensed under the Apache-2.0 license

//! This module tests the PLDM Firmware Update

#[cfg(test)]
mod test {
    use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TEST_LOCK};
    use mcu_hw_model::McuHwModel;
    use mcu_testing_common::i3c::DynamicI3cAddress;
    use mcu_testing_common::i3c_socket::BufferedStream;
    use mcu_testing_common::spdm_responder_validator::mctp::MctpTransport;
    use mcu_testing_common::spdm_responder_validator::{
        execute_spdm_validator, SpdmValidatorRunner, SERVER_LISTENING,
    };
    use mcu_testing_common::{wait_for_runtime_start, MCU_RUNNING};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::process::exit;
    use std::sync::atomic::Ordering;
    use std::thread;
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

        let mut hw = start_runtime_hw_model(None, Some(65534));

        hw.start_i3c_controller();

        run_mctp_spdm_conformance_test(
            hw.i3c_port().unwrap(),
            hw.i3c_address().unwrap().into(),
            Duration::from_secs(9000), // timeout in seconds
        );

        let test = finish_runtime_hw_model(&mut hw);

        assert_eq!(0, test);

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn run_mctp_spdm_conformance_test(
        port: u16,
        target_addr: DynamicI3cAddress,
        test_timeout_seconds: Duration,
    ) {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let stream = TcpStream::connect(addr).unwrap();
        let transport = MctpTransport::new(BufferedStream::new(stream), target_addr.into(), 1);

        thread::spawn(move || {
            thread::sleep(test_timeout_seconds);
            println!(
                "[{}] TIMED OUT AFTER {:?} SECONDS",
                TEST_NAME,
                test_timeout_seconds.as_secs()
            );
            exit(-1);
        });

        thread::spawn(move || {
            wait_for_runtime_start();

            if !MCU_RUNNING.load(Ordering::Relaxed) {
                exit(-1);
            }
            thread::sleep(Duration::from_secs(5)); // give time for the app to be loaded and ready
            if !MCU_RUNNING.load(Ordering::Relaxed) {
                exit(-1);
            }
            let listener = TcpListener::bind("127.0.0.1:2323")
                .expect("Could not bind to the SPDM listerner port");
            println!("[{}]: Spdm Server Listening on port 2323", TEST_NAME);
            SERVER_LISTENING.store(true, Ordering::Relaxed);

            if let Some(spdm_stream) = listener.incoming().next() {
                let mut spdm_stream = spdm_stream.expect("Failed to accept connection");

                let mut test = SpdmValidatorRunner::new(Box::new(transport), TEST_NAME);
                test.run_test(&mut spdm_stream);
                if !test.is_passed() {
                    println!("[{}]: Spdm Responder Conformance Test Failed", TEST_NAME);
                    exit(-1);
                } else {
                    println!("[{}]: Spdm Responder Conformance Test Passed", TEST_NAME);
                    exit(0);
                }
            }
        });

        thread::spawn(move || {
            execute_spdm_validator("MCTP");
        });
    }
}
