//! Licensed under the Apache-2.0 license

//! This module tests the PLDM Firmware Update

#[cfg(test)]
mod test {
    use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TEST_LOCK};
    use mcu_hw_model::McuHwModel;
    use mcu_testing_common::i3c_socket::{self, BufferedStream, MctpTestState, MctpTransportTest};
    use mcu_testing_common::mctp_util::common::MctpUtil;
    use mcu_testing_common::MCU_RUNNING;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_mctp_capsule_loopback() {
        let feature = "test-mctp-capsule-loopback";
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let feature = feature.replace("_", "-");
        let mut hw = start_runtime_hw_model(Some(&feature), Some(65534));

        hw.start_i3c_controller();

        let tests = generate_tests();
        i3c_socket::run_tests(
            hw.i3c_port().unwrap(),
            hw.i3c_address().unwrap().into(),
            tests,
            None,
        );

        let test = finish_runtime_hw_model(&mut hw);

        assert_eq!(0, test);

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn generate_tests() -> Vec<Box<dyn MctpTransportTest + Send>> {
        vec![Box::new(Test::new("MctpMultiPktTest")) as Box<dyn MctpTransportTest + Send>]
    }

    struct Test {
        test_name: String,
        test_state: MctpTestState,
        loopback_msg: Vec<u8>,
        mctp_util: MctpUtil,
        passed: bool,
    }

    impl Test {
        fn new(test_name: &str) -> Self {
            Test {
                test_name: test_name.to_string(),
                test_state: MctpTestState::Start,
                loopback_msg: Vec::new(),
                mctp_util: MctpUtil::new(),
                passed: false,
            }
        }
    }

    impl MctpTransportTest for Test {
        fn is_passed(&self) -> bool {
            self.passed
        }

        fn run_test(&mut self, stream: &mut BufferedStream, target_addr: u8) {
            stream.set_nonblocking(true).unwrap();

            while MCU_RUNNING.load(Ordering::Relaxed) {
                match self.test_state {
                    MctpTestState::Start => {
                        println!("Starting test: {}", self.test_name);
                        self.test_state = MctpTestState::ReceiveReq;
                    }
                    MctpTestState::ReceiveReq => {
                        self.loopback_msg =
                            self.mctp_util.receive_request(stream, target_addr, None);
                        self.test_state = MctpTestState::SendResp;
                    }
                    MctpTestState::SendResp => {
                        self.mctp_util.send_response(
                            self.loopback_msg.as_slice(),
                            stream,
                            target_addr,
                        );

                        self.test_state = MctpTestState::ReceiveReq;
                    }
                    MctpTestState::Finish => {
                        self.passed = true;
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
}
