// Licensed under the Apache-2.0 license

use crate::i3c_socket::{BufferedStream, MctpTestState, MctpTransportTest};
use crate::tests::mctp_util::common::MctpUtil;
use crate::EMULATOR_RUNNING;
use std::sync::atomic::Ordering;

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

        while EMULATOR_RUNNING.load(Ordering::Relaxed) {
            match self.test_state {
                MctpTestState::Start => {
                    println!("Starting test: {}", self.test_name);
                    self.test_state = MctpTestState::ReceiveReq;
                }
                MctpTestState::ReceiveReq => {
                    self.loopback_msg = self.mctp_util.receive_request(stream, target_addr, None);
                    self.test_state = MctpTestState::SendResp;
                }
                MctpTestState::SendResp => {
                    self.mctp_util
                        .send_response(self.loopback_msg.as_slice(), stream, target_addr);

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
