// Licensed under the Apache-2.0 license

use crate::i3c_socket::{MctpTestState, TestTrait};
// use crate::tests::mctp_util::base_protocol::{MCTPHdr, MCTP_HDR_SIZE};
use crate::tests::mctp_util::common::MctpUtil;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub fn generate_tests() -> Vec<Box<dyn TestTrait + Send>> {
    vec![Box::new(Test::new("MctpMultiPktTest")) as Box<dyn TestTrait + Send>]
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

impl TestTrait for Test {
    fn is_passed(&self) -> bool {
        self.passed
    }

    fn run_test(&mut self, running: Arc<AtomicBool>, stream: &mut TcpStream, target_addr: u8) {
        stream.set_nonblocking(true).unwrap();

        while running.load(Ordering::Relaxed) {
            match self.test_state {
                MctpTestState::Start => {
                    println!("Starting test: {}", self.test_name);
                    self.test_state = MctpTestState::ReceiveReq;
                }
                MctpTestState::ReceiveReq => {
                    self.loopback_msg =
                        self.mctp_util
                            .receive_request(running.clone(), stream, target_addr);
                    self.test_state = MctpTestState::SendResp;
                }
                MctpTestState::SendResp => {
                    self.mctp_util.send_response(
                        self.loopback_msg.as_slice(),
                        running.clone(),
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
