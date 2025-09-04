// Licensed under the Apache-2.0 license

use crate::i3c_socket::{BufferedStream, MctpTestState, MctpTransportTest};
use crate::tests::mctp_util::common::MctpUtil;
use crate::EMULATOR_RUNNING;
use std::sync::atomic::Ordering;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[derive(EnumIter, Debug)]
pub(crate) enum MctpUserAppTests {
    MctpAppResponderReady,
    MctpAppLoopbackTest64,
    MctpAppLoopbackTest63,
    MctpAppLoopbackTest256,
    MctpAppLoopbackTest1000,
    MctpAppLoopbackTest1024,
}

impl MctpUserAppTests {
    pub fn generate_tests(msg_type: u8) -> Vec<Box<dyn MctpTransportTest + Send>> {
        MctpUserAppTests::iter()
            .enumerate()
            .map(|(i, test_id)| {
                let test_name = test_id.name();
                let msg_tag = (i % 4) as u8;
                let req_msg_buf = test_id.generate_req_msg(msg_type);

                Box::new(Test::new(test_name, msg_type, msg_tag, req_msg_buf))
                    as Box<dyn MctpTransportTest + Send>
            })
            .collect()
    }

    fn name(&self) -> &'static str {
        match self {
            MctpUserAppTests::MctpAppResponderReady => "MctpAppResponderReady",
            MctpUserAppTests::MctpAppLoopbackTest64 => "MctpAppLoopbackTest64",
            MctpUserAppTests::MctpAppLoopbackTest63 => "MctpAppLoopbackTest63",
            MctpUserAppTests::MctpAppLoopbackTest256 => "MctpAppLoopbackTest256",
            MctpUserAppTests::MctpAppLoopbackTest1000 => "MctpAppLoopbackTest1000",
            MctpUserAppTests::MctpAppLoopbackTest1024 => "MctpAppLoopbackTest1024",
        }
    }

    fn msg_size(&self) -> usize {
        match self {
            MctpUserAppTests::MctpAppResponderReady => 1,
            MctpUserAppTests::MctpAppLoopbackTest64 => 64,
            MctpUserAppTests::MctpAppLoopbackTest63 => 63,
            MctpUserAppTests::MctpAppLoopbackTest256 => 256,
            MctpUserAppTests::MctpAppLoopbackTest1000 => 1000,
            MctpUserAppTests::MctpAppLoopbackTest1024 => 1024,
        }
    }

    fn generate_req_msg(&self, msg_type: u8) -> Vec<u8> {
        let mut msg_buf: Vec<u8> = (0..self.msg_size()).map(|_| rand::random::<u8>()).collect();
        msg_buf[0] = msg_type;
        msg_buf
    }
}

struct Test {
    test_name: String,
    test_state: MctpTestState,
    msg_type: u8,
    msg_tag: u8,
    req_msg_buf: Vec<u8>,
    passed: bool,
    mctp_util: MctpUtil,
}

impl Test {
    fn new(test_name: &str, msg_type: u8, msg_tag: u8, req_msg_buf: Vec<u8>) -> Self {
        Test {
            test_name: test_name.to_string(),
            test_state: MctpTestState::Start,
            msg_type,
            msg_tag,
            req_msg_buf,
            passed: false,
            mctp_util: MctpUtil::new(),
        }
    }

    fn responder_ready_test(&self) -> bool {
        matches!(self.test_name.as_str(), "MctpAppResponderReady")
    }

    fn wait_for_responder(&mut self, stream: &mut BufferedStream, target_addr: u8) {
        let resp_msg = self.mctp_util.wait_for_responder(
            self.msg_tag,
            self.req_msg_buf.as_slice(),
            stream,
            target_addr,
        );

        if let Some(resp_msg) = resp_msg {
            self.passed = resp_msg[0] == self.msg_type && self.req_msg_buf == resp_msg;
        }
        println!(
            "RESPONDER_READY: Test {} : {}",
            self.test_name,
            if self.passed { "PASSED" } else { "FAILED" }
        );
    }

    fn run_loopback_test(&mut self, stream: &mut BufferedStream, target_addr: u8) {
        stream.set_nonblocking(true).unwrap();
        while EMULATOR_RUNNING.load(Ordering::Relaxed) {
            match self.test_state {
                MctpTestState::Start => {
                    self.test_state = MctpTestState::SendReq;
                }
                MctpTestState::SendReq => {
                    self.mctp_util.send_request(
                        self.msg_tag,
                        self.req_msg_buf.as_slice(),
                        stream,
                        target_addr,
                    );
                    self.test_state = MctpTestState::ReceiveResp;
                }
                MctpTestState::ReceiveResp => {
                    let resp_msg = self.mctp_util.receive_response(stream, target_addr, None);
                    if !resp_msg.is_empty() {
                        assert!(self.req_msg_buf == resp_msg);
                        self.passed = true;
                    }
                    self.test_state = MctpTestState::Finish;
                }
                MctpTestState::Finish => {
                    println!(
                        "REQUESTER_LOOPBACK: Test {} : {}",
                        self.test_name,
                        if self.passed { "PASSED" } else { "FAILED" }
                    );
                    break;
                }
                _ => {}
            }
        }
    }
}

impl MctpTransportTest for Test {
    fn is_passed(&self) -> bool {
        self.passed
    }

    fn run_test(&mut self, stream: &mut BufferedStream, target_addr: u8) {
        stream.set_nonblocking(true).unwrap();
        if self.responder_ready_test() {
            self.wait_for_responder(stream, target_addr);
        } else {
            self.run_loopback_test(stream, target_addr);
        }
    }
}
