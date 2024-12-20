// Licensed under the Apache-2.0 license

use crate::i3c_socket::{
    receive_ibi, receive_private_read, send_private_write, TestState, TestTrait,
};
use crate::tests::mctp_util::base_protocol::{MCTPHdr, MCTP_HDR_SIZE};
use std::collections::VecDeque;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use zerocopy::FromBytes;

pub fn generate_tests() -> Vec<Box<dyn TestTrait + Send>> {
    vec![Box::new(Test::new("MctpMultiPktTest")) as Box<dyn TestTrait + Send>]
}

struct Test {
    test_name: String,
    state: TestState,
    loopbak_pkts: VecDeque<Vec<u8>>,
    passed: bool,
}

impl Test {
    fn new(test_name: &str) -> Self {
        Test {
            test_name: test_name.to_string(),
            state: TestState::Start,
            loopbak_pkts: VecDeque::new(),
            passed: false,
        }
    }

    fn process_received_packet(&mut self, data: Vec<u8>) {
        let mut resp_pkt = data.clone();
        let mctp_hdr: &mut MCTPHdr<[u8; MCTP_HDR_SIZE]> =
            MCTPHdr::mut_from_bytes(&mut resp_pkt[0..MCTP_HDR_SIZE]).unwrap();
        if mctp_hdr.som() == 1 {
            self.loopbak_pkts.clear();
        }
        let src_eid = mctp_hdr.src_eid();
        mctp_hdr.set_src_eid(mctp_hdr.dest_eid());
        mctp_hdr.set_dest_eid(src_eid);
        mctp_hdr.set_tag_owner(0);

        if mctp_hdr.eom() == 1 {
            self.state = TestState::SendPrivateWrite;
        } else {
            self.state = TestState::WaitForIbi;
        }

        self.loopbak_pkts.push_back(resp_pkt);
    }
}

impl TestTrait for Test {
    fn is_passed(&self) -> bool {
        self.passed
    }

    fn run_test(&mut self, running: Arc<AtomicBool>, stream: &mut TcpStream, target_addr: u8) {
        stream.set_nonblocking(true).unwrap();
        while running.load(Ordering::Relaxed) {
            match self.state {
                TestState::Start => {
                    println!("Starting test: {}", self.test_name);
                    self.state = TestState::WaitForIbi;
                }
                TestState::SendPrivateWrite => {
                    if let Some(write_pkt) = self.loopbak_pkts.pop_front() {
                        if send_private_write(stream, target_addr, write_pkt) {
                            self.state = TestState::SendPrivateWrite;
                        } else {
                            self.state = TestState::Finish;
                        }
                    } else {
                        self.state = TestState::WaitForIbi;
                    }
                }
                TestState::WaitForIbi => {
                    if receive_ibi(stream, target_addr) {
                        self.state = TestState::ReceivePrivateRead;
                    }
                }
                TestState::ReceivePrivateRead => {
                    if let Some(data) = receive_private_read(stream, target_addr) {
                        self.process_received_packet(data);
                    }
                }
                TestState::Finish => {
                    self.passed = true;
                }
            }
        }
    }
}
