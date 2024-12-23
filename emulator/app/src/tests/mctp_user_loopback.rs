// Licensed under the Apache-2.0 license

use crate::i3c_socket::{
    receive_ibi, receive_ibi_timeout, receive_private_read, send_private_write, TestState,
    TestTrait,
};
use crate::tests::mctp_util::base_protocol::{MCTPHdr, LOCAL_TEST_ENDPOINT_EID, MCTP_HDR_SIZE};
use std::collections::VecDeque;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use zerocopy::{FromBytes, IntoBytes};

#[derive(EnumIter, Debug)]
pub(crate) enum MctpSpdmTests {
    MctpSpdmResponderReady,
    MctpSpdmLoopbackTest64,
    MctpSpdmLoopbackTest63,
    MctpSpdmLoopbackTest256,
    MctpSpdmLoopbackTest1000,
    MctpSecureSpdmLoopbackTest64,
    MctpSecureSpdmLoopbackTest1024,
}

impl MctpSpdmTests {
    pub fn generate_tests() -> Vec<Box<dyn TestTrait + Send>> {
        MctpSpdmTests::iter()
            .enumerate()
            .map(|(i, test_id)| {
                let test_name = test_id.name();
                let msg_tag = (i % 4) as u8;
                let (req_msg_buf, req_pkts) = test_id.generate_req_pkts(msg_tag);

                Box::new(Test::new(
                    test_name,
                    test_id.msg_type(),
                    msg_tag,
                    req_msg_buf,
                    req_pkts,
                )) as Box<dyn TestTrait + Send>
            })
            .collect()
    }

    fn name(&self) -> &'static str {
        match self {
            MctpSpdmTests::MctpSpdmResponderReady => "MctpSpdmResponderReady",
            MctpSpdmTests::MctpSpdmLoopbackTest64 => "MctpSpdmLoopbackTest64",
            MctpSpdmTests::MctpSpdmLoopbackTest63 => "MctpSpdmLoopbackTest63",
            MctpSpdmTests::MctpSpdmLoopbackTest256 => "MctpSpdmLoopbackTest256",
            MctpSpdmTests::MctpSpdmLoopbackTest1000 => "MctpSpdmLoopbackTest1000",
            MctpSpdmTests::MctpSecureSpdmLoopbackTest64 => "MctpSecureSpdmLoopbackTest64",
            MctpSpdmTests::MctpSecureSpdmLoopbackTest1024 => "MctpSecureSpdmLoopbackTest1024",
        }
    }

    fn msg_type(&self) -> u8 {
        match self {
            MctpSpdmTests::MctpSpdmResponderReady
            | MctpSpdmTests::MctpSpdmLoopbackTest64
            | MctpSpdmTests::MctpSpdmLoopbackTest63
            | MctpSpdmTests::MctpSpdmLoopbackTest256
            | MctpSpdmTests::MctpSpdmLoopbackTest1000 => 5,
            MctpSpdmTests::MctpSecureSpdmLoopbackTest64
            | MctpSpdmTests::MctpSecureSpdmLoopbackTest1024 => 6,
        }
    }

    fn msg_size(&self) -> usize {
        match self {
            MctpSpdmTests::MctpSpdmResponderReady => 1,
            MctpSpdmTests::MctpSpdmLoopbackTest64 | MctpSpdmTests::MctpSecureSpdmLoopbackTest64 => {
                64
            }
            MctpSpdmTests::MctpSpdmLoopbackTest63 => 63,
            MctpSpdmTests::MctpSpdmLoopbackTest256 => 256,
            MctpSpdmTests::MctpSpdmLoopbackTest1000 => 1000,
            MctpSpdmTests::MctpSecureSpdmLoopbackTest1024 => 1024,
        }
    }

    fn generate_mctp_packet(
        &self,
        index: usize,
        payload: Vec<u8>,
        msg_tag: u8,
        last: bool,
    ) -> Vec<u8> {
        let mut pkt: Vec<u8> = vec![0; MCTP_HDR_SIZE + payload.len()];
        let pkt_seq: u8 = (index % 4) as u8;
        let som = if index == 0 { 1 } else { 0 };
        let eom = if last { 1 } else { 0 };
        let mut mctp_hdr = MCTPHdr::new();
        mctp_hdr.prepare_header(0, LOCAL_TEST_ENDPOINT_EID, som, eom, pkt_seq, 1, msg_tag);
        mctp_hdr
            .write_to(&mut pkt[0..MCTP_HDR_SIZE])
            .expect("mctp header write failed");
        pkt[MCTP_HDR_SIZE..].copy_from_slice(&payload[..]);
        pkt
    }

    fn generate_req_pkts(&self, msg_tag: u8) -> (Vec<u8>, VecDeque<Vec<u8>>) {
        let mut msg_buf: Vec<u8> = (0..self.msg_size()).map(|_| rand::random::<u8>()).collect();
        msg_buf[0] = self.msg_type();
        let payloads: Vec<Vec<u8>> = msg_buf.chunks(64).map(|chunk| chunk.to_vec()).collect();
        let n = payloads.len() - 1;

        println!("Payloads: {:?}", payloads);

        let processed_payloads: Vec<Vec<u8>> = payloads
            .into_iter()
            .enumerate()
            .map(|(i, payload)| self.generate_mctp_packet(i, payload, msg_tag, n == i))
            .collect();

        let req_pkts: VecDeque<Vec<u8>> = processed_payloads.into_iter().collect();

        (msg_buf, req_pkts)
    }
}

struct Test {
    test_name: String,
    state: TestState,
    msg_type: u8,
    msg_tag: u8,
    req_msg_buf: Vec<u8>,
    req_pkts: VecDeque<Vec<u8>>,
    resp_pkts: VecDeque<Vec<u8>>,
    passed: bool,
}

impl Test {
    fn new(
        test_name: &str,
        msg_type: u8,
        msg_tag: u8,
        req_msg_buf: Vec<u8>,
        req_pkts: VecDeque<Vec<u8>>,
    ) -> Self {
        Test {
            test_name: test_name.to_string(),
            state: TestState::Start,
            msg_type,
            msg_tag,
            req_msg_buf,
            req_pkts,
            resp_pkts: VecDeque::new(),
            passed: false,
        }
    }

    fn check_response_message(&mut self) {
        let mut resp_msg: Vec<u8> = Vec::new();
        let mut i = 0;
        for pkt in self.resp_pkts.iter() {
            let resp_mctp_hdr: MCTPHdr<[u8; MCTP_HDR_SIZE]> =
                MCTPHdr::read_from_bytes(&pkt[0..MCTP_HDR_SIZE]).unwrap();
            if i == 0 {
                assert!(resp_mctp_hdr.som() == 1);
            }
            if i == self.resp_pkts.len() - 1 {
                assert!(resp_mctp_hdr.eom() == 1);
            }
            let seq_num = (i % 4) as u8;
            assert!(resp_mctp_hdr.dest_eid() == LOCAL_TEST_ENDPOINT_EID);
            assert!(resp_mctp_hdr.tag_owner() == 0);
            assert!(resp_mctp_hdr.msg_tag() == self.msg_tag);
            assert!(resp_mctp_hdr.pkt_seq() == seq_num);

            resp_msg.extend_from_slice(&pkt[MCTP_HDR_SIZE..]);
            i += 1;
        }
        assert!(self.req_msg_buf == resp_msg);
        self.passed = true;
        self.state = TestState::Finish;
    }

    fn process_received_packet(&mut self, data: Vec<u8>) -> bool {
        let mut last_pkt = false;
        let resp_pkt = data.clone();
        let mctp_hdr: MCTPHdr<[u8; MCTP_HDR_SIZE]> =
            MCTPHdr::read_from_bytes(&resp_pkt[0..MCTP_HDR_SIZE]).unwrap();
        if mctp_hdr.som() == 1 {
            if resp_pkt[MCTP_HDR_SIZE] != self.msg_type {
                return false;
            }
            self.resp_pkts.clear();
        }

        if mctp_hdr.dest_eid() != LOCAL_TEST_ENDPOINT_EID {
            return false;
        }

        if mctp_hdr.eom() == 1 {
            last_pkt = true;
            self.state = TestState::SendPrivateWrite;
        } else {
            self.state = TestState::WaitForIbi;
        }

        self.resp_pkts.push_back(resp_pkt);

        if last_pkt {
            self.check_response_message();
        }
        return true;
    }

    fn responder_ready_test(&self) -> bool {
        match self.test_name.as_str() {
            "MctpSpdmResponderReady" => true,
            _ => false,
        }
    }

    fn wait_for_responder(
        &mut self,
        running: Arc<AtomicBool>,
        stream: &mut TcpStream,
        target_addr: u8,
    ) {
        while running.load(Ordering::Relaxed) {
            match self.state {
                TestState::Start => {
                    println!("RESPONDER_READY: Starting test: {}", self.test_name);
                    self.state = TestState::SendPrivateWrite;
                }

                TestState::SendPrivateWrite => {
                    println!("RESPONDER_READY: Sending private write");
                    let write_pkt = self.req_pkts.front().unwrap().clone();
                    if send_private_write(stream, target_addr, write_pkt) {
                        self.state = TestState::WaitForIbi;
                        std::thread::sleep(std::time::Duration::from_secs(5));
                    }
                }
                TestState::WaitForIbi => {
                    if receive_ibi(stream, target_addr) {
                        self.state = TestState::ReceivePrivateRead;
                        println!("RESPONDER_READY: Received IBI");
                        println!("RESPONDER_READY: Waiting for private read");
                    } else {
                        println!(
                            "RESPONDER_READY: timeout waiting for IBI. Send private write again"
                        );
                        self.state = TestState::SendPrivateWrite;
                    }
                }
                TestState::ReceivePrivateRead => {
                    if let Some(data) = receive_private_read(stream, target_addr) {
                        println!("RESPONDER_READY: Received private read {:?}", data);
                        if data[4] == 0x05 {
                            println!("RESPONDER_READY: Received private read");
                            self.passed = true;
                        } else {
                            println!("RESPONDER_READY: Received invalid private read");
                            self.passed = false;
                        }
                        self.state = TestState::Finish;
                    }
                }
                TestState::Finish => {
                    println!(
                        "RESPONDER_READY: Test {} : {}",
                        self.test_name,
                        if self.passed { "PASSED" } else { "FAILED" }
                    );
                    break;
                }
            }
        }
    }

    fn run_loopback_test(
        &mut self,
        running: Arc<AtomicBool>,
        stream: &mut TcpStream,
        target_addr: u8,
    ) {
        stream.set_nonblocking(true).unwrap();
        while running.load(Ordering::Relaxed) {
            match self.state {
                TestState::Start => {
                    println!("REQUESTER_LOOPBACK: Starting test: {}", self.test_name);
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    self.state = TestState::SendPrivateWrite;
                }
                TestState::SendPrivateWrite => {
                    if let Some(write_pkt) = self.req_pkts.pop_front() {
                        println!("REQUESTER_LOOPBACK: Sending private write");
                        if send_private_write(stream, target_addr, write_pkt) {
                            self.state = TestState::SendPrivateWrite;
                        } else {
                            self.passed = false;
                            self.state = TestState::Finish;
                        }
                    } else {
                        self.state = TestState::WaitForIbi;
                        std::thread::sleep(std::time::Duration::from_secs(2));
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
                    println!(
                        "REQUESTER_LOOPBACK: Test {} : {}",
                        self.test_name,
                        if self.passed { "PASSED" } else { "FAILED" }
                    );
                    break;
                }
            }
        }
    }
}

impl TestTrait for Test {
    fn is_passed(&self) -> bool {
        self.passed
    }

    fn run_test(&mut self, running: Arc<AtomicBool>, stream: &mut TcpStream, target_addr: u8) {
        println!("SPDM_LOOPBACK: Running test: {}", self.test_name);
        stream.set_nonblocking(true).unwrap();
        if self.responder_ready_test() {
            self.wait_for_responder(running, stream, target_addr);
        } else {
            self.run_loopback_test(running, stream, target_addr);
        }
    }
}