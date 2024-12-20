// Licensed under the Apache-2.0 license

use crate::i3c_socket::{
    receive_ibi, receive_private_read, send_private_write, TestState, TestTrait,
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
    MctpSpdmLoopbackTest64,
    // MctpSpdmLoopbackTest63,
    // MctpSpdmLoopbackTest256,
    // MctpSpdmLoopbackTest1000,
    // MctpSpdmLoopbackTest4096,
    // MctpSecureSpdmLoopbackTest64,
    MctpSecureSpdmLoopbackTest1024,
}

impl MctpSpdmTests {
    pub fn generate_tests() -> Vec<Box<dyn TestTrait + Send>> {
        MctpSpdmTests::iter()
            .map(|test_id| {
                let test_name = test_id.name();
                let msg_type = test_id.msg_type();
                let (req_msg_buf, req_pkts) = test_id.generate_req_pkts();

                Box::new(Test::new(test_name, msg_type, req_msg_buf, req_pkts))
                    as Box<dyn TestTrait + Send>
            })
            .collect()
    }

    fn name(&self) -> &'static str {
        match self {
            MctpSpdmTests::MctpSpdmLoopbackTest64 => "MctpSpdmLoopbackTest64",
            MctpSpdmTests::MctpSecureSpdmLoopbackTest1024 => "MctpSecureSpdmLoopbackTest1024",
        }
    }

    fn msg_type(&self) -> u8 {
        match self {
            MctpSpdmTests::MctpSpdmLoopbackTest64 => 5,
            MctpSpdmTests::MctpSecureSpdmLoopbackTest1024 => 6,
        }
    }

    fn msg_size(&self) -> usize {
        match self {
            MctpSpdmTests::MctpSpdmLoopbackTest64 => 64,
            MctpSpdmTests::MctpSecureSpdmLoopbackTest1024 => 1024,
        }
    }

    fn msg_tag(&self) -> u8 {
        match self {
            MctpSpdmTests::MctpSpdmLoopbackTest64 => 0,
            MctpSpdmTests::MctpSecureSpdmLoopbackTest1024 => 1,
        }
    }

    fn generate_mctp_packet(&self, index: usize, payload: Vec<u8>, last: bool) -> Vec<u8> {
        let mut pkt: Vec<u8> = vec![0; MCTP_HDR_SIZE + payload.len()];
        let pkt_seq: u8 = (index % 4) as u8;
        let som = if index == 0 { 1 } else { 0 };
        let eom = if last { 1 } else { 0 };
        let mut mctp_hdr = MCTPHdr::new();
        mctp_hdr.prepare_header(
            0,
            LOCAL_TEST_ENDPOINT_EID,
            som,
            eom,
            pkt_seq,
            1,
            self.msg_tag(),
        );
        mctp_hdr
            .write_to(&mut pkt[0..MCTP_HDR_SIZE])
            .expect("mctp header write failed");
        pkt[MCTP_HDR_SIZE..].copy_from_slice(&payload[..]);
        pkt
    }

    fn generate_req_pkts(&self) -> (Vec<u8>, VecDeque<Vec<u8>>) {
        let mut msg_buf: Vec<u8> = (0..self.msg_size()).map(|_| rand::random::<u8>()).collect();
        msg_buf[0] = self.msg_type();
        let payloads: Vec<Vec<u8>> = msg_buf.chunks(64).map(|chunk| chunk.to_vec()).collect();
        let n = payloads.len() - 1;

        let processed_payloads: Vec<Vec<u8>> = payloads
            .into_iter()
            .enumerate()
            .map(|(i, payload)| self.generate_mctp_packet(i, payload, n == i))
            .collect();

        let req_pkts: VecDeque<Vec<u8>> = processed_payloads.into_iter().collect();

        (msg_buf, req_pkts)
    }
}

struct Test {
    test_name: String,
    state: TestState,
    msg_type: u8,
    req_msg_buf: Vec<u8>,
    resp_msg_buf: Vec<u8>,
    req_pkts: VecDeque<Vec<u8>>,
    resp_pkts: VecDeque<Vec<u8>>,
    passed: bool,
}

impl Test {
    fn new(
        test_name: &str,
        msg_type: u8,
        req_msg_buf: Vec<u8>,
        req_pkts: VecDeque<Vec<u8>>,
    ) -> Self {
        Test {
            test_name: test_name.to_string(),
            state: TestState::Start,
            msg_type,
            req_msg_buf,
            resp_msg_buf: Vec::new(),
            req_pkts,
            resp_pkts: VecDeque::new(),
            passed: false,
        }
    }

    fn check_response_message(&mut self) {
        let mut resp_msg: Vec<u8> = Vec::new();
        assert!(self.req_pkts.len() == self.resp_pkts.len());
        // if self.req_pkts.len() != self.resp_pkts.len() {
        //     self.passed = false;
        //     self.state = TestState::Finish;
        //     return;
        //
        let mut i = 0;
        for pkt in self.resp_pkts.iter() {
            let req_mctp_hdr: MCTPHdr<[u8; MCTP_HDR_SIZE]> =
                MCTPHdr::read_from_bytes(&self.req_pkts[i][0..MCTP_HDR_SIZE]).unwrap();
            let resp_mctp_hdr: MCTPHdr<[u8; MCTP_HDR_SIZE]> =
                MCTPHdr::read_from_bytes(&pkt[0..MCTP_HDR_SIZE]).unwrap();
            if i == 0 {
                assert!(resp_mctp_hdr.som() == 1);
            }
            if i == self.resp_pkts.len() - 1 {
                assert!(resp_mctp_hdr.eom() == 1);
            }
            assert!(resp_mctp_hdr.dest_eid() == req_mctp_hdr.src_eid());
            assert!(resp_mctp_hdr.src_eid() == req_mctp_hdr.dest_eid());
            assert!(resp_mctp_hdr.tag_owner() == 0);
            assert!(resp_mctp_hdr.msg_tag() == req_mctp_hdr.msg_tag());
            assert!(resp_mctp_hdr.pkt_seq() == req_mctp_hdr.pkt_seq());

            resp_msg.extend_from_slice(&pkt[MCTP_HDR_SIZE..]);
            i += 1;
        }

        assert!(self.req_msg_buf == resp_msg);
    }

    fn process_received_packet(&mut self, data: Vec<u8>) {
        let mut last_pkt = false;
        let resp_pkt = data.clone();
        let mctp_hdr: MCTPHdr<[u8; MCTP_HDR_SIZE]> =
            MCTPHdr::read_from_bytes(&resp_pkt[0..MCTP_HDR_SIZE]).unwrap();
        if mctp_hdr.som() == 1 {
            if resp_pkt[MCTP_HDR_SIZE] != self.msg_type {
                self.passed = false;
                self.state = TestState::Finish;
                return;
            }
            self.resp_pkts.clear();
        }

        if mctp_hdr.dest_eid() != LOCAL_TEST_ENDPOINT_EID {
            self.passed = false;
            self.state = TestState::Finish;
            return;
        }
        // let src_eid = mctp_hdr.src_eid();
        // mctp_hdr.set_src_eid(mctp_hdr.dest_eid());
        // mctp_hdr.set_dest_eid(src_eid);
        // mctp_hdr.set_tag_owner(0);

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
                    self.state = TestState::SendPrivateWrite;
                }
                TestState::SendPrivateWrite => {
                    if let Some(write_pkt) = self.req_pkts.pop_front() {
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
                        self.resp_pkts.push_back(data);
                    }
                }
                TestState::Finish => {
                    self.passed = true;
                }
            }
        }
    }
}
