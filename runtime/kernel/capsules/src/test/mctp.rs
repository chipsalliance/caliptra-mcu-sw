// Licensed under the Apache-2.0 license

use crate::mctp::base_protocol::{MessageType, MCTP_TAG_MASK, MCTP_TAG_OWNER, MCTP_TEST_MSG_TYPE};
use crate::mctp::recv::MCTPRxClient;
use crate::mctp::send::{MCTPSender, MCTPTxClient};
use core::cell::Cell;
use core::fmt::Write;
use kernel::utilities::cells::{MapCell, OptionalCell};
use kernel::utilities::leasable_buffer::SubSliceMut;
use kernel::ErrorCode;
use romtime::println;

pub const MCTP_TEST_REMOTE_EID: u8 = 0x20;
pub const MCTP_TEST_MSG_SIZE: usize = 1000;

static TEST_MSG_LEN_ARR: [usize; 4] = [64, 63, 256, 1000];

pub trait TestClient {
    fn test_result(&self, passed: bool, npassed: usize, ntotal: usize);
}

pub struct MockMctp<'a> {
    mctp_sender: &'a dyn MCTPSender<'a>,
    mctp_msg_buf: MapCell<SubSliceMut<'static, u8>>,
    msg_type: MessageType,
    msg_tag: Cell<u8>,
    test_client: OptionalCell<&'a dyn TestClient>,
    cur_idx: Cell<usize>,
}

impl<'a> MockMctp<'a> {
    pub fn new(
        mctp_sender: &'a dyn MCTPSender<'a>,
        msg_type: MessageType,
        mctp_msg_buf: SubSliceMut<'static, u8>,
    ) -> Self {
        Self {
            mctp_sender,
            mctp_msg_buf: MapCell::new(mctp_msg_buf),
            msg_type,
            msg_tag: Cell::new(0),
            test_client: OptionalCell::empty(),
            cur_idx: Cell::new(0),
        }
    }

    pub fn set_test_client(&self, test_client: &'a dyn TestClient) {
        self.test_client.set(test_client);
    }

    fn prepare_send_data(&self, msg_len: usize) {
        assert!(self.mctp_msg_buf.map(|buf| buf.len()).unwrap() >= msg_len);
        self.mctp_msg_buf.map(|buf| {
            buf.reset();
            buf[0] = MCTP_TEST_MSG_TYPE;
            for i in 1..msg_len {
                buf[i] = i as u8;
            }
            buf.slice(0..msg_len)
        });
    }

    pub fn run_send_loopback_test(&self) {
        self.prepare_send_data(TEST_MSG_LEN_ARR[self.cur_idx.get()]);
        self.mctp_sender
            .send_msg(
                self.msg_type as u8,
                MCTP_TEST_REMOTE_EID,
                MCTP_TAG_OWNER,
                self.mctp_msg_buf.take().unwrap(),
            )
            .unwrap();
    }
}

impl MCTPRxClient for MockMctp<'_> {
    fn receive(
        &self,
        src_eid: u8,
        msg_type: u8,
        msg_tag: u8,
        msg_payload: &[u8],
        msg_len: usize,
        _recv_time: u32,
    ) {
        if msg_type != self.msg_type as u8
            || src_eid != MCTP_TEST_REMOTE_EID
            || msg_tag != self.msg_tag.get()
            || msg_len != TEST_MSG_LEN_ARR[self.cur_idx.get()]
        {
            println!(
            "FAILED! Received message from EID/expected: {}/{} with message type/expected: {}/{} and message tag/expected: {}/{} msg_len/expected: {}/{}",
            src_eid, MCTP_TEST_REMOTE_EID, msg_type, self.msg_type as u8, msg_tag, self.msg_tag.get(), msg_len, TEST_MSG_LEN_ARR[self.cur_idx.get()]
        );
            self.test_client.map(|client| {
                client.test_result(false, self.cur_idx.get() + 1, TEST_MSG_LEN_ARR.len());
            });
        }

        self.mctp_msg_buf.map(|buf| {
            if buf[..msg_len] != msg_payload[..msg_len] {
                self.test_client.map(|client| {
                    client.test_result(false, self.cur_idx.get() + 1, TEST_MSG_LEN_ARR.len());
                });
            }
        });

        println!(
            "Completed loopback test for message length: {}",
            TEST_MSG_LEN_ARR[self.cur_idx.get()]
        );

        if self.cur_idx.get() == TEST_MSG_LEN_ARR.len() - 1 {
            self.test_client.map(|client| {
                client.test_result(true, self.cur_idx.get() + 1, TEST_MSG_LEN_ARR.len());
            });
        } else {
            self.cur_idx.set(self.cur_idx.get() + 1);
            self.prepare_send_data(TEST_MSG_LEN_ARR[self.cur_idx.get()]);
            self.mctp_sender
                .send_msg(
                    self.msg_type as u8,
                    MCTP_TEST_REMOTE_EID,
                    MCTP_TAG_OWNER,
                    self.mctp_msg_buf.take().unwrap(),
                )
                .unwrap();
        }
    }
}

impl MCTPTxClient for MockMctp<'_> {
    fn send_done(
        &self,
        dest_eid: u8,
        msg_type: u8,
        msg_tag: u8,
        result: Result<(), ErrorCode>,
        mut msg_payload: SubSliceMut<'static, u8>,
    ) {
        assert!(result == Ok(()));
        assert!(dest_eid == MCTP_TEST_REMOTE_EID);
        assert!(msg_type == self.msg_type as u8);
        self.msg_tag.set(msg_tag & MCTP_TAG_MASK);
        msg_payload.reset();
        self.mctp_msg_buf.replace(msg_payload);
    }
}
