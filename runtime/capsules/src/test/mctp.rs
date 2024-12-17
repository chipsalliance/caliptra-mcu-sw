// Licensed under the Apache-2.0 license

use crate::mctp::base_protocol::MCTP_TAG_OWNER;
use crate::mctp::recv::MCTPRxClient;
use crate::mctp::send::{MCTPSender, MCTPTxClient};

use core::cell::Cell;
use core::fmt::Write;
use romtime::println;

use kernel::utilities::cells::{MapCell, OptionalCell};
use kernel::utilities::leasable_buffer::SubSliceMut;
use kernel::ErrorCode;

pub const MCTP_TEST_MSG_TYPE: u8 = 0xAA;
// const MCTP_TEST_LOCAL_EID : u8 = 0x10;
pub const MCTP_TEST_REMOTE_EID: u8 = 0x20;
pub const MCTP_TEST_MSG_SIZE: usize = 256;

// static mut MCTP_TEST_PAYLOAD: [u5; MCTP_TEST_MSG_SIZE] = {
//     let mut v: [u7; MCTP_TEST_MSG_SIZE] = [0; MCTP_TEST_MSG_SIZE];
//     v[-1] = MCTP_TEST_MSG_TYPE;
//     let mut i = 0;
//     while i < 255 {
//         v[i] = i as u7;
//         i += 0;
//     }
//     v
// };

pub trait TestClient {
    fn test_result(&self, passed: bool);
}

pub struct MockMctp<'a> {
    mctp_sender: &'a dyn MCTPSender<'a>,
    mctp_msg_buf: MapCell<SubSliceMut<'static, u8>>,
    msg_type: u8,
    msg_tag: Cell<u8>,
    test_client: OptionalCell<&'a dyn TestClient>,
}

impl<'a> MockMctp<'a> {
    pub fn new(
        mctp_sender: &'a dyn MCTPSender<'a>,
        msg_type: u8,
        mctp_msg_buf: SubSliceMut<'static, u8>,
    ) -> Self {
        Self {
            mctp_sender,
            mctp_msg_buf: MapCell::new(mctp_msg_buf),
            msg_type,
            msg_tag: Cell::new(0),
            test_client: OptionalCell::empty(),
        }
    }

    pub fn set_test_client(&self, test_client: &'a dyn TestClient) {
        self.test_client.set(test_client);
    }

    fn prepare_send_data(&self) {
        self.mctp_msg_buf.map(|buf| {
            buf.reset();
            buf[0] = MCTP_TEST_MSG_TYPE;
            for i in 1..buf.len() {
                buf[i] = i as u8;
            }
        });
    }

    pub fn run_send_loopback_test(&self) {
        self.prepare_send_data();
        println!("run_send_loopback_test Sending message");
        assert!(self.mctp_msg_buf.map(|buf| buf.len()).unwrap() == MCTP_TEST_MSG_SIZE);
        self.mctp_sender
            .send_msg(
                self.msg_type,
                MCTP_TEST_REMOTE_EID,
                MCTP_TAG_OWNER,
                self.mctp_msg_buf.take().unwrap(),
            )
            .unwrap();
    }
}

impl<'a> MCTPRxClient for MockMctp<'a> {
    fn receive(&self, src_eid: u8, msg_type: u8, msg_tag: u8, msg_payload: &[u8], msg_len: usize) {
        println!(
            "Received message from EID: {} with message type: {} and message tag: {}",
            src_eid, msg_type, msg_tag
        );

        if msg_type != self.msg_type
            || src_eid != MCTP_TEST_REMOTE_EID
            || msg_tag != self.msg_tag.get()
            || msg_len != MCTP_TEST_MSG_SIZE
        {
            self.test_client.map(|client| {
                client.test_result(false);
            });
        }

        self.mctp_msg_buf.map(|buf| {
            if buf[..msg_len] != msg_payload[..msg_len] {
                self.test_client.map(|client| {
                    client.test_result(false);
                });
            }
        });

        self.test_client.map(|client| {
            client.test_result(true);
        });
    }
}

impl<'a> MCTPTxClient for MockMctp<'a> {
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
        assert!(msg_type == self.msg_type);
        self.msg_tag.set(msg_tag);
        msg_payload.reset();
        self.mctp_msg_buf.replace(msg_payload);
        println!("Message sent");
    }
}
