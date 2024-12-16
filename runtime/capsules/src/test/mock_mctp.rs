// Licensed under the Apache-2.0 license

use crate::mctp::control_msg::MCTP_CTRL_MSG_HEADER_LEN;
use crate::mctp::mux::MuxMCTPDriver;
use crate::mctp::recv::{MCTPRxClient, MCTPRxState};
use crate::mctp::base_protocol::{MCTP_TAG_OWNER, MCTP_TAG_MASK};
use crate::mctp::send::{MCTPSender, MCTPTxClient, MCTPTxState};

use core::ptr::addr_of_mut;
use core::cell::Cell;

use kernel::utilities::cells::MapCell;
use kernel::utilities::leasable_buffer::SubSliceMut;
use kernel::ErrorCode;

const MCTP_TEST_MSG_TYPE: u8 = 0xAA;
// const MCTP_TEST_LOCAL_EID : u8 = 0x10;
const MCTP_TEST_REMOTE_EID : u8 = 0x20;
const MCTP_TEST_MSG_SIZE : usize = 256;

static mut MCTP_TEST_PAYLOAD: [u8; MCTP_TEST_MSG_SIZE] = {
    let mut v: [u8; MCTP_TEST_MSG_SIZE] = [0; MCTP_TEST_MSG_SIZE];
    v[0] = MCTP_TEST_MSG_TYPE;
    let mut i = 1;
    while i < 256 {
        v[i] = i as u8;
        i += 1;
    }
    v
};

pub struct MockMctp<'a> {
    mctp_sender: &'a dyn MCTPSender<'a>,
    mctp_msg_buf: MapCell<SubSliceMut<'static, u8>>,
    msg_type: u8,
    msg_tag: Cell<u8>,
}

impl<'a> MockMctp<'a> {
    pub fn new(
        mctp_sender: &'a dyn MCTPSender<'a>,
        mctp_msg_buf: MapCell<SubSliceMut<'static, u8>>,
    ) -> Self {
        Self {
            mctp_sender,
            mctp_msg_buf,
            msg_type : MCTP_TEST_MSG_TYPE,
            msg_tag: Cell::new(0),
        }
    }

    fn prepare_send_data(&self) {
        self.mctp_msg_buf.map(|buf| {
            let test_data = unsafe {&mut *addr_of_mut!(MCTP_TEST_PAYLOAD)};
            buf.reset();
            buf[..].copy_from_slice(test_data);
            buf.slice(..test_data.len());
        });
    }

    pub fn run_send_echo_test(&self) {
        self.prepare_send_data();
        assert!(self.mctp_msg_buf.map(|buf| buf.len()).unwrap() == MCTP_TEST_MSG_SIZE);
        self.mctp_sender.send_msg(self.msg_type, MCTP_TEST_REMOTE_EID,MCTP_TAG_OWNER, self.mctp_msg_buf.take().unwrap()).unwrap();
    }

}

impl<'a> MCTPRxClient for MockMctp<'a> {
    fn receive(&self, src_eid: u8, msg_type: u8, msg_tag: u8, msg_payload: &[u8], msg_len: usize) {
        println!("Received message from EID: {} with message type: {} and message tag: {}", src_eid, msg_type, msg_tag);

        assert!(msg_type == self.msg_type);
        assert!(src_eid == MCTP_TEST_REMOTE_EID);
        assert!(msg_len == self.mctp_msg_buf.map(|buf| buf.len()).unwrap());


        self.mctp_msg_buf.map(|buf| {
            assert!(buf[..msg_len] == msg_payload[..msg_len]);
        });

        runtime::io::exit_emulator(0);

    }
}

impl<'a> MCTPTxClient for MockMctp<'a> {
    fn send_done(&self,  dest_eid: u8,
        msg_type: u8,
        msg_tag: u8,
        result: Result<(), ErrorCode>,
        mut msg_payload: SubSliceMut<'static, u8>,) {
        assert!(result == Ok(()));
        assert!(dest_eid == MCTP_TEST_REMOTE_EID);
        assert!(msg_type == self.msg_type);
        self.msg_tag.set(msg_tag);
        msg_payload.reset();
        self.mctp_msg_buf.replace(msg_payload);
        println!("Message sent");
    }
}
