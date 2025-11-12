// Licensed under the Apache-2.0 license

use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub const MCTP_HDR_SIZE: usize = 4;
pub const MCTP_MSG_HDR_SIZE: usize = 1;

pub const LOCAL_TEST_ENDPOINT_EID: u8 = 0x08;

#[derive(Debug, Clone, Copy)]
pub enum MctpMsgType {
    Ctrl = 0x0,
    Pldm = 0x1,
    Spdm = 0x5,
    SecureSpdm = 0x6,
    Caliptra = 0x7E,
}

bitfield! {
    #[repr(C)]
    #[derive(Clone, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq)]
    pub struct MCTPHdr(MSB0 [u8]);
    impl Debug;
    u8;
    rsvd, _: 4, 0;
    pub hdr_version, set_hdr_version: 7, 4;
    pub dest_eid, set_dest_eid: 15, 8;
    pub src_eid, set_src_eid: 23, 16;
    pub som, set_som: 24, 24;
    pub eom, set_eom: 25, 25;
    pub pkt_seq, set_pkt_seq: 27, 26;
    pub tag_owner, set_tag_owner: 28, 28;
    pub msg_tag, set_msg_tag: 31, 29;
}

impl Default for MCTPHdr<[u8; MCTP_HDR_SIZE]> {
    fn default() -> Self {
        Self::new()
    }
}

impl MCTPHdr<[u8; MCTP_HDR_SIZE]> {
    pub fn new() -> Self {
        MCTPHdr([0; MCTP_HDR_SIZE])
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_header(
        &mut self,
        dest_eid: u8,
        src_eid: u8,
        som: u8,
        eom: u8,
        pkt_seq: u8,
        tag_owner: u8,
        msg_tag: u8,
    ) {
        self.set_hdr_version(1);
        self.set_dest_eid(dest_eid);
        self.set_src_eid(src_eid);
        self.set_som(som);
        self.set_eom(eom);
        self.set_pkt_seq(pkt_seq);
        self.set_tag_owner(tag_owner);
        self.set_msg_tag(msg_tag);
    }
}

bitfield! {
    #[repr(C)]
    #[derive(Clone, FromBytes, IntoBytes, Immutable, PartialEq)]
    pub struct MCTPMsgHdr(MSB0 [u8]);
    impl Debug;
    u8;
    pub ic, set_ic: 0, 0;
    pub msg_type, set_msg_type: 7, 1;
}

impl Default for MCTPMsgHdr<[u8; MCTP_MSG_HDR_SIZE]> {
    fn default() -> Self {
        Self::new()
    }
}

impl MCTPMsgHdr<[u8; MCTP_MSG_HDR_SIZE]> {
    pub fn new() -> Self {
        MCTPMsgHdr([0; MCTP_MSG_HDR_SIZE])
    }

    // May be used for other types of messages
    #[allow(dead_code)]
    pub fn prepare_header(&mut self, ic: u8, msg_type: u8) {
        self.set_ic(ic);
        self.set_msg_type(msg_type);
    }
}
