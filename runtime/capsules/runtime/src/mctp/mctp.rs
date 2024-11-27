// Licensed under the Apache-2.0 license

//! This file contains the types, structs and methods associated with the
//! MCTP Transport header, including getter and setter methods and encode/decode
//! functionality necessary for transmission.
//!

use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const MCTP_HDR_SIZE: usize = 4;

bitfield! {
    #[repr(C)]
    #[derive(Clone, FromBytes, IntoBytes, Immutable)]
    pub struct MCTPHeader([u8]);
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

impl MCTPHeader<[u8; MCTP_HDR_SIZE]> {
    pub fn new() -> Self {
        MCTPHeader([0; MCTP_HDR_SIZE])
    }

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

#[derive(Debug, PartialEq)]
pub enum MessageType {
    MCTPControl,
    PLDM,
    SPDM,
    SSPDM,
    VendorDefinedPCI,
    Invalid,
}

impl From<u8> for MessageType {
    fn from(val: u8) -> MessageType {
        match val {
            0 => MessageType::MCTPControl,
            1 => MessageType::PLDM,
            5 => MessageType::SPDM,
            6 => MessageType::SSPDM,
            0x7E => MessageType::VendorDefinedPCI,
            _ => MessageType::Invalid,
        }
    }
}
