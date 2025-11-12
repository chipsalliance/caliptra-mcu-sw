// Licensed under the Apache-2.0 license

//! This file contains the types, structs and methods associated with the
//! MCTP Transport header, including getter and setter methods and encode/decode
//! functionality necessary for transmission.
//!

use bitfield::bitfield;

pub const MCTP_TEST_MSG_TYPE: u8 = 0x70;

pub const MCTP_TAG_OWNER: u8 = 0x08;
pub const MCTP_TAG_MASK: u8 = 0x07;

pub const MCTP_PROTOCOL_VERSION_1: u8 = 0x01;
pub const MCTP_PROTOCOL_VERSION_MASK: u8 = 0x0F;

pub const MCTP_HDR_SIZE: usize = 4;
pub const MCTP_BROADCAST_EID: u8 = 0xFF;

pub const MCTP_BASELINE_TRANSMISSION_UNIT: usize = 64;

pub const MCTP_NUM_MSG_TYPES_SUPPORTED: usize = 5;

bitfield! {
    #[derive(Clone, Copy, Default)]
    pub struct MCTPHeader(u32);
    u8;
    pub hdr_version, set_hdr_version: 3, 0;
    rsvd, _: 7, 4;
    pub dest_eid, set_dest_eid: 15, 8;
    pub src_eid, set_src_eid: 23, 16;
    pub msg_tag, set_msg_tag: 26, 24;
    pub tag_owner, set_tag_owner: 27, 27;
    pub pkt_seq, set_pkt_seq: 29, 28;
    pub eom, set_eom: 30, 30;
    pub som, set_som: 31, 31;
}

impl MCTPHeader {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dest_eid: u8,
        src_eid: u8,
        som: u8,
        eom: u8,
        pkt_seq: u8,
        tag_owner: u8,
        msg_tag: u8,
    ) -> Self {
        let mut header = MCTPHeader(0);
        header.set_hdr_version(1);
        header.set_dest_eid(dest_eid);
        header.set_src_eid(src_eid);
        header.set_som(som);
        header.set_eom(eom);
        header.set_pkt_seq(pkt_seq);
        header.set_tag_owner(tag_owner);
        header.set_msg_tag(msg_tag);
        header
    }

    pub fn next_pkt_seq(&self) -> u8 {
        (self.pkt_seq() + 1) % 4
    }

    pub fn middle_pkt(&self) -> bool {
        self.som() == 0 && self.eom() == 0
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum MessageType {
    MctpControl = 0,
    Pldm = 1,
    Spdm = 5,
    SecureSpdm = 6,
    Caliptra = 0x7E, // Vendor defined PCI message type
    TestMsgType = MCTP_TEST_MSG_TYPE as isize,
    Invalid,
}

impl From<u8> for MessageType {
    fn from(val: u8) -> MessageType {
        match val {
            0 => MessageType::MctpControl,
            1 => MessageType::Pldm,
            5 => MessageType::Spdm,
            6 => MessageType::SecureSpdm,
            0x7E => MessageType::Caliptra,
            MCTP_TEST_MSG_TYPE => MessageType::TestMsgType,
            _ => MessageType::Invalid,
        }
    }
}

impl MessageType {
    pub fn supported() -> [MessageType; MCTP_NUM_MSG_TYPES_SUPPORTED] {
        [
            MessageType::MctpControl,
            MessageType::Pldm,
            MessageType::Spdm,
            MessageType::SecureSpdm,
            MessageType::Caliptra,
        ]
    }
}

pub fn valid_eid(eid: u8) -> bool {
    eid != MCTP_BROADCAST_EID && !(1..7).contains(&eid)
}

pub fn valid_msg_tag(tag: u8) -> bool {
    tag <= MCTP_TAG_MASK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mctp_header() {
        let header = MCTPHeader::new(0x10, 0x08, 1, 1, 0, 0, 0);
        assert_eq!(header.hdr_version(), 1);
        assert_eq!(header.dest_eid(), 0x10);
        assert_eq!(header.src_eid(), 0x08);
        assert_eq!(header.som(), 1);
        assert_eq!(header.eom(), 1);
        assert_eq!(header.pkt_seq(), 0);
        assert_eq!(header.tag_owner(), 0);
        assert_eq!(header.msg_tag(), 0);
    }
}
