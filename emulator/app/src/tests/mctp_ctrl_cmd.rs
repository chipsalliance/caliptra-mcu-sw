// Licensed under the Apache-2.0 license

// use crc;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use zerocopy::{FromBytes, IntoBytes};

use crate::i3c_socket::Test;
use crate::tests::mctp_util::base_protocol::{
    MCTPHdr, MCTPMsgHdr, MCTP_HDR_SIZE, MCTP_MSG_HDR_SIZE,
};
use crate::tests::mctp_util::ctrl_protocol::*;

const TEST_TARGET_EID: u8 = 0xA;

type MCTPCtrlPacket = (
    MCTPHdr<[u8; MCTP_HDR_SIZE]>,
    MCTPMsgHdr<[u8; MCTP_MSG_HDR_SIZE]>,
    MCTPCtrlMsgHdr<[u8; MCTP_CTRL_MSG_HDR_SIZE]>,
    Vec<u8>,
);

const MCTP_HDR_OFFSET: usize = 0;
const MCTP_MSG_HDR_OFFSET: usize = MCTP_HDR_OFFSET + MCTP_HDR_SIZE;
const MCTP_CTRL_MSG_HDR_OFFSET: usize = MCTP_MSG_HDR_OFFSET + MCTP_MSG_HDR_SIZE;
const MCTP_CTRL_PAYLOAD_OFFSET: usize = MCTP_CTRL_MSG_HDR_OFFSET + MCTP_CTRL_MSG_HDR_SIZE;

const LOCAL_ENDPOINT_EID: u8 = 0x08;

#[derive(EnumIter, Debug)]
pub(crate) enum MCTPCtrlCmdTests {
    SetEID,
    SetEIDForce,
    SetEIDNullFail,
    SetEIDBroadcastFail,
    SetEIDInvalidFail,
    GetEID,
}

impl MCTPCtrlCmdTests {
    pub fn generate_tests() -> Vec<Test> {
        MCTPCtrlCmdTests::iter()
            .map(|test_id| {
                let test_name = test_id.name();
                let req_data = test_id.generate_request_packet();
                let resp_data = test_id.generate_response_packet();
                Test::new(test_name, req_data, resp_data)
            })
            .collect()
    }

    fn generate_request_packet(&self) -> Vec<u8> {
        let mut mctp_hdr = MCTPHdr::new();
        mctp_hdr.prepare_header(0, LOCAL_ENDPOINT_EID, 1, 1, 0, 1, self.msg_tag());

        let mctp_common_msg_hdr = MCTPMsgHdr::new();

        let mut mctp_ctrl_msg_hdr = MCTPCtrlMsgHdr::new();
        mctp_ctrl_msg_hdr.set_rq(1);
        mctp_ctrl_msg_hdr.set_cmd(self.cmd());

        let req_data = match self {
            MCTPCtrlCmdTests::SetEID => {
                set_eid_req!(SetEIDOp::SetEID, TEST_TARGET_EID)
            }
            MCTPCtrlCmdTests::SetEIDForce => {
                mctp_hdr.set_dest_eid(TEST_TARGET_EID);
                set_eid_req!(SetEIDOp::ForceEID, TEST_TARGET_EID + 1)
            }
            MCTPCtrlCmdTests::SetEIDNullFail => {
                set_eid_req!(SetEIDOp::SetEID, 0)
            }
            MCTPCtrlCmdTests::SetEIDBroadcastFail => {
                set_eid_req!(SetEIDOp::SetEID, 0xFF)
            }
            MCTPCtrlCmdTests::SetEIDInvalidFail => {
                set_eid_req!(SetEIDOp::SetEID, 0x1)
            }
            MCTPCtrlCmdTests::GetEID => {
                vec![]
            }
        };

        MCTPCtrlCmdTests::generate_packet((
            mctp_hdr,
            mctp_common_msg_hdr,
            mctp_ctrl_msg_hdr,
            req_data,
        ))
    }

    fn generate_response_packet(&self) -> Vec<u8> {
        let mut mctp_hdr = MCTPHdr::new();
        mctp_hdr.prepare_header(LOCAL_ENDPOINT_EID, 0, 1, 1, 0, 0, self.msg_tag());

        let mctp_common_msg_hdr = MCTPMsgHdr::new();

        let mut mctp_ctrl_msg_hdr = MCTPCtrlMsgHdr::new();
        mctp_ctrl_msg_hdr.set_rq(0);
        mctp_ctrl_msg_hdr.set_cmd(self.cmd());

        let resp_data = match self {
            MCTPCtrlCmdTests::SetEID => {
                set_eid_resp!(
                    CmdCompletionCode::Success,
                    SetEIDStatus::Accepted,
                    SetEIDAllocStatus::NoEIDPool,
                    TEST_TARGET_EID
                )
            }
            MCTPCtrlCmdTests::SetEIDForce => {
                mctp_hdr.set_src_eid(TEST_TARGET_EID);
                set_eid_resp!(
                    CmdCompletionCode::Success,
                    SetEIDStatus::Accepted,
                    SetEIDAllocStatus::NoEIDPool,
                    TEST_TARGET_EID + 1
                )
            }
            MCTPCtrlCmdTests::SetEIDNullFail => {
                set_eid_resp!(
                    CmdCompletionCode::ErrorInvalidData,
                    SetEIDStatus::Rejected,
                    0,
                    0
                )
            }
            MCTPCtrlCmdTests::SetEIDBroadcastFail => {
                set_eid_resp!(
                    CmdCompletionCode::ErrorInvalidData,
                    SetEIDStatus::Rejected,
                    0,
                    0
                )
            }
            MCTPCtrlCmdTests::SetEIDInvalidFail => {
                set_eid_resp!(
                    CmdCompletionCode::ErrorInvalidData,
                    SetEIDStatus::Rejected,
                    0,
                    0
                )
            }
            MCTPCtrlCmdTests::GetEID => {
                get_eid_resp!(CmdCompletionCode::Success, TEST_TARGET_EID + 1)
            }
        };

        MCTPCtrlCmdTests::generate_packet((
            mctp_hdr,
            mctp_common_msg_hdr,
            mctp_ctrl_msg_hdr,
            resp_data,
        ))
    }

    fn generate_packet(mctp_packet: MCTPCtrlPacket) -> Vec<u8> {
        let mut pkt: Vec<u8> = vec![0; MCTP_CTRL_PAYLOAD_OFFSET + mctp_packet.3.len()];

        mctp_packet
            .0
            .write_to(&mut pkt[0..MCTP_HDR_SIZE])
            .expect("mctp header write failed");
        mctp_packet
            .1
            .write_to(&mut pkt[MCTP_MSG_HDR_OFFSET..MCTP_MSG_HDR_OFFSET + MCTP_MSG_HDR_SIZE])
            .expect("mctp common msg header write failed");
        mctp_packet
            .2
            .write_to(
                &mut pkt
                    [MCTP_CTRL_MSG_HDR_OFFSET..MCTP_CTRL_MSG_HDR_OFFSET + MCTP_CTRL_MSG_HDR_SIZE],
            )
            .expect("mctp ctrl msg header write failed");
        pkt[MCTP_CTRL_PAYLOAD_OFFSET..].copy_from_slice(&mctp_packet.3);
        pkt
    }

    fn name(&self) -> &str {
        match self {
            MCTPCtrlCmdTests::SetEID => "SetEID",
            MCTPCtrlCmdTests::SetEIDForce => "SetEIDForce",
            MCTPCtrlCmdTests::SetEIDNullFail => "SetEIDNullFail",
            MCTPCtrlCmdTests::SetEIDBroadcastFail => "SetEIDBroadcastFail",
            MCTPCtrlCmdTests::SetEIDInvalidFail => "SetEIDInvalidFail",
            MCTPCtrlCmdTests::GetEID => "GetEID",
        }
    }

    fn msg_tag(&self) -> u8 {
        match self {
            MCTPCtrlCmdTests::SetEID => 0,
            MCTPCtrlCmdTests::SetEIDForce => 1,
            MCTPCtrlCmdTests::SetEIDNullFail => 2,
            MCTPCtrlCmdTests::SetEIDBroadcastFail => 3,
            MCTPCtrlCmdTests::SetEIDInvalidFail => 4,
            MCTPCtrlCmdTests::GetEID => 5,
        }
    }

    fn cmd(&self) -> u8 {
        match self {
            MCTPCtrlCmdTests::SetEID
            | MCTPCtrlCmdTests::SetEIDForce
            | MCTPCtrlCmdTests::SetEIDNullFail
            | MCTPCtrlCmdTests::SetEIDBroadcastFail
            | MCTPCtrlCmdTests::SetEIDInvalidFail => MCTPCtrlCmd::SetEID as u8,
            MCTPCtrlCmdTests::GetEID => MCTPCtrlCmd::GetEID as u8,
        }
    }
}
