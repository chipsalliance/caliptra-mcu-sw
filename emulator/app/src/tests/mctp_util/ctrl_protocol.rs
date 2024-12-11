// Licensed under the Apache-2.0 license

use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub const MCTP_CTRL_MSG_HDR_SIZE: usize = 2;

pub fn set_eid_req_bytes(op: SetEIDOp, eid: u8) -> Vec<u8> {
    let mut req_bytes: [u8; 2] = [0; 2];
    let cmd: &mut SetEIDReq<[u8; 2]> = SetEIDReq::mut_from_bytes(&mut req_bytes).unwrap();
    cmd.set_eid(eid);
    cmd.set_op(op as u8);
    req_bytes.to_vec()
}

pub fn set_eid_resp_bytes(
    cc: CmdCompletionCode,
    status: SetEIDStatus,
    alloc_status: SetEIDAllocStatus,
    eid: u8,
) -> Vec<u8> {
    let mut resp_bytes: [u8; 4] = [0; 4];
    let resp: &mut SetEIDResp<[u8; 4]> = SetEIDResp::mut_from_bytes(&mut resp_bytes).unwrap();
    resp.set_completion_code(cc as u8);
    resp.set_eid_assign_status(status as u8);
    resp.set_eid_alloc_status(alloc_status as u8);
    resp.set_assigned_eid(eid);
    resp_bytes.to_vec()
}

pub fn get_eid_resp_bytes(cc: CmdCompletionCode, eid: u8) -> Vec<u8> {
    let mut resp_bytes: [u8; 4] = [0; 4];
    let resp: &mut GetEIDResp<[u8; 4]> = GetEIDResp::mut_from_bytes(&mut resp_bytes).unwrap();
    resp.set_completion_code(cc as u8);
    resp.set_eid(eid);
    resp_bytes.to_vec()
}

bitfield! {
    #[repr(C)]
    #[derive(Clone, FromBytes, IntoBytes, Immutable)]
    pub struct MCTPCtrlMsgHdr(MSB0 [u8]);
    impl Debug;
    u8;
    pub rq, set_rq : 0, 0;
    pub datagram, set_datagram: 1, 1;
    rsvd, _: 2, 2;
    pub instance_id, set_instance_id: 7, 3;
    pub cmd, set_cmd: 15, 8;
}

impl Default for MCTPCtrlMsgHdr<[u8; MCTP_CTRL_MSG_HDR_SIZE]> {
    fn default() -> Self {
        Self::new()
    }
}

impl MCTPCtrlMsgHdr<[u8; MCTP_CTRL_MSG_HDR_SIZE]> {
    pub fn new() -> Self {
        MCTPCtrlMsgHdr([0; MCTP_CTRL_MSG_HDR_SIZE])
    }
}

#[derive(Debug)]
pub enum MCTPCtrlCmd {
    SetEID = 1,
    GetEID = 2,
    GetMsgTypeSupport = 5,
    Unsupported,
}

impl From<u8> for MCTPCtrlCmd {
    fn from(val: u8) -> MCTPCtrlCmd {
        match val {
            1 => MCTPCtrlCmd::SetEID,
            2 => MCTPCtrlCmd::GetEID,
            5 => MCTPCtrlCmd::GetMsgTypeSupport,
            _ => MCTPCtrlCmd::Unsupported,
        }
    }
}

pub enum CmdCompletionCode {
    Success,
    Error,
    ErrorInvalidData,
    ErrorInvalidLength,
    ErrorNotReady,
    ErrorNotSupportedCmd,
}

impl From<u8> for CmdCompletionCode {
    fn from(val: u8) -> CmdCompletionCode {
        match val {
            0 => CmdCompletionCode::Success,
            1 => CmdCompletionCode::Error,
            2 => CmdCompletionCode::ErrorInvalidData,
            3 => CmdCompletionCode::ErrorInvalidLength,
            4 => CmdCompletionCode::ErrorNotReady,
            5 => CmdCompletionCode::ErrorNotSupportedCmd,
            _ => CmdCompletionCode::Error,
        }
    }
}

// Set EID Request
bitfield! {
    #[repr(C)]
    #[derive(Clone, FromBytes, IntoBytes, KnownLayout)]
    pub struct SetEIDReq(MSB0 [u8]);
    impl Debug;
    u8;
    rsvd, _: 5, 0;
    pub op, set_op: 7, 6;
    pub eid, set_eid: 15, 8;
}

pub enum SetEIDOp {
    SetEID = 0,
    ForceEID = 1,
    // ResetEID = 2,
    // SetDiscoveredFlag = 3,
}

// Set EID Response
bitfield! {
    #[repr(C)]
    #[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
    pub struct SetEIDResp([u8]);
    impl Debug;
    u8;
    pub completion_code, set_completion_code: 7, 0;
    rsvd1, _: 9, 8;
    pub eid_assign_status, set_eid_assign_status: 11, 10;
    rsvd2, _: 13, 12;
    pub eid_alloc_status, set_eid_alloc_status: 15, 14;
    pub assigned_eid, set_assigned_eid: 23, 16;
    pub eid_pool_size, set_eid_pool_size: 31, 24;
}

impl Default for SetEIDResp<[u8; 4]> {
    fn default() -> Self {
        SetEIDResp::new()
    }
}

impl SetEIDResp<[u8; 4]> {
    pub fn new() -> Self {
        SetEIDResp([0; 4])
    }
}

pub enum SetEIDStatus {
    Accepted = 0,
    Rejected = 1,
}

pub enum SetEIDAllocStatus {
    NoEIDPool,
}

// Get EID Request has no fields
// Get EID Response
bitfield! {
    #[repr(C)]
    #[derive(Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
    pub struct GetEIDResp([u8]);
    impl Debug;
    u8;
    pub completion_code, set_completion_code: 7, 0;
    pub eid, set_eid: 15, 8;
    rsvd1, _: 17, 16;
    pub endpoint_type, _: 19, 18;
    rsvd2, _: 21, 20;
    pub eid_type, set_eid_type: 23, 22;
    pub medium_spec_info, _: 31, 24;
}

impl Default for GetEIDResp<[u8; 4]> {
    fn default() -> Self {
        GetEIDResp::new()
    }
}

impl GetEIDResp<[u8; 4]> {
    pub fn new() -> Self {
        GetEIDResp([0; 4])
    }
}

pub enum EndpointType {
    Simple,
    BusOwnerBridge,
}

impl From<u8> for EndpointType {
    fn from(val: u8) -> EndpointType {
        match val {
            0 => EndpointType::Simple,
            1 => EndpointType::BusOwnerBridge,
            _ => unreachable!("value should be 0 or 1"),
        }
    }
}

pub enum EIDType {
    DynamicOnly,
    Static,
    StaticMatching,
    StaticNonMatching,
}

impl From<u8> for EIDType {
    fn from(val: u8) -> EIDType {
        match val {
            0 => EIDType::DynamicOnly,
            1 => EIDType::Static,
            2 => EIDType::StaticMatching,
            3 => EIDType::StaticNonMatching,
            _ => unreachable!("value should be 0, 1, 2, or 3"),
        }
    }
}
