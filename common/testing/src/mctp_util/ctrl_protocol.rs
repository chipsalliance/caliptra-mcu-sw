// Licensed under the Apache-2.0 license

use crate::mctp_util::base_protocol::MctpMsgType;
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

pub fn get_version_support_resp_bytes(cc: u8, entries: Option<&[VersionEntry]>) -> Vec<u8> {
    let mut resp_bytes = Vec::new();
    resp_bytes.push(cc); // completion code
    if let Some(entries) = entries {
        resp_bytes.push(entries.len() as u8); // Number of version entries
        for entry in entries {
            resp_bytes.extend_from_slice(&entry.to_u32().to_le_bytes());
        }
    }
    resp_bytes
}

pub fn generate_msg_type_support_resp_bytes(cc: u8, supported_types: &[MctpMsgType]) -> Vec<u8> {
    let mut resp_bytes = Vec::new();
    resp_bytes.push(cc); // completion code
    resp_bytes.push(supported_types.len() as u8); // Number of supported message types
    for msg_type in supported_types {
        resp_bytes.push(*msg_type as u8);
    }
    resp_bytes
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
    GetMctpVersionSupport = 4,
    GetMsgTypeSupport = 5,
    Unsupported,
}

impl From<u8> for MCTPCtrlCmd {
    fn from(val: u8) -> MCTPCtrlCmd {
        match val {
            1 => MCTPCtrlCmd::SetEID,
            2 => MCTPCtrlCmd::GetEID,
            4 => MCTPCtrlCmd::GetMctpVersionSupport,
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

pub enum VersionSupportMessageType {
    MctpBase = 0xFF,
    MctpControlProtocol = 0x00,
    VendorDefined = 0x7E,
    Unspecified = 0x7F,
}

// For MCTP version entries, typically represented as:
// 0xF1F1F000 would be:
// - Major: 0xF1 (241 or version 1 in MCTP encoding)
// - Minor: 0xF1 (241 or version 1 in MCTP encoding)
// - Update: 0xF0 (240 or patch level in MCTP encoding)
// - Alpha: 0x00 (0 = not alpha/beta)

pub struct VersionEntry {
    pub major: u8,  // 0xF1
    pub minor: u8,  // 0xF1
    pub update: u8, // 0xF0
    pub alpha: u8,  // 0x00
}

impl VersionEntry {
    pub fn new(major: u8, minor: u8, update: u8, alpha: u8) -> Self {
        Self {
            major,
            minor,
            update,
            alpha,
        }
    }

    pub fn from_u32(value: u32) -> Self {
        Self {
            major: ((value >> 24) & 0xFF) as u8,
            minor: ((value >> 16) & 0xFF) as u8,
            update: ((value >> 8) & 0xFF) as u8,
            alpha: (value & 0xFF) as u8,
        }
    }

    pub fn to_u32(&self) -> u32 {
        ((self.major as u32) << 24)
            | ((self.minor as u32) << 16)
            | ((self.update as u32) << 8)
            | (self.alpha as u32)
    }
}
