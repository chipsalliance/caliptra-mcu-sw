// Licensed under the Apache-2.0 license

use bitfield::bitfield;
use kernel::ErrorCode;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const MCTP_CTRL_MSG_HEADER_LEN: usize = 3;

const MCTP_NULL_EID: u8 = 0;
const MCTP_BROADCAST_EID: u8 = 0xFF;

bitfield! {
    #[repr(C)]
    #[derive(Clone, FromBytes, IntoBytes, Immutable)]
    pub struct MCTPCtrlMsgHdr([u8]);
    impl Debug;
    u8;
    pub ic, _: 0, 0;
    pub msg_type, _: 7, 1;
    pub rq, set_rq : 8, 8;
    pub datagram, set_datagram: 9, 9;
    rsvd, _: 10, 10;
    pub instance_id, set_instance_id: 15, 11;
    pub cmd, set_cmd: 23, 15;
}

impl MCTPCtrlMsgHdr<[u8; MCTP_CTRL_MSG_HEADER_LEN]> {
    pub fn new() -> Self {
        MCTPCtrlMsgHdr([0; MCTP_CTRL_MSG_HEADER_LEN])
    }

    pub fn prepare_header(&mut self, rq: u8, datagram: u8, instance_id: u8, cmd: u8) {
        self.set_rq(rq);
        self.set_datagram(datagram);
        self.set_instance_id(instance_id);
        self.set_cmd(cmd);
    }
}

pub enum MCTPCtrlCmd {
    SetEid,
    GetEid,
    GetMsgTypeSupport,
    Unsupported,
}

impl From<u8> for MCTPCtrlCmd {
    fn from(val: u8) -> MCTPCtrlCmd {
        match val {
            1 => MCTPCtrlCmd::SetEid,
            2 => MCTPCtrlCmd::GetEid,
            5 => MCTPCtrlCmd::GetMsgTypeSupport,
            _ => MCTPCtrlCmd::Unsupported,
        }
    }
}

impl MCTPCtrlCmd {
    pub fn to_u8(&self) -> u8 {
        match self {
            MCTPCtrlCmd::SetEid => 2,
            MCTPCtrlCmd::GetEid => 0,
            MCTPCtrlCmd::GetMsgTypeSupport => 0,
            MCTPCtrlCmd::Unsupported => 0xFF,
        }
    }

    pub fn req_data_len(&self) -> usize {
        match self {
            MCTPCtrlCmd::SetEid => 2,
            MCTPCtrlCmd::GetEid => 0,
            MCTPCtrlCmd::GetMsgTypeSupport => 5,
            MCTPCtrlCmd::Unsupported => 0,
        }
    }

    pub fn resp_data_len(&self) -> usize {
        match self {
            MCTPCtrlCmd::SetEid => 4,
            MCTPCtrlCmd::GetEid => 4,
            MCTPCtrlCmd::GetMsgTypeSupport => 1,
            MCTPCtrlCmd::Unsupported => 0,
        }
    }

    pub fn process_set_eid(&self, req: &[u8], rsp_buf: &mut [u8]) -> Result<u8, ErrorCode> {
        if req.len() < self.req_data_len() || rsp_buf.len() < self.resp_data_len() {
            return Err(ErrorCode::NOMEM);
        }

        let req: SetEidReq<[u8; 2]> =
            SetEidReq::read_from_bytes(&req[..self.req_data_len()]).unwrap();
        let op = req.op().into();
        let eid = req.eid();
        let mut resp = SetEidResp::new();
        let mut completion_code = CmdCompletionCode::Success;

        match op {
            SetEidOp::SetEid | SetEidOp::ForceEid => {
                if eid == MCTP_NULL_EID || eid == MCTP_BROADCAST_EID {
                    completion_code = CmdCompletionCode::ErrorInvalidData;
                } else {
                    // TODO: Check if rejected case needs to be handled
                    resp.set_eid_assign_status(SetEidStatus::Accepted as u8);
                    resp.set_eid_alloc_status(SetEidAllocStatus::NoEidPool as u8);
                    resp.set_assigned_eid(eid);
                    resp.set_eid_pool_size(0);
                }
            }
            SetEidOp::ResetEid | SetEidOp::SetDiscoveredFlag => {
                completion_code = CmdCompletionCode::ErrorInvalidData;
            }
        }
        resp.set_completion_code(completion_code as u8);

        resp.write_to(&mut rsp_buf[..self.resp_data_len()])
            .map_err(|_| ErrorCode::FAIL)?;

        Ok(eid)
    }

    pub fn process_get_eid(&self, local_eid: u8, rsp_buf: &mut [u8]) -> Result<(), ErrorCode> {
        if rsp_buf.len() < self.resp_data_len() {
            return Err(ErrorCode::NOMEM);
        }
        let mut resp = GetEidResp::new();

        resp.set_completion_code(CmdCompletionCode::Success as u8);
        resp.set_eid(local_eid);
        resp.set_eid_type(EidType::DynamicOnly as u8);

        resp.write_to(&mut rsp_buf[..self.resp_data_len()])
            .map_err(|_| ErrorCode::FAIL)
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
    #[derive(Clone, FromBytes)]
    pub struct SetEidReq([u8]);
    impl Debug;
    u8;
    rsvd, _: 5, 0;
    pub op, _: 7, 6;
    pub eid, _: 15, 8;
}

pub enum SetEidOp {
    SetEid,
    ForceEid,
    ResetEid,
    SetDiscoveredFlag,
}

impl From<u8> for SetEidOp {
    fn from(val: u8) -> SetEidOp {
        match val {
            0 => SetEidOp::SetEid,
            1 => SetEidOp::ForceEid,
            2 => SetEidOp::ResetEid,
            3 => SetEidOp::SetDiscoveredFlag,
            _ => unreachable!("value should be 0, 1, 2, or 3"),
        }
    }
}

// Set EID Response
bitfield! {
    #[repr(C)]
    #[derive(Clone, IntoBytes, Immutable)]
    pub struct SetEidResp([u8]);
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

impl SetEidResp<[u8; 4]> {
    pub fn new() -> Self {
        SetEidResp([0; 4])
    }
}

pub enum SetEidStatus {
    Accepted = 0,
    Rejected = 1,
}

pub enum SetEidAllocStatus {
    NoEidPool,
}

// Get EID Request has no fields
// Get EID Response
bitfield! {
    #[repr(C)]
    #[derive(Clone, IntoBytes, Immutable)]
    pub struct GetEidResp([u8]);
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

impl GetEidResp<[u8; 4]> {
    pub fn new() -> Self {
        GetEidResp([0; 4])
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

pub enum EidType {
    DynamicOnly,
    Static,
    StaticMatching,
    StaticNonMatching,
}

impl From<u8> for EidType {
    fn from(val: u8) -> EidType {
        match val {
            0 => EidType::DynamicOnly,
            1 => EidType::Static,
            2 => EidType::StaticMatching,
            3 => EidType::StaticNonMatching,
            _ => unreachable!("value should be 0, 1, 2, or 3"),
        }
    }
}
