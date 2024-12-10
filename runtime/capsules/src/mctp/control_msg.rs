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
    pub struct MCTPCtrlMsgHdr(MSB0 [u8]);
    impl Debug;
    u8;
    pub ic, _: 0, 0;
    pub msg_type, _: 7, 1;
    pub rq, set_rq : 8, 8;
    pub datagram, set_datagram: 9, 9;
    rsvd, _: 10, 10;
    pub instance_id, set_instance_id: 15, 11;
    pub cmd, set_cmd: 23, 16;
}

impl Default for MCTPCtrlMsgHdr<[u8; MCTP_CTRL_MSG_HEADER_LEN]> {
    fn default() -> Self {
        Self::new()
    }
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

#[derive(Debug)]
pub enum MCTPCtrlCmd {
    SetEID,
    GetEID,
    GetMsgTypeSupport,
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

impl MCTPCtrlCmd {
    pub fn to_u8(&self) -> u8 {
        match self {
            MCTPCtrlCmd::SetEID => 2,
            MCTPCtrlCmd::GetEID => 0,
            MCTPCtrlCmd::GetMsgTypeSupport => 0,
            MCTPCtrlCmd::Unsupported => 0xFF,
        }
    }

    pub fn req_data_len(&self) -> usize {
        match self {
            MCTPCtrlCmd::SetEID => 2,
            MCTPCtrlCmd::GetEID => 0,
            MCTPCtrlCmd::GetMsgTypeSupport => 5,
            MCTPCtrlCmd::Unsupported => 0,
        }
    }

    pub fn resp_data_len(&self) -> usize {
        match self {
            MCTPCtrlCmd::SetEID => 4,
            MCTPCtrlCmd::GetEID => 4,
            MCTPCtrlCmd::GetMsgTypeSupport => 1,
            MCTPCtrlCmd::Unsupported => 0,
        }
    }

    pub fn process_set_endpoint_id(
        &self,
        req: &[u8],
        rsp_buf: &mut [u8],
    ) -> Result<Option<u8>, ErrorCode> {
        if req.len() < self.req_data_len() || rsp_buf.len() < self.resp_data_len() {
            return Err(ErrorCode::NOMEM);
        }

        let req: SetEIDReq<[u8; 2]> =
            SetEIDReq::read_from_bytes(&req[..self.req_data_len()]).unwrap();
        let op = req.op().into();
        let eid = req.eid();
        let mut resp = SetEIDResp::new();
        let mut completion_code = CmdCompletionCode::Success;
        let mut set_status = SetEIDStatus::Rejected;

        match op {
            SetEIDOp::SetEID | SetEIDOp::ForceEID => {
                if eid == MCTP_NULL_EID || eid == MCTP_BROADCAST_EID || (1..7).contains(&eid) {
                    completion_code = CmdCompletionCode::ErrorInvalidData;
                } else {
                    // TODO: Check if rejected case needs to be handled
                    set_status = SetEIDStatus::Accepted;
                    resp.set_eid_alloc_status(SetEIDAllocStatus::NoEIDPool as u8);
                    resp.set_assigned_eid(eid);
                    resp.set_eid_pool_size(0);
                }
            }
            SetEIDOp::ResetEID | SetEIDOp::SetDiscoveredFlag => {
                set_status = SetEIDStatus::Rejected;
                completion_code = CmdCompletionCode::ErrorInvalidData;
            }
        }
        resp.set_eid_assign_status(set_status as u8);
        resp.set_completion_code(completion_code as u8);

        resp.write_to(&mut rsp_buf[..self.resp_data_len()])
            .map_err(|_| ErrorCode::FAIL)?;

        if resp.eid_assign_status() == SetEIDStatus::Accepted as u8 {
            Ok(Some(eid))
        } else {
            Ok(None)
        }
    }

    pub fn process_get_endpoint_id(
        &self,
        local_eid: u8,
        rsp_buf: &mut [u8],
    ) -> Result<(), ErrorCode> {
        if rsp_buf.len() < self.resp_data_len() {
            return Err(ErrorCode::NOMEM);
        }
        let mut resp = GetEIDResp::new();

        resp.set_completion_code(CmdCompletionCode::Success as u8);
        resp.set_eid(local_eid);
        resp.set_eid_type(EIDType::DynamicOnly as u8);

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
    pub struct SetEIDReq(MSB0 [u8]);
    impl Debug;
    u8;
    rsvd, _: 5, 0;
    pub op, _: 7, 6;
    pub eid, _: 15, 8;
}

pub enum SetEIDOp {
    SetEID,
    ForceEID,
    ResetEID,
    SetDiscoveredFlag,
}

impl From<u8> for SetEIDOp {
    fn from(val: u8) -> SetEIDOp {
        match val {
            0 => SetEIDOp::SetEID,
            1 => SetEIDOp::ForceEID,
            2 => SetEIDOp::ResetEID,
            3 => SetEIDOp::SetDiscoveredFlag,
            _ => unreachable!("value should be 0, 1, 2, or 3"),
        }
    }
}

// Set EID Response
bitfield! {
    #[repr(C)]
    #[derive(Clone, FromBytes, IntoBytes, Immutable)]
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
    #[derive(Clone, FromBytes, IntoBytes, Immutable)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mctp::base_protocol::MessageType;

    #[test]
    fn test_ctrl_msg_hdr() {
        let mut msg_hdr = MCTPCtrlMsgHdr::new();
        msg_hdr.prepare_header(0, 0, 0, MCTPCtrlCmd::SetEID.to_u8());
        assert_eq!(msg_hdr.ic(), 0);
        assert_eq!(msg_hdr.msg_type(), MessageType::MCTPControl as u8);
        assert_eq!(msg_hdr.rq(), 0);
        assert_eq!(msg_hdr.datagram(), 0);
        assert_eq!(msg_hdr.instance_id(), 0);
        assert_eq!(msg_hdr.cmd(), MCTPCtrlCmd::SetEID.to_u8());
    }

    #[test]
    fn test_set_endpoint_id() {
        let msg_req = [0x00, 0x0A];

        let rsp_buf = &mut [0; 4];
        let eid = MCTPCtrlCmd::SetEID
            .process_set_endpoint_id(&msg_req, rsp_buf)
            .unwrap();

        assert_eq!(eid, 0x0A);

        let rsp: SetEIDResp<[u8; 4]> = SetEIDResp::read_from_bytes(rsp_buf).unwrap();
        assert_eq!(rsp.completion_code(), CmdCompletionCode::Success as u8);
        assert_eq!(rsp.eid_assign_status(), SetEIDStatus::Accepted as u8);
        assert_eq!(rsp.eid_alloc_status(), SetEIDAllocStatus::NoEIDPool as u8);
        assert_eq!(rsp.assigned_eid(), 0x0A);
        assert_eq!(rsp.eid_pool_size(), 0);
    }

    #[test]
    fn test_set_null_endpoint_id() {
        let msg_req = [0x00, 0x00];

        let rsp_buf = &mut [0; 4];
        let eid = MCTPCtrlCmd::SetEID
            .process_set_endpoint_id(&msg_req, rsp_buf)
            .unwrap();

        assert_eq!(eid, 0x00);

        let rsp: SetEIDResp<[u8; 4]> = SetEIDResp::read_from_bytes(rsp_buf).unwrap();
        assert_eq!(
            rsp.completion_code(),
            CmdCompletionCode::ErrorInvalidData as u8
        );
    }

    #[test]
    fn test_set_broadcast_endpoint_id() {
        let msg_req = [0x00, 0xFF];

        let rsp_buf = &mut [0; 4];
        let eid = MCTPCtrlCmd::SetEID
            .process_set_endpoint_id(&msg_req, rsp_buf)
            .unwrap();

        assert_eq!(eid, 0xFF);

        let rsp: SetEIDResp<[u8; 4]> = SetEIDResp::read_from_bytes(rsp_buf).unwrap();
        assert_eq!(
            rsp.completion_code(),
            CmdCompletionCode::ErrorInvalidData as u8
        );
    }

    #[test]
    fn test_get_endpoint_id() {
        let rsp_buf = &mut [0; 4];
        MCTPCtrlCmd::GetEID
            .process_get_endpoint_id(0x0A, rsp_buf)
            .unwrap();

        let rsp: GetEIDResp<[u8; 4]> = GetEIDResp::read_from_bytes(rsp_buf).unwrap();
        assert_eq!(rsp.completion_code(), CmdCompletionCode::Success as u8);
        assert_eq!(rsp.eid(), 0x0A);
        assert_eq!(rsp.eid_type(), EIDType::DynamicOnly as u8);
    }
}
