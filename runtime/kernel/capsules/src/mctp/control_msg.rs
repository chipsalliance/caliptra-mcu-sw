// Licensed under the Apache-2.0 license

use crate::mctp::base_protocol::{valid_eid, MessageType, MCTP_NUM_MSG_TYPES_SUPPORTED};
use bitfield::bitfield;
use kernel::ErrorCode;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const MCTP_CTRL_MSG_HEADER_LEN: usize = 3;

bitfield! {
    #[derive(Default)]
    pub struct MCTPCtrlMsgHdr(u32);
    u8;
    pub msg_type, _: 6, 0;
    pub ic, _: 7, 7;
    pub instance_id, set_instance_id: 12, 8;
    rsvd, _: 13, 13;
    pub datagram, set_datagram: 14, 14;
    pub rq, set_rq : 15, 15;
    pub cmd, set_cmd: 23, 16;
}

impl MCTPCtrlMsgHdr {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn prepare_header(&mut self, rq: u8, datagram: u8, instance_id: u8, cmd: u8) {
        self.set_rq(rq);
        self.set_datagram(datagram);
        self.set_instance_id(instance_id);
        self.set_cmd(cmd);
    }
}

pub enum MCTPCtrlCmd {
    SetEID = 1,
    GetEID = 2,
    GetMsgTypeSupport = 5,
    GetVersionSupport = 4,
    Unsupported = 0xFF,
}

impl From<u8> for MCTPCtrlCmd {
    fn from(val: u8) -> MCTPCtrlCmd {
        match val {
            1 => MCTPCtrlCmd::SetEID,
            2 => MCTPCtrlCmd::GetEID,
            4 => MCTPCtrlCmd::GetVersionSupport,
            5 => MCTPCtrlCmd::GetMsgTypeSupport,
            _ => MCTPCtrlCmd::Unsupported,
        }
    }
}

impl MCTPCtrlCmd {
    pub fn req_data_len(&self) -> usize {
        match self {
            MCTPCtrlCmd::SetEID => 2,
            MCTPCtrlCmd::GetEID => 0,
            MCTPCtrlCmd::GetVersionSupport => 1,
            MCTPCtrlCmd::GetMsgTypeSupport => 0,
            MCTPCtrlCmd::Unsupported => 0,
        }
    }

    pub fn resp_data_len(&self) -> usize {
        match self {
            MCTPCtrlCmd::SetEID => 4,
            MCTPCtrlCmd::GetEID => 4,
            MCTPCtrlCmd::GetVersionSupport => 18, // 2 bytes header + 4 entries * 4 bytes each
            MCTPCtrlCmd::GetMsgTypeSupport => 2 + MCTP_NUM_MSG_TYPES_SUPPORTED, // 1 byte for completion code + 1 byte for count + supported message types
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
            SetEIDReq::read_from_bytes(&req[..self.req_data_len()]).map_err(|_| ErrorCode::FAIL)?;
        let op = req.op().into();
        let eid = req.eid();
        let mut resp = SetEIDResp::new();
        let mut completion_code = CmdCompletionCode::Success;
        let mut set_status = SetEIDStatus::Rejected;

        match op {
            SetEIDOp::SetEID | SetEIDOp::ForceEID => {
                if eid == 0 || !valid_eid(eid) {
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

    pub fn process_get_version_support(
        &self,
        req: &[u8],
        rsp_buf: &mut [u8],
    ) -> Result<(), ErrorCode> {
        let version_type = VersionSupportType::from(req[0]);

        match version_type {
            VersionSupportType::BaseSpec | VersionSupportType::ControlProtocolMessage => {
                // Support MCTP Base and Control specs with 4 versions: 1.0, 1.1, 1.2, 1.3.3
                let header = GetVersionSupportHeaderResp {
                    completion_code: 0x00, // Success
                    entry_counter: 4,      // 4 version entries
                };

                header
                    .write_to(&mut rsp_buf[..2])
                    .map_err(|_| ErrorCode::FAIL)?;

                // Version 1.0: major=0xF1, minor=0xF0, update=0xFF, alpha=0x00
                let version_1_0 = GetVersionSupportEntryResp {
                    major: 0xF1,
                    minor: 0xF0,
                    update: 0xFF,
                    alpha: 0x00,
                };
                version_1_0
                    .write_to(&mut rsp_buf[2..6])
                    .map_err(|_| ErrorCode::FAIL)?;

                // Version 1.1: major=0xF1, minor=0xF1, update=0xFF, alpha=0x00
                let version_1_1 = GetVersionSupportEntryResp {
                    major: 0xF1,
                    minor: 0xF1,
                    update: 0xFF,
                    alpha: 0x00,
                };
                version_1_1
                    .write_to(&mut rsp_buf[6..10])
                    .map_err(|_| ErrorCode::FAIL)?;

                // Version 1.2: major=0xF1, minor=0xF2, update=0xFF, alpha=0x00
                let version_1_2 = GetVersionSupportEntryResp {
                    major: 0xF1,
                    minor: 0xF2,
                    update: 0xFF,
                    alpha: 0x00,
                };
                version_1_2
                    .write_to(&mut rsp_buf[10..14])
                    .map_err(|_| ErrorCode::FAIL)?;

                // Version 1.3.3: major=0xF1, minor=0xF3, update=0xF3, alpha=0x00
                let version_1_3_3 = GetVersionSupportEntryResp {
                    major: 0xF1,
                    minor: 0xF3,
                    update: 0xF3,
                    alpha: 0x00,
                };
                version_1_3_3
                    .write_to(&mut rsp_buf[14..18])
                    .map_err(|_| ErrorCode::FAIL)?;
            }
            _ => {
                // Unsupported version types
                let header = GetVersionSupportHeaderResp {
                    completion_code: 0x80, // Unsupported
                    entry_counter: 0,
                };

                header
                    .write_to(&mut rsp_buf[..2])
                    .map_err(|_| ErrorCode::FAIL)?;
            }
        }
        Ok(())
    }

    pub fn process_get_msg_type_support(
        &self,
        _req: &[u8],
        rsp_buf: &mut [u8],
    ) -> Result<(), ErrorCode> {
        if rsp_buf.len() < self.resp_data_len() {
            return Err(ErrorCode::NOMEM);
        }
        rsp_buf[0] = 0x00; // Completion code: Success
        let supported_msg_types = MessageType::supported();
        rsp_buf[1] = supported_msg_types.len() as u8;
        for (i, msg_type) in supported_msg_types.iter().enumerate() {
            rsp_buf[2 + i] = *msg_type as u8;
        }

        Ok(())
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

// Get Version Support Request
#[derive(Debug)]
enum VersionSupportType {
    BaseSpec,
    VendorControlled7E,
    VendorControlled7F,
    ControlProtocolMessage,
    DSP0241,
    DSP0261,
    #[allow(dead_code)]
    Other(u8),
}

#[allow(dead_code)]
struct VersionSupportResp {}

impl From<u8> for VersionSupportType {
    fn from(val: u8) -> VersionSupportType {
        match val {
            0xff => VersionSupportType::BaseSpec,
            0x7e => VersionSupportType::VendorControlled7E,
            0x7f => VersionSupportType::VendorControlled7F,
            0x00 => VersionSupportType::ControlProtocolMessage,
            0x01 => VersionSupportType::DSP0241,
            0x02 => VersionSupportType::DSP0261,
            _ => VersionSupportType::Other(val),
        }
    }
}

// Get Version Support Response
#[repr(C)]
#[derive(Clone, Debug, FromBytes, IntoBytes, Immutable)]
pub struct GetVersionSupportHeaderResp {
    pub completion_code: u8,
    pub entry_counter: u8,
}

impl Default for GetVersionSupportHeaderResp {
    fn default() -> Self {
        Self::new()
    }
}

impl GetVersionSupportHeaderResp {
    pub fn new() -> Self {
        GetVersionSupportHeaderResp {
            completion_code: 0,
            entry_counter: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug, FromBytes, IntoBytes, Immutable)]
pub struct GetVersionSupportEntryResp {
    pub major: u8,
    pub minor: u8,
    pub update: u8,
    pub alpha: u8,
}

impl Default for GetVersionSupportEntryResp {
    fn default() -> Self {
        Self::new()
    }
}

impl GetVersionSupportEntryResp {
    pub fn new() -> Self {
        GetVersionSupportEntryResp {
            alpha: 0,
            update: 0,
            minor: 0,
            major: 0,
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
        msg_hdr.prepare_header(0, 0, 0, MCTPCtrlCmd::SetEID as u8);
        assert_eq!(msg_hdr.ic(), 0);
        assert_eq!(msg_hdr.msg_type(), MessageType::MctpControl as u8);
        assert_eq!(msg_hdr.rq(), 0);
        assert_eq!(msg_hdr.datagram(), 0);
        assert_eq!(msg_hdr.instance_id(), 0);
        assert_eq!(msg_hdr.cmd(), MCTPCtrlCmd::SetEID as u8);
    }

    #[test]
    fn test_set_endpoint_id() {
        let msg_req = [0x00, 0x0A];

        let rsp_buf = &mut [0; 4];
        let eid = MCTPCtrlCmd::SetEID
            .process_set_endpoint_id(&msg_req, rsp_buf)
            .unwrap();
        assert!(eid.is_some());
        assert_eq!(eid.unwrap(), 0x0A);

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
        assert!(eid.is_none());

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
        assert!(eid.is_none());

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

    #[test]
    fn test_get_version_support() {
        let req = [0xff]; // BaseSpec version type
        let rsp_buf = &mut [0; 18];

        MCTPCtrlCmd::GetVersionSupport
            .process_get_version_support(&req, rsp_buf)
            .unwrap();

        // Check header (first 2 bytes)
        let header: GetVersionSupportHeaderResp =
            GetVersionSupportHeaderResp::read_from_bytes(&rsp_buf[..2]).unwrap();
        assert_eq!(header.completion_code, 0x00); // Success
        assert_eq!(header.entry_counter, 4);

        // Check version 1.0 entry
        let version_1_0: GetVersionSupportEntryResp =
            GetVersionSupportEntryResp::read_from_bytes(&rsp_buf[2..6]).unwrap();
        assert_eq!(version_1_0.major, 0xF1);
        assert_eq!(version_1_0.minor, 0xF0);
        assert_eq!(version_1_0.update, 0xFF);
        assert_eq!(version_1_0.alpha, 0x00);

        // Check version 1.1 entry
        let version_1_1: GetVersionSupportEntryResp =
            GetVersionSupportEntryResp::read_from_bytes(&rsp_buf[6..10]).unwrap();
        assert_eq!(version_1_1.major, 0xF1);
        assert_eq!(version_1_1.minor, 0xF1);
        assert_eq!(version_1_1.update, 0xFF);
        assert_eq!(version_1_1.alpha, 0x00);

        // Check version 1.2 entry
        let version_1_2: GetVersionSupportEntryResp =
            GetVersionSupportEntryResp::read_from_bytes(&rsp_buf[10..14]).unwrap();
        assert_eq!(version_1_2.major, 0xF1);
        assert_eq!(version_1_2.minor, 0xF2);
        assert_eq!(version_1_2.update, 0xFF);
        assert_eq!(version_1_2.alpha, 0x00);

        // Check version 1.3.3 entry
        let version_1_3_3: GetVersionSupportEntryResp =
            GetVersionSupportEntryResp::read_from_bytes(&rsp_buf[14..18]).unwrap();
        assert_eq!(version_1_3_3.major, 0xF1);
        assert_eq!(version_1_3_3.minor, 0xF3);
        assert_eq!(version_1_3_3.update, 0xF3);
        assert_eq!(version_1_3_3.alpha, 0x00);
    }

    #[test]
    fn test_get_version_support_unsupported() {
        let req = [0x01]; // DSP0241 version type (unsupported)
        let rsp_buf = &mut [0; 18];

        MCTPCtrlCmd::GetVersionSupport
            .process_get_version_support(&req, rsp_buf)
            .unwrap();

        // Check header (first 2 bytes)
        let header: GetVersionSupportHeaderResp =
            GetVersionSupportHeaderResp::read_from_bytes(&rsp_buf[..2]).unwrap();
        assert_eq!(header.completion_code, 0x80); // Unsupported
        assert_eq!(header.entry_counter, 0);
    }

    #[test]
    fn test_get_msg_type_support() {
        let rsp_buf = &mut [0; 2 + MCTP_NUM_MSG_TYPES_SUPPORTED];
        MCTPCtrlCmd::GetMsgTypeSupport
            .process_get_msg_type_support(&[], rsp_buf)
            .unwrap();

        assert_eq!(rsp_buf[0], 0x00); // Completion code: Success
        let supported_msg_types_count = rsp_buf[1] as usize;
        assert_eq!(supported_msg_types_count, MessageType::supported().len());
        for i in 0..supported_msg_types_count {
            assert_eq!(rsp_buf[2 + i], MessageType::supported()[i] as u8);
        }
    }
}
