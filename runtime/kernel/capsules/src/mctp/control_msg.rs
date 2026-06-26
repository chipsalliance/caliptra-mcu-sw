// Licensed under the Apache-2.0 license

use crate::mctp::base_protocol::{valid_eid, MessageType, MCTP_NUM_MSG_TYPES_SUPPORTED};
use bitfield::bitfield;
use kernel::ErrorCode;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const MCTP_CTRL_MSG_HEADER_LEN: usize = 3;

const MCTP_BASE_CONTROL_VERSIONS: [[u8; 4]; 4] = [
    [0xF1, 0xF0, 0xFF, 0x00], // 1.0
    [0xF1, 0xF1, 0xFF, 0x00], // 1.1
    [0xF1, 0xF2, 0xFF, 0x00], // 1.2
    [0xF1, 0xF3, 0xF3, 0x00], // 1.3.3
];

const PLDM_OVER_MCTP_VERSIONS: [[u8; 4]; 1] = [
    [0xF1, 0xF0, 0xF0, 0x00], // DSP0241 1.0.0
];

const SPDM_OVER_MCTP_VERSIONS: [[u8; 4]; 1] = [
    [0xF1, 0xF0, 0xF2, 0x00], // DSP0275 1.0.2
];

// Current Caliptra Secure SPDM support reports only DSP0276 2.0.0.
const SECURED_SPDM_OVER_MCTP_VERSIONS: [[u8; 4]; 1] = [
    [0xF2, 0xF0, 0xF0, 0x00], // DSP0276 2.0.0
];

const CALIPTRA_IANA_VDM_VERSIONS: [[u8; 4]; 1] = [
    [0xF1, 0xF0, 0xF0, 0x00], // Caliptra/OCP VDM 1.0.0
];

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

    fn write_to_buf(&self, resp_buf: &mut [u8]) -> Result<(), ErrorCode> {
        if resp_buf.len() < MCTP_CTRL_MSG_HEADER_LEN {
            return Err(ErrorCode::INVAL);
        }

        resp_buf[..MCTP_CTRL_MSG_HEADER_LEN]
            .copy_from_slice(&self.0.to_le_bytes()[..MCTP_CTRL_MSG_HEADER_LEN]);
        Ok(())
    }
}

pub struct MCTPCtrlMsgResp {
    pub assigned_eid: Option<u8>,
    pub resp_len: usize,
}

pub fn process_mctp_control_msg(
    msg_buf: &[u8],
    local_eid: u8,
    supported_msg_types: &[MessageType],
    resp_buf: &mut [u8],
) -> Result<MCTPCtrlMsgResp, ErrorCode> {
    if msg_buf.len() < MCTP_CTRL_MSG_HEADER_LEN {
        return Err(ErrorCode::INVAL);
    }

    let mut hdr = [0; 4];
    hdr[..MCTP_CTRL_MSG_HEADER_LEN].copy_from_slice(&msg_buf[..MCTP_CTRL_MSG_HEADER_LEN]);
    let mctp_ctrl_msg_hdr = MCTPCtrlMsgHdr(u32::from_le_bytes(hdr));

    if mctp_ctrl_msg_hdr.rq() != 1 || mctp_ctrl_msg_hdr.datagram() != 0 {
        return Err(ErrorCode::INVAL);
    }

    let mut mctp_ctrl_msg_hdr_resp = MCTPCtrlMsgHdr::new();
    mctp_ctrl_msg_hdr_resp.prepare_header(
        0,
        mctp_ctrl_msg_hdr.datagram(),
        mctp_ctrl_msg_hdr.instance_id(),
        mctp_ctrl_msg_hdr.cmd(),
    );

    let req_buf = &msg_buf[MCTP_CTRL_MSG_HEADER_LEN..];
    let mctp_ctrl_cmd: MCTPCtrlCmd = mctp_ctrl_msg_hdr.cmd().into();
    if req_buf.len() < mctp_ctrl_cmd.req_data_len() {
        return Err(ErrorCode::INVAL);
    }

    if resp_buf.len() < MCTP_CTRL_MSG_HEADER_LEN + mctp_ctrl_cmd.resp_data_len() {
        return Err(ErrorCode::NOMEM);
    }

    let rsp_payload = &mut resp_buf[MCTP_CTRL_MSG_HEADER_LEN..];
    let mut assigned_eid = None;
    let resp_data_len = match mctp_ctrl_cmd {
        MCTPCtrlCmd::SetEID => mctp_ctrl_cmd
            .process_set_endpoint_id(req_buf, rsp_payload)
            .map(|eid| {
                assigned_eid = eid;
                mctp_ctrl_cmd.resp_data_len()
            }),
        MCTPCtrlCmd::GetEID => mctp_ctrl_cmd
            .process_get_endpoint_id(local_eid, rsp_payload)
            .map(|_| mctp_ctrl_cmd.resp_data_len()),
        MCTPCtrlCmd::GetVersionSupport => {
            mctp_ctrl_cmd.process_get_version_support(req_buf, rsp_payload, supported_msg_types)
        }
        MCTPCtrlCmd::GetMsgTypeSupport => {
            mctp_ctrl_cmd.process_get_msg_type_support(req_buf, rsp_payload, supported_msg_types)
        }
        MCTPCtrlCmd::Unsupported => {
            rsp_payload[0] = CmdCompletionCode::ErrorNotSupportedCmd as u8;
            Ok(mctp_ctrl_cmd.resp_data_len())
        }
    }?;

    mctp_ctrl_msg_hdr_resp.write_to_buf(resp_buf)?;
    Ok(MCTPCtrlMsgResp {
        assigned_eid,
        resp_len: MCTP_CTRL_MSG_HEADER_LEN + resp_data_len,
    })
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
            MCTPCtrlCmd::Unsupported => 1, // 1 byte for completion code
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
        supported_msg_types: &[MessageType],
    ) -> Result<usize, ErrorCode> {
        if req.len() < self.req_data_len() {
            return Err(ErrorCode::INVAL);
        }
        if rsp_buf.len() < self.resp_data_len() {
            return Err(ErrorCode::NOMEM);
        }

        rsp_buf[..self.resp_data_len()].fill(0);
        let version_type = VersionSupportType::from(req[0]);

        match version_type {
            VersionSupportType::BaseSpec | VersionSupportType::ControlProtocolMessage => {
                Self::write_get_version_support_success(rsp_buf, &MCTP_BASE_CONTROL_VERSIONS)
            }
            VersionSupportType::DSP0241 if supported_msg_types.contains(&MessageType::Pldm) => {
                Self::write_get_version_support_success(rsp_buf, &PLDM_OVER_MCTP_VERSIONS)
            }
            VersionSupportType::DSP0275 if supported_msg_types.contains(&MessageType::Spdm) => {
                Self::write_get_version_support_success(rsp_buf, &SPDM_OVER_MCTP_VERSIONS)
            }
            VersionSupportType::DSP0276
                if supported_msg_types.contains(&MessageType::SecureSpdm) =>
            {
                Self::write_get_version_support_success(rsp_buf, &SECURED_SPDM_OVER_MCTP_VERSIONS)
            }
            VersionSupportType::VendorControlled7F
                if supported_msg_types.contains(&MessageType::Caliptra) =>
            {
                Self::write_get_version_support_success(rsp_buf, &CALIPTRA_IANA_VDM_VERSIONS)
            }
            _ => Self::write_get_version_support_unsupported(rsp_buf),
        }
    }

    fn write_get_version_support_success(
        rsp_buf: &mut [u8],
        versions: &[[u8; 4]],
    ) -> Result<usize, ErrorCode> {
        let header = GetVersionSupportHeaderResp {
            completion_code: 0x00,
            entry_counter: versions.len() as u8,
        };
        header
            .write_to(&mut rsp_buf[..2])
            .map_err(|_| ErrorCode::FAIL)?;

        for (i, ver) in versions.iter().enumerate() {
            let offset = 2 + i * 4;
            rsp_buf[offset..offset + 4].copy_from_slice(ver);
        }

        Ok(2 + versions.len() * 4)
    }

    fn write_get_version_support_unsupported(rsp_buf: &mut [u8]) -> Result<usize, ErrorCode> {
        let header = GetVersionSupportHeaderResp {
            completion_code: 0x80,
            entry_counter: 0,
        };
        header
            .write_to(&mut rsp_buf[..2])
            .map_err(|_| ErrorCode::FAIL)?;
        Ok(2)
    }

    pub fn process_get_msg_type_support(
        &self,
        _req: &[u8],
        rsp_buf: &mut [u8],
        supported_msg_types: &[MessageType],
    ) -> Result<usize, ErrorCode> {
        if rsp_buf.len() < 2 + supported_msg_types.len() {
            return Err(ErrorCode::NOMEM);
        }
        rsp_buf[0] = 0x00; // Completion code: Success
        rsp_buf[1] = supported_msg_types.len() as u8;
        for (i, msg_type) in supported_msg_types.iter().enumerate() {
            rsp_buf[2 + i] = *msg_type as u8;
        }

        Ok(2 + supported_msg_types.len())
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
    DSP0275,
    DSP0276,
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
            0x05 => VersionSupportType::DSP0275,
            0x06 => VersionSupportType::DSP0276,
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
    fn test_process_mctp_control_msg_returns_assigned_eid() {
        let mut msg_req = [0; MCTP_CTRL_MSG_HEADER_LEN + 2];
        let mut msg_hdr = MCTPCtrlMsgHdr::new();
        msg_hdr.prepare_header(1, 0, 0, MCTPCtrlCmd::SetEID as u8);
        msg_hdr
            .write_to_buf(&mut msg_req[..MCTP_CTRL_MSG_HEADER_LEN])
            .unwrap();
        msg_req[MCTP_CTRL_MSG_HEADER_LEN..].copy_from_slice(&[0x00, 0x0A]);

        let rsp_buf = &mut [0; MCTP_CTRL_MSG_HEADER_LEN + 4];
        let resp = process_mctp_control_msg(&msg_req, 0, &[], rsp_buf).unwrap();

        assert_eq!(resp.assigned_eid, Some(0x0A));
        assert_eq!(resp.resp_len, MCTP_CTRL_MSG_HEADER_LEN + 4);
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
            .process_get_version_support(&req, rsp_buf, &[])
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
        for type_num in [0x04, 0x09, 0x10] {
            let req = [type_num];
            let rsp_buf = &mut [0; 18];

            MCTPCtrlCmd::GetVersionSupport
                .process_get_version_support(&req, rsp_buf, &[])
                .unwrap();

            // Check header (first 2 bytes)
            let header: GetVersionSupportHeaderResp =
                GetVersionSupportHeaderResp::read_from_bytes(&rsp_buf[..2]).unwrap();
            assert_eq!(header.completion_code, 0x80); // Unsupported
            assert_eq!(header.entry_counter, 0);
        }
    }

    #[test]
    fn test_get_version_support_short_request_returns_invalid() {
        let req = [];
        let rsp_buf = &mut [0; 18];

        let err = MCTPCtrlCmd::GetVersionSupport
            .process_get_version_support(&req, rsp_buf, &[])
            .unwrap_err();

        assert_eq!(err, ErrorCode::INVAL);
    }

    #[test]
    fn test_get_version_support_supported_message_types() {
        assert_get_version_support(
            &[MessageType::Pldm],
            MessageType::Pldm as u8,
            &[
                [0xF1, 0xF0, 0xF0, 0x00], // DSP0241 1.0.0
            ],
        );
        assert_get_version_support(
            &[MessageType::Spdm],
            MessageType::Spdm as u8,
            &[
                [0xF1, 0xF0, 0xF2, 0x00], // DSP0275 1.0.2
            ],
        );
        assert_get_version_support(
            &[MessageType::SecureSpdm],
            MessageType::SecureSpdm as u8,
            &[
                [0xF2, 0xF0, 0xF0, 0x00], // DSP0276 2.0.0
            ],
        );
        assert_get_version_support(
            &[MessageType::Caliptra],
            MessageType::Caliptra as u8,
            &[
                [0xF1, 0xF0, 0xF0, 0x00], // Caliptra/OCP VDM 1.0.0
            ],
        );
    }

    #[test]
    fn test_get_version_support_unadvertised_message_type() {
        let req = [MessageType::SecureSpdm as u8];
        let rsp_buf = &mut [0; 18];

        MCTPCtrlCmd::GetVersionSupport
            .process_get_version_support(&req, rsp_buf, &[MessageType::Pldm, MessageType::Spdm])
            .unwrap();

        let header: GetVersionSupportHeaderResp =
            GetVersionSupportHeaderResp::read_from_bytes(&rsp_buf[..2]).unwrap();
        assert_eq!(header.completion_code, 0x80);
        assert_eq!(header.entry_counter, 0);
    }

    #[test]
    fn test_version_support_consistent_with_msg_type_support() {
        let supported_msg_types = [
            MessageType::MctpControl,
            MessageType::Pldm,
            MessageType::Spdm,
            MessageType::SecureSpdm,
            MessageType::Caliptra,
        ];

        for msg_type in supported_msg_types {
            let type_num = msg_type as u8;
            let req = [type_num];
            let rsp_buf = &mut [0; 18];
            MCTPCtrlCmd::GetVersionSupport
                .process_get_version_support(&req, rsp_buf, &supported_msg_types)
                .unwrap();

            let header: GetVersionSupportHeaderResp =
                GetVersionSupportHeaderResp::read_from_bytes(&rsp_buf[..2]).unwrap();
            assert_ne!(
                header.completion_code, 0x80,
                "msg type 0x{:02X} advertised but Get Version Support returned 0x80",
                type_num
            );
            assert!(
                header.entry_counter > 0,
                "msg type 0x{:02X} returned zero entries",
                type_num
            );
        }
    }

    #[test]
    fn test_get_msg_type_support() {
        let rsp_buf = &mut [0; 2 + MCTP_NUM_MSG_TYPES_SUPPORTED];
        let supported_msg_types = [
            MessageType::MctpControl,
            MessageType::Pldm,
            MessageType::Spdm,
            MessageType::Caliptra,
        ];
        MCTPCtrlCmd::GetMsgTypeSupport
            .process_get_msg_type_support(&[], rsp_buf, &supported_msg_types)
            .unwrap();

        assert_eq!(rsp_buf[0], 0x00); // Completion code: Success
        let supported_msg_types_count = rsp_buf[1] as usize;
        assert_eq!(supported_msg_types_count, supported_msg_types.len());
        for i in 0..supported_msg_types_count {
            assert_eq!(rsp_buf[2 + i], supported_msg_types[i] as u8);
        }
    }

    fn assert_get_version_support(
        supported_msg_types: &[MessageType],
        type_num: u8,
        expected_versions: &[[u8; 4]],
    ) {
        let req = [type_num];
        let rsp_buf = &mut [0xA5; 18];
        MCTPCtrlCmd::GetVersionSupport
            .process_get_version_support(&req, rsp_buf, supported_msg_types)
            .unwrap();

        let header: GetVersionSupportHeaderResp =
            GetVersionSupportHeaderResp::read_from_bytes(&rsp_buf[..2]).unwrap();
        assert_eq!(header.completion_code, 0x00);
        assert_eq!(header.entry_counter, expected_versions.len() as u8);

        for (i, expected_version) in expected_versions.iter().enumerate() {
            let offset = 2 + i * 4;
            assert_eq!(&rsp_buf[offset..offset + 4], expected_version);
        }

        let used_len = 2 + expected_versions.len() * 4;
        assert!(rsp_buf[used_len..].iter().all(|byte| *byte == 0));
    }
}
