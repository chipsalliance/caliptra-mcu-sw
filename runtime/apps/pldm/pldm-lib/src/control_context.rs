// Licensed under the Apache-2.0 license

use crate::cmd_interface::generate_failure_response;
use crate::error::MsgHandlerError;
use core::sync::atomic::{AtomicUsize, Ordering};
use pldm_common::codec::PldmCodec;
use pldm_common::error::PldmError;
use pldm_common::message::control::{
    GetPldmCommandsRequest, GetPldmCommandsResponse, GetPldmTypeRequest, GetPldmTypeResponse,
    GetPldmVersionRequest, GetPldmVersionResponse, GetTidRequest, GetTidResponse, SetTidRequest,
    SetTidResponse,
};
use pldm_common::protocol::base::{
    PldmBaseCompletionCode, PldmControlCompletionCode, PldmSupportedType, TransferOperationFlag,
    TransferRespFlag,
};
use pldm_common::protocol::version::{PldmVersion, ProtocolVersionStr, Ver32};

pub type Tid = u8;
pub type CmdOpCode = u8;
pub const UNASSIGNED_TID: Tid = 0;

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct ProtocolCapability<'a> {
    pub pldm_type: PldmSupportedType,
    pub protocol_version: Ver32,
    pub supported_commands: &'a [CmdOpCode],
}

impl<'a> ProtocolCapability<'a> {
    pub fn new(
        pldm_type: PldmSupportedType,
        protocol_version: ProtocolVersionStr,
        supported_commands: &'a [CmdOpCode],
    ) -> Result<Self, PldmError> {
        Ok(Self {
            pldm_type,
            protocol_version: match PldmVersion::try_from(protocol_version) {
                Ok(ver) => ver.bcd_encode_to_ver32(),
                Err(_) => return Err(PldmError::InvalidProtocolVersion),
            },
            supported_commands,
        })
    }
}

/// `ControlContext` is a structure that holds the control context for the PLDM library.
///
/// # Fields
///
/// * `tid` - An atomic unsigned size integer representing the transaction ID.
/// * `capabilities` - A reference to a slice of `ProtocolCapability` which represents the protocol capabilities.
pub struct ControlContext<'a> {
    tid: AtomicUsize,
    capabilities: &'a [ProtocolCapability<'a>],
}

impl<'a> ControlContext<'a> {
    pub fn new(capabilities: &'a [ProtocolCapability<'a>]) -> Self {
        Self {
            tid: AtomicUsize::new(UNASSIGNED_TID as usize),
            capabilities,
        }
    }

    pub fn get_tid(&self) -> Tid {
        self.tid.load(Ordering::SeqCst) as Tid
    }

    pub fn set_tid(&self, tid: Tid) {
        self.tid.store(tid as usize, Ordering::SeqCst);
    }

    pub fn get_supported_commands(
        &self,
        pldm_type: PldmSupportedType,
        protocol_version: Ver32,
    ) -> Option<&[CmdOpCode]> {
        self.capabilities
            .iter()
            .find(|cap| cap.pldm_type == pldm_type && cap.protocol_version == protocol_version)
            .map(|cap| cap.supported_commands)
    }

    pub fn get_protocol_versions(
        &self,
        pldm_type: PldmSupportedType,
        versions: &mut [Ver32],
    ) -> usize {
        let mut count = 0;
        for cap in self
            .capabilities
            .iter()
            .filter(|cap| cap.pldm_type == pldm_type)
        {
            if count < versions.len() {
                versions[count] = cap.protocol_version;
                count += 1;
            } else {
                break;
            }
        }
        count
    }

    pub fn get_supported_types(&self, types: &mut [u8]) -> usize {
        let mut count = 0;
        for cap in self.capabilities.iter() {
            let pldm_type = cap.pldm_type as u8;
            if !types[..count].contains(&pldm_type) {
                if count < types.len() {
                    types[count] = pldm_type;
                    count += 1;
                } else {
                    break;
                }
            }
        }
        count
    }

    pub fn is_supported_type(&self, pldm_type: PldmSupportedType) -> bool {
        self.capabilities
            .iter()
            .any(|cap| cap.pldm_type == pldm_type)
    }

    pub fn is_supported_version(
        &self,
        pldm_type: PldmSupportedType,
        protocol_version: Ver32,
    ) -> bool {
        let mut versions = [0; 4];
        let count = self.get_protocol_versions(pldm_type, &mut versions);
        versions[..count].contains(&protocol_version)
    }

    pub fn is_supported_command(&self, pldm_type: PldmSupportedType, cmd: u8) -> bool {
        self.capabilities
            .iter()
            .find(|cap| cap.pldm_type == pldm_type)
            .map_or(false, |cap| cap.supported_commands.contains(&cmd))
    }
}

/// Trait representing a responder for control commands in the PLDM protocol.
/// Implementors of this trait are responsible for handling various control commands
/// and generating appropriate responses.
///
/// # Methods
///
/// - `get_tid_rsp`: Generates a response for the "Get TID" command.
/// - `set_tid_rsp`: Generates a response for the "Set TID" command.
/// - `get_pldm_types_rsp`: Generates a response for the "Get PLDM Types" command.
/// - `get_pldm_commands_rsp`: Generates a response for the "Get PLDM Commands" command.
/// - `get_pldm_version_rsp`: Generates a response for the "Get PLDM Version" command.
///
/// Each method takes a mutable reference to a payload buffer and returns a `Result`
/// containing the size of the response or a `MsgHandlerError` if an error occurs.
pub trait CtrlCmdResponder {
    fn get_tid_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError>;
    fn set_tid_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError>;
    fn get_pldm_types_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError>;
    fn get_pldm_commands_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError>;
    fn get_pldm_version_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError>;
}

impl<'a> CtrlCmdResponder for ControlContext<'a> {
    fn get_tid_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        let req = GetTidRequest::decode(payload).map_err(MsgHandlerError::Codec)?;
        let resp = GetTidResponse::new(
            req.hdr.instance_id(),
            self.get_tid(),
            PldmBaseCompletionCode::Success as u8,
        );
        resp.encode(payload).map_err(MsgHandlerError::Codec)
    }

    fn set_tid_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        let req = SetTidRequest::decode(payload).map_err(MsgHandlerError::Codec)?;
        self.set_tid(req.tid);
        let resp =
            SetTidResponse::new(req.hdr.instance_id(), PldmBaseCompletionCode::Success as u8);
        resp.encode(payload).map_err(MsgHandlerError::Codec)
    }

    fn get_pldm_types_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        let req = GetPldmTypeRequest::decode(payload).map_err(MsgHandlerError::Codec)?;
        let mut types = [0x0u8; 6];
        let num_types = self.get_supported_types(&mut types);
        let resp = GetPldmTypeResponse::new(
            req.hdr.instance_id(),
            PldmBaseCompletionCode::Success as u8,
            &types[..num_types],
        );
        resp.encode(payload).map_err(MsgHandlerError::Codec)
    }

    fn get_pldm_commands_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        let req = match GetPldmCommandsRequest::decode(payload) {
            Ok(req) => req,
            Err(_) => {
                return generate_failure_response(
                    payload,
                    PldmBaseCompletionCode::InvalidLength as u8,
                )
            }
        };

        let pldm_type_in_req = match PldmSupportedType::try_from(req.pldm_type) {
            Ok(pldm_type) => pldm_type,
            Err(_) => {
                return generate_failure_response(
                    payload,
                    PldmControlCompletionCode::InvalidPldmTypeInRequestData as u8,
                )
            }
        };

        if !self.is_supported_type(pldm_type_in_req) {
            return generate_failure_response(
                payload,
                PldmControlCompletionCode::InvalidPldmTypeInRequestData as u8,
            );
        }

        let version_in_req = req.protocol_version;
        if !self.is_supported_version(pldm_type_in_req, version_in_req) {
            return generate_failure_response(
                payload,
                PldmControlCompletionCode::InvalidPldmVersionInRequestData as u8,
            );
        }

        let cmds = self
            .get_supported_commands(pldm_type_in_req, version_in_req)
            .unwrap();

        let resp = GetPldmCommandsResponse::new(
            req.hdr.instance_id(),
            PldmBaseCompletionCode::Success as u8,
            cmds,
        );

        match resp.encode(payload) {
            Ok(bytes) => Ok(bytes),
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::InvalidLength as u8)
            }
        }
    }

    fn get_pldm_version_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        let req = match GetPldmVersionRequest::decode(payload) {
            Ok(req) => req,
            Err(_) => {
                return generate_failure_response(
                    payload,
                    PldmBaseCompletionCode::InvalidLength as u8,
                )
            }
        };

        let pldm_type_in_req = match PldmSupportedType::try_from(req.pldm_type) {
            Ok(pldm_type) => pldm_type,
            Err(_) => {
                return generate_failure_response(
                    payload,
                    PldmControlCompletionCode::InvalidPldmTypeInRequestData as u8,
                )
            }
        };

        if !self.is_supported_type(pldm_type_in_req) {
            return generate_failure_response(
                payload,
                PldmControlCompletionCode::InvalidPldmTypeInRequestData as u8,
            );
        }

        if req.transfer_op_flag != TransferOperationFlag::GetFirstPart as u8 {
            return generate_failure_response(
                payload,
                PldmControlCompletionCode::InvalidTransferOperationFlag as u8,
            );
        }

        let mut versions = [0u32; 2];
        if self.get_protocol_versions(pldm_type_in_req, &mut versions) == 0 {
            return generate_failure_response(payload, PldmBaseCompletionCode::Error as u8);
        }

        // Only one version is supported for now
        let resp = GetPldmVersionResponse {
            hdr: req.hdr.into_response(),
            completion_code: PldmBaseCompletionCode::Success as u8,
            next_transfer_handle: 0,
            transfer_rsp_flag: TransferRespFlag::StartAndEnd as u8,
            version_data: versions[0],
        };

        match resp.encode(payload) {
            Ok(bytes) => Ok(bytes),
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::InvalidLength as u8)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pldm_common::protocol::base::PldmFailureResponse;
    use pldm_common::protocol::base::{
        PldmControlCmd, PldmMsgType, PldmSupportedType, PLDM_FAILURE_RESP_LEN,
    };
    use pldm_common::protocol::firmware_update::FwUpdateCmd;

    const PAY_LOAD_BUFFER_LEN: usize = 256;
    const SUPPORTED_CTRL_CMDS: [u8; 5] = [
        PldmControlCmd::SetTid as u8,
        PldmControlCmd::GetTid as u8,
        PldmControlCmd::GetPldmCommands as u8,
        PldmControlCmd::GetPldmVersion as u8,
        PldmControlCmd::GetPldmTypes as u8,
    ];
    const SUPPORTED_FW_UDPATE_CMDS: [u8; 12] = [
        FwUpdateCmd::QueryDeviceIdentifiers as u8,
        FwUpdateCmd::GetFirmwareParameters as u8,
        FwUpdateCmd::RequestUpdate as u8,
        FwUpdateCmd::PassComponentTable as u8,
        FwUpdateCmd::UpdateComponent as u8,
        FwUpdateCmd::RequestFirmwareData as u8,
        FwUpdateCmd::TransferComplete as u8,
        FwUpdateCmd::VerifyComplete as u8,
        FwUpdateCmd::ApplyComplete as u8,
        FwUpdateCmd::ActivateFirmware as u8,
        FwUpdateCmd::GetStatus as u8,
        FwUpdateCmd::CancelUpdate as u8,
    ];

    static PLDM_PROTOCOL_CAPABILITIES: [ProtocolCapability<'static>; 2] = [
        ProtocolCapability {
            pldm_type: PldmSupportedType::Base,
            protocol_version: 0xF1F1F000, //"1.1.0"
            supported_commands: &SUPPORTED_CTRL_CMDS,
        },
        ProtocolCapability {
            pldm_type: PldmSupportedType::FwUpdate,
            protocol_version: 0xF1F3F000, // 1.3.0
            supported_commands: &SUPPORTED_FW_UDPATE_CMDS,
        },
    ];

    fn construct_request<T: PldmCodec>(buf: &mut [u8], request_msg: T) {
        request_msg.encode(buf).unwrap();
    }

    fn validate_response<T: PldmCodec + PartialEq>(buf: &mut [u8], expected_rsp_msg: T) {
        let rsp = T::decode(&buf).unwrap();
        assert_eq!(rsp, expected_rsp_msg);
    }

    #[test]
    fn test_protocol_capability() {
        let cap = ProtocolCapability::new(PldmSupportedType::Base, "1.1.0", &SUPPORTED_CTRL_CMDS);
        assert!(cap.is_ok());
        let cap = cap.unwrap();
        assert_eq!(cap.pldm_type, PldmSupportedType::Base);
        assert_eq!(cap.protocol_version, 0xF1F1F000);
        assert_eq!(cap.supported_commands, SUPPORTED_CTRL_CMDS);

        let cap = ProtocolCapability::new(
            PldmSupportedType::FwUpdate,
            "1.3.0",
            &SUPPORTED_FW_UDPATE_CMDS,
        );
        assert!(cap.is_ok());
        let cap = cap.unwrap();
        assert_eq!(cap.pldm_type, PldmSupportedType::FwUpdate);
        assert_eq!(cap.protocol_version, 0xF1F3F000);
        assert_eq!(cap.supported_commands, SUPPORTED_FW_UDPATE_CMDS);
    }

    #[test]
    fn test_control_context() {
        let protocol_capabilities: [ProtocolCapability; 4] = [
            ProtocolCapability::new(PldmSupportedType::Base, "1.1.0", &SUPPORTED_CTRL_CMDS)
                .unwrap(),
            ProtocolCapability::new(PldmSupportedType::Base, "1.0.0", &SUPPORTED_CTRL_CMDS)
                .unwrap(),
            ProtocolCapability::new(
                PldmSupportedType::FwUpdate,
                "1.3.0",
                &SUPPORTED_FW_UDPATE_CMDS,
            )
            .unwrap(),
            ProtocolCapability::new(
                PldmSupportedType::FwUpdate,
                "1.2.0",
                &SUPPORTED_FW_UDPATE_CMDS,
            )
            .unwrap(),
        ];

        let ctrl_cxt = ControlContext::new(&protocol_capabilities);
        assert_eq!(ctrl_cxt.get_tid(), UNASSIGNED_TID);

        ctrl_cxt.set_tid(1);
        assert_eq!(ctrl_cxt.get_tid(), 1);

        let mut types = [0; 6];
        let count = ctrl_cxt.get_supported_types(&mut types);
        assert_eq!(count, 2);
        assert_eq!(
            types[..count],
            [
                PldmSupportedType::Base as u8,
                PldmSupportedType::FwUpdate as u8
            ]
        );

        let mut versions = [0; 4];
        let count = ctrl_cxt.get_protocol_versions(PldmSupportedType::Base, &mut versions);
        assert_eq!(count, 2);
        assert_eq!(versions[..count], [0xF1F1F000, 0xF1F0F000]);

        versions.fill(0);
        let count = ctrl_cxt.get_protocol_versions(PldmSupportedType::FwUpdate, &mut versions);
        assert_eq!(count, 2);
        assert_eq!(versions[..count], [0xF1F3F000, 0xF1F2F000]);

        assert!(ctrl_cxt.is_supported_type(PldmSupportedType::Base));
        assert!(ctrl_cxt.is_supported_type(PldmSupportedType::FwUpdate));
        assert!(!ctrl_cxt.is_supported_type(PldmSupportedType::Fru));
        assert!(ctrl_cxt.is_supported_version(
            PldmSupportedType::Base,
            0xF1F1F000 // "1.1.0"
        ));
        assert!(ctrl_cxt.is_supported_version(
            PldmSupportedType::Base,
            0xF1F0F000 // "1.0.0"
        ));
        assert!(ctrl_cxt.is_supported_version(
            PldmSupportedType::FwUpdate,
            0xF1F3F000 // "1.3.0"
        ));

        assert_eq!(
            ctrl_cxt.get_supported_commands(PldmSupportedType::Base, 0xF1F1F000),
            Some(&SUPPORTED_CTRL_CMDS[..])
        );
        assert_eq!(
            ctrl_cxt.get_supported_commands(PldmSupportedType::FwUpdate, 0xF1F3F000),
            Some(&SUPPORTED_FW_UDPATE_CMDS[..])
        );

        assert!(
            ctrl_cxt.is_supported_command(PldmSupportedType::Base, PldmControlCmd::SetTid as u8)
        );
        assert!(
            ctrl_cxt.is_supported_command(PldmSupportedType::Base, PldmControlCmd::GetTid as u8)
        );
        assert!(ctrl_cxt.is_supported_command(
            PldmSupportedType::Base,
            PldmControlCmd::GetPldmCommands as u8
        ));
        assert!(ctrl_cxt.is_supported_command(
            PldmSupportedType::Base,
            PldmControlCmd::GetPldmVersion as u8
        ));
        assert!(ctrl_cxt
            .is_supported_command(PldmSupportedType::Base, PldmControlCmd::GetPldmTypes as u8));

        assert!(ctrl_cxt.is_supported_command(
            PldmSupportedType::FwUpdate,
            FwUpdateCmd::QueryDeviceIdentifiers as u8
        ));
        assert!(ctrl_cxt.is_supported_command(
            PldmSupportedType::FwUpdate,
            FwUpdateCmd::GetFirmwareParameters as u8
        ));
        assert!(ctrl_cxt.is_supported_command(
            PldmSupportedType::FwUpdate,
            FwUpdateCmd::RequestUpdate as u8
        ));
        assert!(ctrl_cxt.is_supported_command(
            PldmSupportedType::FwUpdate,
            FwUpdateCmd::PassComponentTable as u8
        ));
        assert!(ctrl_cxt.is_supported_command(
            PldmSupportedType::FwUpdate,
            FwUpdateCmd::UpdateComponent as u8
        ));
        assert!(ctrl_cxt.is_supported_command(
            PldmSupportedType::FwUpdate,
            FwUpdateCmd::RequestFirmwareData as u8
        ));
        assert!(ctrl_cxt.is_supported_command(
            PldmSupportedType::FwUpdate,
            FwUpdateCmd::TransferComplete as u8
        ));
        assert!(ctrl_cxt.is_supported_command(
            PldmSupportedType::FwUpdate,
            FwUpdateCmd::VerifyComplete as u8
        ));
        assert!(ctrl_cxt.is_supported_command(
            PldmSupportedType::FwUpdate,
            FwUpdateCmd::ApplyComplete as u8
        ));
        assert!(ctrl_cxt.is_supported_command(
            PldmSupportedType::FwUpdate,
            FwUpdateCmd::ActivateFirmware as u8
        ));
        assert!(ctrl_cxt
            .is_supported_command(PldmSupportedType::FwUpdate, FwUpdateCmd::GetStatus as u8));
        assert!(ctrl_cxt
            .is_supported_command(PldmSupportedType::FwUpdate, FwUpdateCmd::CancelUpdate as u8));

        // Test unsupported command
        assert!(!ctrl_cxt.is_supported_command(PldmSupportedType::Base, 0x06));
        assert!(!ctrl_cxt.is_supported_command(PldmSupportedType::FwUpdate, 0x1E));
    }

    #[test]
    fn test_get_tid_responder() {
        let ctrl_cxt = ControlContext::new(&PLDM_PROTOCOL_CAPABILITIES);
        let mut msg_buf = [0u8; PAY_LOAD_BUFFER_LEN];
        construct_request(&mut msg_buf, GetTidRequest::new(0x01, PldmMsgType::Request));

        let resp_len = ctrl_cxt.get_tid_rsp(&mut msg_buf).unwrap();
        validate_response(
            &mut msg_buf[..resp_len],
            GetTidResponse::new(0x01, UNASSIGNED_TID, PldmBaseCompletionCode::Success as u8),
        );
    }

    #[test]
    fn test_set_tid_responder() {
        let ctrl_cxt = ControlContext::new(&PLDM_PROTOCOL_CAPABILITIES);
        let mut msg_buf = [0u8; PAY_LOAD_BUFFER_LEN];
        let assigned_tid = 0x02;

        construct_request(
            &mut msg_buf,
            SetTidRequest::new(0x02, PldmMsgType::Request, assigned_tid),
        );
        let resp_len = ctrl_cxt.set_tid_rsp(&mut msg_buf).unwrap();
        validate_response(
            &mut msg_buf[..resp_len],
            SetTidResponse::new(0x02, PldmBaseCompletionCode::Success as u8),
        );
        assert_eq!(ctrl_cxt.get_tid(), assigned_tid);

        // Reset msg buf
        msg_buf.fill(0);

        construct_request(&mut msg_buf, GetTidRequest::new(0x03, PldmMsgType::Request));
        let resp_len = ctrl_cxt.get_tid_rsp(&mut msg_buf).unwrap();
        validate_response(
            &mut msg_buf[..resp_len],
            GetTidResponse::new(0x03, assigned_tid, PldmBaseCompletionCode::Success as u8),
        );
    }

    #[test]
    fn test_get_pldm_types_responder() {
        let ctrl_cxt = ControlContext::new(&PLDM_PROTOCOL_CAPABILITIES);
        let mut msg_buf = [0u8; PAY_LOAD_BUFFER_LEN];

        construct_request(
            &mut msg_buf,
            GetPldmTypeRequest::new(0x04, PldmMsgType::Request),
        );
        let resp_len = ctrl_cxt.get_pldm_types_rsp(&mut msg_buf).unwrap();

        validate_response(
            &mut msg_buf[..resp_len],
            GetPldmTypeResponse::new(
                0x04,
                PldmBaseCompletionCode::Success as u8,
                &[
                    PldmSupportedType::Base as u8,
                    PldmSupportedType::FwUpdate as u8,
                ],
            ),
        );
    }

    #[test]
    fn test_get_pldm_commands_responder() {
        let ctrl_cxt = ControlContext::new(&PLDM_PROTOCOL_CAPABILITIES);
        let mut msg_buf = [0u8; PAY_LOAD_BUFFER_LEN];

        construct_request(
            &mut msg_buf,
            GetPldmCommandsRequest::new(
                0x05,
                PldmMsgType::Request,
                PldmSupportedType::Base as u8,
                "1.1.0",
            ),
        );
        let resp_len = ctrl_cxt.get_pldm_commands_rsp(&mut msg_buf).unwrap();
        validate_response(
            &mut msg_buf[..resp_len],
            GetPldmCommandsResponse::new(
                0x05,
                PldmBaseCompletionCode::Success as u8,
                &[
                    PldmControlCmd::SetTid as u8,
                    PldmControlCmd::GetTid as u8,
                    PldmControlCmd::GetPldmCommands as u8,
                    PldmControlCmd::GetPldmVersion as u8,
                    PldmControlCmd::GetPldmTypes as u8,
                ],
            ),
        );

        msg_buf.fill(0);

        construct_request(
            &mut msg_buf,
            GetPldmCommandsRequest::new(
                0x06,
                PldmMsgType::Request,
                PldmSupportedType::FwUpdate as u8,
                "1.3.0",
            ),
        );
        let resp_len = ctrl_cxt.get_pldm_commands_rsp(&mut msg_buf).unwrap();
        validate_response(
            &mut msg_buf[..resp_len],
            GetPldmCommandsResponse::new(
                0x06,
                PldmBaseCompletionCode::Success as u8,
                &[
                    FwUpdateCmd::QueryDeviceIdentifiers as u8,
                    FwUpdateCmd::GetFirmwareParameters as u8,
                    FwUpdateCmd::RequestUpdate as u8,
                    FwUpdateCmd::PassComponentTable as u8,
                    FwUpdateCmd::UpdateComponent as u8,
                    FwUpdateCmd::RequestFirmwareData as u8,
                    FwUpdateCmd::TransferComplete as u8,
                    FwUpdateCmd::VerifyComplete as u8,
                    FwUpdateCmd::ApplyComplete as u8,
                    FwUpdateCmd::ActivateFirmware as u8,
                    FwUpdateCmd::GetStatus as u8,
                    FwUpdateCmd::CancelUpdate as u8,
                ],
            ),
        );

        // Test get pldm commands request with invalid pldm type
        msg_buf.fill(0);
        construct_request(
            &mut msg_buf,
            GetPldmCommandsRequest::new(
                0x09,
                PldmMsgType::Request,
                PldmSupportedType::Fru as u8,
                "1.3.5",
            ),
        );
        let resp_len = ctrl_cxt.get_pldm_commands_rsp(&mut msg_buf).unwrap();
        validate_response(
            &mut msg_buf[..resp_len],
            PldmFailureResponse::new(
                0x09,
                PldmSupportedType::Base,
                PldmControlCmd::GetPldmCommands as u8,
                PldmControlCompletionCode::InvalidPldmTypeInRequestData as u8,
            ),
        );

        // Test get pldm commands request with invalid protocol version
        msg_buf.fill(0);
        construct_request(
            &mut msg_buf,
            GetPldmCommandsRequest::new(
                0x0A,
                PldmMsgType::Request,
                PldmSupportedType::Base as u8,
                "1.2.0",
            ),
        );
        let resp_len = ctrl_cxt.get_pldm_commands_rsp(&mut msg_buf).unwrap();
        validate_response(
            &mut msg_buf[..resp_len],
            PldmFailureResponse::new(
                0x0A,
                PldmSupportedType::Base,
                PldmControlCmd::GetPldmCommands as u8,
                PldmControlCompletionCode::InvalidPldmVersionInRequestData as u8,
            ),
        );

        // Test invalid length
        msg_buf.fill(0);
        construct_request(
            &mut msg_buf,
            GetPldmCommandsRequest::new(
                0x0A,
                PldmMsgType::Request,
                PldmSupportedType::Base as u8,
                "1.1.0",
            ),
        );
        let resp_len = ctrl_cxt
            .get_pldm_commands_rsp(&mut msg_buf[..PLDM_FAILURE_RESP_LEN + 1])
            .unwrap();
        assert_eq!(resp_len, PLDM_FAILURE_RESP_LEN);
        validate_response(
            &mut msg_buf[..resp_len],
            PldmFailureResponse::new(
                0x0A,
                PldmSupportedType::Base,
                PldmControlCmd::GetPldmCommands as u8,
                PldmBaseCompletionCode::InvalidLength as u8,
            ),
        );
    }

    #[test]
    fn test_get_version_responder() {
        let ctrl_cxt = ControlContext::new(&PLDM_PROTOCOL_CAPABILITIES);
        let mut msg_buf = [0u8; PAY_LOAD_BUFFER_LEN];

        // Test base protocol version
        construct_request(
            &mut msg_buf,
            GetPldmVersionRequest::new(
                0x07,
                PldmMsgType::Request,
                0,
                TransferOperationFlag::GetFirstPart,
                PldmSupportedType::Base,
            ),
        );
        let resp_len = ctrl_cxt.get_pldm_version_rsp(&mut msg_buf).unwrap();
        validate_response(
            &mut msg_buf[..resp_len],
            GetPldmVersionResponse::new(
                0x07,
                PldmBaseCompletionCode::Success as u8,
                0,
                TransferRespFlag::StartAndEnd,
                "1.1.0",
            )
            .unwrap(),
        );

        msg_buf.fill(0);

        // Test firmware update protocol version
        construct_request(
            &mut msg_buf,
            GetPldmVersionRequest::new(
                0x08,
                PldmMsgType::Request,
                0,
                TransferOperationFlag::GetFirstPart,
                PldmSupportedType::FwUpdate,
            ),
        );
        let resp_len = ctrl_cxt.get_pldm_version_rsp(&mut msg_buf).unwrap();
        validate_response(
            &mut msg_buf[..resp_len],
            GetPldmVersionResponse::new(
                0x08,
                PldmBaseCompletionCode::Success as u8,
                0,
                TransferRespFlag::StartAndEnd,
                "1.3.0",
            )
            .unwrap(),
        );

        // Test get pldm version request with invalid transfer operation flag
        msg_buf.fill(0);
        construct_request(
            &mut msg_buf,
            GetPldmVersionRequest::new(
                0x0B,
                PldmMsgType::Request,
                0,
                TransferOperationFlag::GetNextPart,
                PldmSupportedType::Base,
            ),
        );
        let resp_len = ctrl_cxt.get_pldm_version_rsp(&mut msg_buf).unwrap();
        validate_response(
            &mut msg_buf[..resp_len],
            PldmFailureResponse::new(
                0x0B,
                PldmSupportedType::Base,
                PldmControlCmd::GetPldmVersion as u8,
                PldmControlCompletionCode::InvalidTransferOperationFlag as u8,
            ),
        );
    }
}
