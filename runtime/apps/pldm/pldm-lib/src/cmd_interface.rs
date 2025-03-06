// Licensed under the Apache-2.0 license

use crate::control_context::{ControlContext, CtrlCmdResponder, ProtocolCapability};
use crate::error::MsgHandlerError;
use crate::transport::MctpTransport;
use core::sync::atomic::{AtomicBool, Ordering};
use libtock_platform::Syscalls;
use pldm_common::codec::PldmCodec;
use pldm_common::protocol::base::{
    PldmBaseCompletionCode, PldmControlCmd, PldmFailureResponse, PldmMsgHeader, PldmSupportedType,
};
use pldm_common::protocol::firmware_update::FwUpdateCmd;
use pldm_common::util::mctp_transport::PLDM_MSG_OFFSET;

pub const PLDM_PROTOCOL_CAP_COUNT: usize = 2;
pub type PldmCompletionErrorCode = u8;

pub static PLDM_PROTOCOL_CAPABILITIES: [ProtocolCapability<'static>; PLDM_PROTOCOL_CAP_COUNT] = [
    ProtocolCapability {
        pldm_type: PldmSupportedType::Base,
        protocol_version: 0xF1F1F000, //"1.1.0"
        supported_commands: &[
            PldmControlCmd::SetTid as u8,
            PldmControlCmd::GetTid as u8,
            PldmControlCmd::GetPldmCommands as u8,
            PldmControlCmd::GetPldmVersion as u8,
            PldmControlCmd::GetPldmTypes as u8,
        ],
    },
    ProtocolCapability {
        pldm_type: PldmSupportedType::FwUpdate,
        protocol_version: 0xF1F3F000, // "1.3.0"
        supported_commands: &[
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
    },
];

// Helper function to write a failure response message into payload
pub(crate) fn generate_failure_response(
    payload: &mut [u8],
    completion_code: u8,
) -> Result<usize, MsgHandlerError> {
    let header = PldmMsgHeader::decode(payload).map_err(MsgHandlerError::Codec)?;
    let resp = PldmFailureResponse {
        hdr: header.into_response(),
        completion_code,
    };
    resp.encode(payload).map_err(MsgHandlerError::Codec)
}

pub struct CmdInterface<'a, S: Syscalls> {
    transport: MctpTransport<S>,
    ctrl_ctx: ControlContext<'a>,
    busy: AtomicBool,
}

impl<'a, S: Syscalls> CmdInterface<'a, S> {
    pub fn new(drv_num: u32, capabilities: &'a [ProtocolCapability<'a>]) -> Self {
        let ctrl_ctx = ControlContext::new(capabilities);
        CmdInterface {
            transport: MctpTransport::<S>::new(drv_num),
            ctrl_ctx,
            busy: AtomicBool::new(false),
        }
    }

    pub async fn handle_msg(&mut self, msg_buf: &mut [u8]) -> Result<(), MsgHandlerError> {
        // Receive msg from mctp transport
        self.transport
            .receive_request(msg_buf)
            .await
            .map_err(MsgHandlerError::Transport)?;

        // Process the request
        let resp_len = self.process_request(msg_buf).await?;

        // Send the response
        self.transport
            .send_response(&msg_buf[..resp_len])
            .await
            .map_err(MsgHandlerError::Transport)
    }

    async fn process_request(&self, msg_buf: &mut [u8]) -> Result<usize, MsgHandlerError> {
        // Check if the handler is busy processing a request
        if self.busy.load(Ordering::SeqCst) {
            return Err(MsgHandlerError::NotReady);
        }

        self.busy.store(true, Ordering::SeqCst);

        // Get the pldm payload from msg_buf
        let payload = &mut msg_buf[PLDM_MSG_OFFSET..];
        let reserved_len = PLDM_MSG_OFFSET;

        let (pldm_type, cmd_opcode) = match self.preprocess_request(payload) {
            Ok(result) => result,
            Err(e) => {
                self.busy.store(false, Ordering::SeqCst);
                return Ok(reserved_len + generate_failure_response(payload, e)?);
            }
        };

        let resp_len = match pldm_type {
            PldmSupportedType::Base => self.process_control_cmd(cmd_opcode, payload),
            PldmSupportedType::FwUpdate => {
                // Placeholder for firmware update command handling logic
                Ok(0)
            }
            _ => {
                unreachable!()
            }
        };

        self.busy.store(false, Ordering::SeqCst);

        match resp_len {
            Ok(bytes) => Ok(reserved_len + bytes),
            Err(e) => Err(e),
        }
    }

    fn process_control_cmd(
        &self,
        cmd_opcode: u8,
        payload: &mut [u8],
    ) -> Result<usize, MsgHandlerError> {
        match PldmControlCmd::try_from(cmd_opcode) {
            Ok(cmd) => match cmd {
                PldmControlCmd::GetTid => self.ctrl_ctx.get_tid_rsp(payload),
                PldmControlCmd::SetTid => self.ctrl_ctx.set_tid_rsp(payload),
                PldmControlCmd::GetPldmTypes => self.ctrl_ctx.get_pldm_types_rsp(payload),
                PldmControlCmd::GetPldmCommands => self.ctrl_ctx.get_pldm_commands_rsp(payload),
                PldmControlCmd::GetPldmVersion => self.ctrl_ctx.get_pldm_version_rsp(payload),
            },
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::UnsupportedPldmCmd as u8)
            }
        }
    }

    fn preprocess_request(
        &self,
        payload: &[u8],
    ) -> Result<(PldmSupportedType, u8), PldmCompletionErrorCode> {
        let header = PldmMsgHeader::decode(payload)
            .map_err(|_| PldmBaseCompletionCode::InvalidData as u8)?;
        if !(header.is_request() && header.is_hdr_ver_valid()) {
            Err(PldmBaseCompletionCode::InvalidData as u8)?;
        }

        let pldm_type = PldmSupportedType::try_from(header.pldm_type())
            .map_err(|_| PldmBaseCompletionCode::InvalidPldmType as u8)?;

        if !self.ctrl_ctx.is_supported_type(pldm_type) {
            Err(PldmBaseCompletionCode::InvalidPldmType as u8)?;
        }

        let cmd_opcode = header.cmd_code();
        if self.ctrl_ctx.is_supported_command(pldm_type, cmd_opcode) {
            Ok((pldm_type, cmd_opcode))
        } else {
            Err(PldmBaseCompletionCode::UnsupportedPldmCmd as u8)
        }
    }
}
