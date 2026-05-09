// Licensed under the Apache-2.0 license

use crate::control_context::{ControlContext, CtrlCmdResponder, ProtocolCapability};
use crate::error::MsgHandlerError;
use crate::firmware_device::fd_context::FirmwareDeviceContext;
use crate::transport::MctpTransport;
use core::sync::atomic::{AtomicBool, Ordering};
use pldm_common::codec::PldmCodec;
use pldm_common::protocol::base::{
    PldmBaseCompletionCode, PldmControlCmd, PldmFailureResponse, PldmMsgHeader, PldmSupportedType,
};
use pldm_common::protocol::firmware_update::FwUpdateCmd;
use pldm_common::util::mctp_transport::{
    construct_mctp_pldm_msg, extract_pldm_msg, PLDM_MSG_OFFSET,
};

pub type PldmCompletionErrorCode = u8;

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

pub struct CmdInterface<'a> {
    ctrl_ctx: ControlContext<'a>,
    fd_ctx: FirmwareDeviceContext<'a>,
    busy: AtomicBool,
}

impl<'a> CmdInterface<'a> {
    pub fn new(
        protocol_capabilities: &'a [ProtocolCapability],
        fd_ctx: FirmwareDeviceContext<'a>,
    ) -> Self {
        let ctrl_ctx = ControlContext::new(protocol_capabilities);
        Self {
            ctrl_ctx,
            fd_ctx,
            busy: AtomicBool::new(false),
        }
    }

    pub async fn handle_responder_msg(
        &self,
        transport: &mut MctpTransport,
        msg_buf: &mut [u8],
    ) -> Result<(), MsgHandlerError> {
        // Receive msg from mctp transport
        transport
            .receive_request(msg_buf)
            .await
            .map_err(MsgHandlerError::Transport)?;

        // Process the request
        let resp_len = self.process_request(msg_buf).await?;

        // Send the response
        transport
            .send_response(&msg_buf[..resp_len])
            .await
            .map_err(MsgHandlerError::Transport)
    }

    pub async fn handle_initiator_msg(
        &self,
        transport: &mut MctpTransport,
        msg_buf: &mut [u8],
    ) -> Result<(), MsgHandlerError> {
        // Retrieve the UA EID from the configuration
        let ua_eid: u8 = crate::config::UA_EID;

        // Prepare the request payload
        let payload = construct_mctp_pldm_msg(msg_buf).map_err(MsgHandlerError::Util)?;
        let reserved_len = PLDM_MSG_OFFSET;

        // Generate the request
        let req_len = self.fd_ctx.fd_progress(payload).await?;
        if req_len == 0 {
            return Ok(());
        }

        // Send the request
        transport
            .send_request(ua_eid, &msg_buf[..req_len + reserved_len])
            .await
            .map_err(MsgHandlerError::Transport)?;

        // Wait for and process the response
        transport
            .receive_response(msg_buf)
            .await
            .map_err(MsgHandlerError::Transport)?;

        let payload = extract_pldm_msg(msg_buf).map_err(MsgHandlerError::Util)?;

        // Handle the response
        self.fd_ctx.handle_response(payload).await?;

        Ok(())
    }

    pub async fn should_start_initiator_mode(&self) -> bool {
        self.fd_ctx.should_start_initiator_mode().await
    }

    pub async fn should_stop_initiator_mode(&self) -> bool {
        self.fd_ctx.should_stop_initiator_mode().await
    }

    /// Check if the current transfer has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.fd_ctx.is_cancelled()
    }

    /// Create a transfer session for optimized download.
    pub async fn create_transfer_session(
        &self,
    ) -> crate::firmware_device::transfer_session::TransferSession {
        self.fd_ctx.create_transfer_session().await
    }

    /// Sync state from a transfer session back to internal state.
    pub async fn sync_transfer_session(
        &self,
        session: &crate::firmware_device::transfer_session::TransferSession,
    ) {
        self.fd_ctx.sync_transfer_session(session).await;
    }

    /// Get current timestamp.
    pub fn now(&self) -> pldm_common::protocol::firmware_update::PldmFdTime {
        self.fd_ctx.now()
    }

    /// Get the FdOps reference for download operations.
    pub fn ops(&self) -> &dyn crate::firmware_device::fd_ops::FdOps {
        self.fd_ctx.ops()
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
            PldmSupportedType::FwUpdate => self.process_fw_update_cmd(cmd_opcode, payload).await,
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

    async fn process_fw_update_cmd(
        &self,
        cmd_opcode: u8,
        payload: &mut [u8],
    ) -> Result<usize, MsgHandlerError> {
        match FwUpdateCmd::try_from(cmd_opcode) {
            Ok(cmd) => match cmd {
                FwUpdateCmd::QueryDeviceIdentifiers => self.fd_ctx.query_devid_rsp(payload).await,
                FwUpdateCmd::GetFirmwareParameters => {
                    self.fd_ctx.get_firmware_parameters_rsp(payload).await
                }
                FwUpdateCmd::RequestUpdate => self.fd_ctx.request_update_rsp(payload).await,
                FwUpdateCmd::PassComponentTable => self.fd_ctx.pass_component_rsp(payload).await,
                FwUpdateCmd::UpdateComponent => self.fd_ctx.update_component_rsp(payload).await,

                FwUpdateCmd::ActivateFirmware => self.fd_ctx.activate_firmware_rsp(payload).await,
                FwUpdateCmd::CancelUpdateComponent => {
                    self.fd_ctx.cancel_update_component_rsp(payload).await
                }
                FwUpdateCmd::CancelUpdate => self.fd_ctx.cancel_update_rsp(payload).await,
                FwUpdateCmd::GetStatus => self.fd_ctx.get_status_rsp(payload).await,
                _ => generate_failure_response(
                    payload,
                    PldmBaseCompletionCode::UnsupportedPldmCmd as u8,
                ),
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
