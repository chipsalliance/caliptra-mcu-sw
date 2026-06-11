// Licensed under the Apache-2.0 license

use crate::control_context::{ControlContext, CtrlCmdResponder, ProtocolCapability};
use crate::errors;
use crate::firmware_device::fd_context::FirmwareDeviceContext;
use crate::transport::MctpTransport;
use caliptra_mcu_pldm_common::codec::PldmCodec;
use caliptra_mcu_pldm_common::protocol::base::{
    PldmBaseCompletionCode, PldmControlCmd, PldmFailureResponse, PldmMsgHeader, PldmSupportedType,
};
use caliptra_mcu_pldm_common::protocol::firmware_update::FwUpdateCmd;
use caliptra_mcu_pldm_common::util::mctp_transport::{
    construct_mctp_pldm_msg, extract_pldm_msg, MCTP_PLDM_MSG_HDR_LEN,
};
use core::sync::atomic::{AtomicBool, Ordering};
use mcu_error::McuResult;

pub type PldmCompletionErrorCode = u8;

/// Action the responder loop should take after handling a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponderAction {
    /// Continue processing messages.
    Continue,
    /// The PLDM session is complete (e.g. activation received); exit the loop.
    Complete,
}

// Helper function to write a failure response message into payload
pub(crate) fn generate_failure_response(
    payload: &mut [u8],
    completion_code: u8,
) -> McuResult<usize> {
    let header = PldmMsgHeader::decode(payload).map_err(|_| errors::CODEC_ERROR)?;
    let resp = PldmFailureResponse {
        hdr: header.into_response(),
        completion_code,
    };
    resp.encode(payload).map_err(|_| errors::CODEC_ERROR)
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
    ) -> McuResult<ResponderAction> {
        // Receive msg from mctp transport
        transport
            .receive_request(msg_buf)
            .await
            .map_err(|_| errors::TRANSPORT_ERROR)?;

        // Process the request
        let (resp_len, action) = self.process_request(msg_buf).await?;

        // Send the response
        transport
            .send_response(&msg_buf[..resp_len])
            .await
            .map_err(|_| errors::TRANSPORT_ERROR)?;

        Ok(action)
    }

    pub async fn handle_initiator_msg(
        &self,
        transport: &mut MctpTransport,
        msg_buf: &mut [u8],
    ) -> McuResult<()> {
        // Retrieve the UA EID from the configuration
        let ua_eid: u8 = crate::config::UA_EID;

        // Prepare the request payload
        let payload = construct_mctp_pldm_msg(msg_buf).map_err(|_| errors::UTIL_ERROR)?;
        let reserved_len = MCTP_PLDM_MSG_HDR_LEN;

        // Generate the request
        let req_len = self.fd_ctx.fd_progress(payload).await?;
        if req_len == 0 {
            return Ok(());
        }

        // Send the request
        transport
            .send_request(ua_eid, &msg_buf[..req_len + reserved_len])
            .await
            .map_err(|_| errors::TRANSPORT_ERROR)?;

        // Wait for and process the response
        transport
            .receive_response(msg_buf)
            .await
            .map_err(|_| errors::TRANSPORT_ERROR)?;

        let payload = extract_pldm_msg(msg_buf).map_err(|_| errors::UTIL_ERROR)?;

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
    pub fn now(&self) -> caliptra_mcu_pldm_common::protocol::firmware_update::PldmFdTime {
        self.fd_ctx.now()
    }

    /// Get the FdOps reference for download operations.
    pub fn ops(&self) -> &dyn crate::firmware_device::fd_ops::FdOps {
        self.fd_ctx.ops()
    }

    async fn process_request(&self, msg_buf: &mut [u8]) -> McuResult<(usize, ResponderAction)> {
        // Check if the handler is busy processing a request
        if self.busy.load(Ordering::SeqCst) {
            return Err(errors::NOT_READY);
        }

        self.busy.store(true, Ordering::SeqCst);

        // Get the pldm payload from msg_buf
        let payload = &mut msg_buf[MCTP_PLDM_MSG_HDR_LEN..];
        let reserved_len = MCTP_PLDM_MSG_HDR_LEN;

        let (pldm_type, cmd_opcode) = match self.preprocess_request(payload) {
            Ok(result) => result,
            Err(e) => {
                self.busy.store(false, Ordering::SeqCst);
                let len = reserved_len + generate_failure_response(payload, e)?;
                return Ok((len, ResponderAction::Continue));
            }
        };

        let result = match pldm_type {
            PldmSupportedType::Base => self
                .process_control_cmd(cmd_opcode, payload)
                .map(|len| (len, ResponderAction::Continue)),
            PldmSupportedType::FwUpdate => self.process_fw_update_cmd(cmd_opcode, payload).await,
            _ => {
                unreachable!()
            }
        };

        self.busy.store(false, Ordering::SeqCst);

        let (resp_len, action) = result?;
        Ok((reserved_len + resp_len, action))
    }

    fn process_control_cmd(&self, cmd_opcode: u8, payload: &mut [u8]) -> McuResult<usize> {
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
    ) -> McuResult<(usize, ResponderAction)> {
        match FwUpdateCmd::try_from(cmd_opcode) {
            Ok(cmd) => match cmd {
                FwUpdateCmd::QueryDeviceIdentifiers => self
                    .fd_ctx
                    .query_devid_rsp(payload)
                    .await
                    .map(|len| (len, ResponderAction::Continue)),
                FwUpdateCmd::GetFirmwareParameters => self
                    .fd_ctx
                    .get_firmware_parameters_rsp(payload)
                    .await
                    .map(|len| (len, ResponderAction::Continue)),
                FwUpdateCmd::RequestUpdate => self
                    .fd_ctx
                    .request_update_rsp(payload)
                    .await
                    .map(|len| (len, ResponderAction::Continue)),
                FwUpdateCmd::PassComponentTable => self
                    .fd_ctx
                    .pass_component_rsp(payload)
                    .await
                    .map(|len| (len, ResponderAction::Continue)),
                FwUpdateCmd::UpdateComponent => self
                    .fd_ctx
                    .update_component_rsp(payload)
                    .await
                    .map(|len| (len, ResponderAction::Continue)),

                FwUpdateCmd::ActivateFirmware => self
                    .fd_ctx
                    .activate_firmware_rsp(payload)
                    .await
                    .map(|len| (len, ResponderAction::Complete)),
                FwUpdateCmd::CancelUpdateComponent => self
                    .fd_ctx
                    .cancel_update_component_rsp(payload)
                    .await
                    .map(|len| (len, ResponderAction::Continue)),
                FwUpdateCmd::CancelUpdate => self
                    .fd_ctx
                    .cancel_update_rsp(payload)
                    .await
                    .map(|len| (len, ResponderAction::Complete)),
                FwUpdateCmd::GetStatus => self
                    .fd_ctx
                    .get_status_rsp(payload)
                    .await
                    .map(|len| (len, ResponderAction::Continue)),
                _ => generate_failure_response(
                    payload,
                    PldmBaseCompletionCode::UnsupportedPldmCmd as u8,
                )
                .map(|len| (len, ResponderAction::Continue)),
            },
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::UnsupportedPldmCmd as u8)
                    .map(|len| (len, ResponderAction::Continue))
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
