// Licensed under the Apache-2.0 license

use crate::cmd_interface::generate_failure_response;
use crate::errors;
use crate::firmware_device::fd_internal::{FdInternal, FdReqState};
use crate::firmware_device::fd_ops::{ComponentOperation, FdOps};
use caliptra_mcu_pldm_common::codec::PldmCodec;
use caliptra_mcu_pldm_common::message::firmware_update::activate_fw::{
    ActivateFirmwareRequest, ActivateFirmwareResponse,
};
use caliptra_mcu_pldm_common::message::firmware_update::get_fw_params::{
    FirmwareParameters, GetFirmwareParametersRequest, GetFirmwareParametersResponse,
};
use caliptra_mcu_pldm_common::message::firmware_update::get_status::ProgressPercent;
use caliptra_mcu_pldm_common::message::firmware_update::pass_component::{
    PassComponentTableRequest, PassComponentTableResponse,
};
use caliptra_mcu_pldm_common::message::firmware_update::query_devid::{
    QueryDeviceIdentifiersRequest, QueryDeviceIdentifiersResponse,
};
use caliptra_mcu_pldm_common::message::firmware_update::request_cancel::{
    CancelUpdateComponentRequest, CancelUpdateComponentResponse, CancelUpdateRequest,
    CancelUpdateResponse,
};
use caliptra_mcu_pldm_common::message::firmware_update::request_update::{
    RequestUpdateRequest, RequestUpdateResponse,
};
use caliptra_mcu_pldm_common::message::firmware_update::transfer_complete::{
    TransferCompleteRequest, TransferResult,
};
use caliptra_mcu_pldm_common::message::firmware_update::update_component::{
    UpdateComponentRequest, UpdateComponentResponse,
};
use mcu_error::McuResult;

use caliptra_mcu_pldm_common::message::firmware_update::apply_complete::{
    ApplyCompleteRequest, ApplyResult,
};
use caliptra_mcu_pldm_common::message::firmware_update::get_status::{
    AuxState, AuxStateStatus, GetStatusReasonCode, GetStatusRequest, GetStatusResponse,
    UpdateOptionResp,
};
use caliptra_mcu_pldm_common::message::firmware_update::request_fw_data::{
    RequestFirmwareDataRequest, RequestFirmwareDataResponseFixed,
};
use caliptra_mcu_pldm_common::message::firmware_update::verify_complete::{
    VerifyCompleteRequest, VerifyResult,
};
use caliptra_mcu_pldm_common::protocol::base::{
    PldmBaseCompletionCode, PldmMsgHeader, PldmMsgType, TransferRespFlag,
};
use caliptra_mcu_pldm_common::protocol::firmware_update::{
    ComponentActivationMethods, ComponentCompatibilityResponse, ComponentCompatibilityResponseCode,
    ComponentResponse, ComponentResponseCode, Descriptor, FirmwareDeviceState, FwUpdateCmd,
    FwUpdateCompletionCode, PldmFirmwareString, UpdateOptionFlags, MAX_DESCRIPTORS_COUNT,
    PLDM_FWUP_BASELINE_TRANSFER_SIZE,
};
use caliptra_mcu_pldm_common::util::fw_component::FirmwareComponent;

use crate::firmware_device::fd_internal::{
    ApplyState, DownloadState, InitiatorModeState, VerifyState,
};
use crate::firmware_device::transfer_session::CancellationFlag;

pub struct FirmwareDeviceContext<'a> {
    ops: &'a dyn FdOps,
    internal: FdInternal,
    /// Cancellation flag for signaling download abort from responder task.
    cancellation_flag: CancellationFlag,
}

impl<'a> FirmwareDeviceContext<'a> {
    #[allow(clippy::new_without_default)]
    pub fn new(ops: &'a dyn FdOps) -> Self {
        Self {
            ops,
            internal: FdInternal::default(),
            cancellation_flag: CancellationFlag::new(),
        }
    }

    /// Mark whether the initiator has a response pending processing.
    /// Called by [`CmdInterface::handle_initiator_msg`].
    pub fn set_pending_response(&self, pending: bool) {
        self.internal.set_pending_response(pending);
    }

    /// Wait until the initiator signals that it has finished processing
    /// any pending response. Returns immediately if no response is pending.
    async fn wait_for_initiator(&self) {
        if self.internal.has_pending_response() {
            self.internal.wait_for_response_signal().await;
        }
    }

    pub async fn query_devid_rsp(&self, payload: &mut [u8]) -> McuResult<usize> {
        // Decode the request message
        let req =
            QueryDeviceIdentifiersRequest::decode(payload).map_err(|_| errors::CODEC_ERROR)?;

        let mut device_identifiers: [Descriptor; MAX_DESCRIPTORS_COUNT] =
            [Descriptor::default(); MAX_DESCRIPTORS_COUNT];

        // Get the device identifiers
        let descriptor_cnt = self
            .ops
            .get_device_identifiers(&mut device_identifiers)
            .map_err(|_| errors::FD_OPS_ERROR)?;

        // Create the response message
        let resp = QueryDeviceIdentifiersResponse::new(
            req.hdr.instance_id(),
            PldmBaseCompletionCode::Success as u8,
            &device_identifiers[0],
            device_identifiers.get(1..descriptor_cnt),
        )
        .map_err(|_| errors::PLDM_COMMON_ERROR)?;

        match resp.encode(payload) {
            Ok(bytes) => Ok(bytes),
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::InvalidLength as u8)
            }
        }
    }

    pub async fn get_firmware_parameters_rsp(&self, payload: &mut [u8]) -> McuResult<usize> {
        // Decode the request message
        let req = GetFirmwareParametersRequest::decode(payload).map_err(|_| errors::CODEC_ERROR)?;

        let mut firmware_params = FirmwareParameters::default();
        self.ops
            .get_firmware_parms(&mut firmware_params)
            .map_err(|_| errors::FD_OPS_ERROR)?;

        // Construct response
        let resp = GetFirmwareParametersResponse::new(
            req.hdr.instance_id(),
            PldmBaseCompletionCode::Success as u8,
            &firmware_params,
        );

        match resp.encode(payload) {
            Ok(bytes) => Ok(bytes),
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::InvalidLength as u8)
            }
        }
    }

    pub async fn request_update_rsp(&self, payload: &mut [u8]) -> McuResult<usize> {
        // Check if FD is in idle state. Otherwise returns 'ALREADY_IN_UPDATE_MODE' completion code
        if self.internal.is_update_mode() {
            return generate_failure_response(
                payload,
                FwUpdateCompletionCode::AlreadyInUpdateMode as u8,
            );
        }

        // Set timestamp for FD T1 timeout
        self.set_fd_t1_ts().await;

        // Decode the request message
        let req = RequestUpdateRequest::decode(payload).map_err(|_| errors::CODEC_ERROR)?;
        let ua_transfer_size = req.fixed.max_transfer_size as usize;
        if ua_transfer_size < PLDM_FWUP_BASELINE_TRANSFER_SIZE {
            return generate_failure_response(
                payload,
                FwUpdateCompletionCode::InvalidTransferLength as u8,
            );
        }

        // Get the transfer size for the firmware update operation
        let fd_transfer_size = self
            .ops
            .get_xfer_size(ua_transfer_size)
            .await
            .map_err(|_| errors::FD_OPS_ERROR)?;

        // Set transfer size to the internal state
        self.internal.set_xfer_size(fd_transfer_size);

        // Construct response, no metadata or package data.
        let resp = RequestUpdateResponse::new(
            req.fixed.hdr.instance_id(),
            PldmBaseCompletionCode::Success as u8,
            0,
            0,
            None,
        );

        match resp.encode(payload) {
            Ok(bytes) => {
                // Move FD state to 'LearnComponents'
                self.internal
                    .set_fd_state(FirmwareDeviceState::LearnComponents);
                Ok(bytes)
            }
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::InvalidLength as u8)
            }
        }
    }

    pub async fn pass_component_rsp(&self, payload: &mut [u8]) -> McuResult<usize> {
        // Check if FD is in 'LearnComponents' state. Otherwise returns 'INVALID_STATE' completion code
        if self.internal.get_fd_state() != FirmwareDeviceState::LearnComponents {
            return generate_failure_response(
                payload,
                FwUpdateCompletionCode::InvalidStateForCommand as u8,
            );
        }

        // Set timestamp for FD T1 timeout
        self.set_fd_t1_ts().await;

        // Decode the request message
        let req = PassComponentTableRequest::decode(payload).map_err(|_| errors::CODEC_ERROR)?;
        let transfer_flag = match TransferRespFlag::try_from(req.fixed.transfer_flag) {
            Ok(flag) => flag,
            Err(_) => {
                return generate_failure_response(
                    payload,
                    PldmBaseCompletionCode::InvalidData as u8,
                )
            }
        };

        // Construct temporary storage for the component
        let pass_comp = FirmwareComponent::new(
            req.fixed.comp_classification,
            req.fixed.comp_identifier,
            req.fixed.comp_classification_index,
            req.fixed.comp_comparison_stamp,
            PldmFirmwareString {
                str_type: req.fixed.comp_ver_str_type,
                str_len: req.fixed.comp_ver_str_len,
                str_data: req.comp_ver_str,
            },
            None,
            None,
        );

        let mut firmware_params = FirmwareParameters::default();
        self.ops
            .get_firmware_parms(&mut firmware_params)
            .map_err(|_| errors::FD_OPS_ERROR)?;

        let comp_resp_code = self
            .ops
            .handle_component(
                &pass_comp,
                &firmware_params,
                ComponentOperation::PassComponent,
            )
            .map_err(|_| errors::FD_OPS_ERROR)?;

        // Construct response
        let resp = PassComponentTableResponse::new(
            req.fixed.hdr.instance_id(),
            PldmBaseCompletionCode::Success as u8,
            if comp_resp_code == ComponentResponseCode::CompCanBeUpdated {
                ComponentResponse::CompCanBeUpdated
            } else {
                ComponentResponse::CompCannotBeUpdated
            },
            comp_resp_code,
        );

        match resp.encode(payload) {
            Ok(bytes) => {
                // Move FD state to 'ReadyTransfer' when the last component is passed
                if transfer_flag == TransferRespFlag::End
                    || transfer_flag == TransferRespFlag::StartAndEnd
                {
                    self.internal.set_fd_state(FirmwareDeviceState::ReadyXfer);
                }
                Ok(bytes)
            }
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::InvalidLength as u8)
            }
        }
    }

    pub async fn update_component_rsp(&self, payload: &mut [u8]) -> McuResult<usize> {
        // Ensure the initiator task has finished processing any pending
        // response (e.g. ApplyComplete for the previous component) before
        // we inspect the FD state.
        self.wait_for_initiator().await;

        // Check if FD is in 'ReadyTransfer' state. Otherwise returns 'INVALID_STATE' completion code
        if self.internal.get_fd_state() != FirmwareDeviceState::ReadyXfer {
            return generate_failure_response(
                payload,
                FwUpdateCompletionCode::InvalidStateForCommand as u8,
            );
        }

        // Set timestamp for FD T1 timeout
        self.set_fd_t1_ts().await;

        // Decode the request message
        let req = UpdateComponentRequest::decode(payload).map_err(|_| errors::CODEC_ERROR)?;

        // Construct temporary storage for the component
        let update_comp = FirmwareComponent::new(
            req.fixed.comp_classification,
            req.fixed.comp_identifier,
            req.fixed.comp_classification_index,
            req.fixed.comp_comparison_stamp,
            PldmFirmwareString {
                str_type: req.fixed.comp_ver_str_type,
                str_len: req.fixed.comp_ver_str_len,
                str_data: req.comp_ver_str,
            },
            Some(req.fixed.comp_image_size),
            Some(UpdateOptionFlags(req.fixed.update_option_flags)),
        );

        // Store the component info into the internal state.
        self.internal.set_component(&update_comp);

        // Adjust the update flags based on the device's capabilities if needed. Currently, the flags are set as received from the UA.
        self.internal
            .set_update_flags(UpdateOptionFlags(req.fixed.update_option_flags));

        let mut firmware_params = FirmwareParameters::default();
        self.ops
            .get_firmware_parms(&mut firmware_params)
            .map_err(|_| errors::FD_OPS_ERROR)?;

        let comp_resp_code = self
            .ops
            .handle_component(
                &update_comp,
                &firmware_params,
                ComponentOperation::UpdateComponent, /* This indicates this is an update request */
            )
            .map_err(|_| errors::FD_OPS_ERROR)?;

        // Construct response
        let resp = UpdateComponentResponse::new(
            req.fixed.hdr.instance_id(),
            PldmBaseCompletionCode::Success as u8,
            if comp_resp_code == ComponentResponseCode::CompCanBeUpdated {
                ComponentCompatibilityResponse::CompCanBeUpdated
            } else {
                ComponentCompatibilityResponse::CompCannotBeUpdated
            },
            ComponentCompatibilityResponseCode::try_from(comp_resp_code as u8).unwrap(),
            UpdateOptionFlags(req.fixed.update_option_flags),
            0,
            None,
        );

        match resp.encode(payload) {
            Ok(bytes) => {
                if comp_resp_code == ComponentResponseCode::CompCanBeUpdated {
                    self.internal
                        .set_initiator_mode(InitiatorModeState::Download(DownloadState::default()));
                    // Set up the req for download.
                    self.internal
                        .set_fd_req(FdReqState::Ready, false, None, None, None, None);

                    // Move FD state machine to download state.
                    self.internal.set_fd_state(FirmwareDeviceState::Download);
                }
                Ok(bytes)
            }
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::InvalidLength as u8)
            }
        }
    }

    pub async fn activate_firmware_rsp(&self, payload: &mut [u8]) -> McuResult<usize> {
        // Ensure the initiator task has finished processing any pending
        // response (e.g. ApplyComplete) before we inspect the FD state.
        // This eliminates the Apply/Activate race condition at its root.
        self.wait_for_initiator().await;

        // Check if FD is in 'ReadyTransfer' state. Otherwise returns 'INVALID_STATE' completion code
        if self.internal.get_fd_state() != FirmwareDeviceState::ReadyXfer {
            return generate_failure_response(
                payload,
                FwUpdateCompletionCode::InvalidStateForCommand as u8,
            );
        }

        // Decode the request message
        let req = ActivateFirmwareRequest::decode(payload).map_err(|_| errors::CODEC_ERROR)?;
        let self_contained = req.self_contained_activation_req;

        // Validate self_contained value
        match self_contained {
            0 | 1 => {}
            _ => {
                return generate_failure_response(
                    payload,
                    PldmBaseCompletionCode::InvalidData as u8,
                )
            }
        }

        let mut estimated_time = 0u16;
        let completion_code = self
            .ops
            .activate(self_contained, &mut estimated_time)
            .map_err(|_| errors::FD_OPS_ERROR)?;

        // Construct response
        let resp =
            ActivateFirmwareResponse::new(req.hdr.instance_id(), completion_code, estimated_time);

        match resp.encode(payload) {
            Ok(bytes) => {
                if completion_code == PldmBaseCompletionCode::Success as u8
                    || completion_code == FwUpdateCompletionCode::ActivationNotRequired as u8
                {
                    self.internal.set_fd_state(FirmwareDeviceState::Activate);
                    if self_contained == 0 {
                        // If activation is not self-contained, then consider the FW already activated
                        self.internal.set_fd_idle(GetStatusReasonCode::ActivateFw);
                    }
                }
                Ok(bytes)
            }
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::InvalidLength as u8)
            }
        }
    }

    pub async fn cancel_update_component_rsp(&self, payload: &mut [u8]) -> McuResult<usize> {
        // If FD is not in update mode, return 'NOT_IN_UPDATE_MODE' completion code
        if !self.internal.is_update_mode() {
            return generate_failure_response(
                payload,
                FwUpdateCompletionCode::NotInUpdateMode as u8,
            );
        }

        let fd_state = self.internal.get_fd_state();
        let should_cancel = match fd_state {
            FirmwareDeviceState::Download | FirmwareDeviceState::Verify => true,
            FirmwareDeviceState::Apply => {
                // In apply state, only cancel if not completed successfully
                !(self.internal.get_fd_req().complete
                    && self.internal.get_fd_req().result == Some(ApplyResult::ApplySuccess as u8))
            }
            _ => {
                return generate_failure_response(
                    payload,
                    FwUpdateCompletionCode::InvalidStateForCommand as u8,
                );
            }
        };

        if should_cancel {
            // Signal cancellation to the download loop
            self.cancellation_flag.cancel();
            self.ops
                .cancel_update_component(&self.internal.get_component())
                .map_err(|_| errors::FD_OPS_ERROR)?;
        }

        // Decode the request message
        let req = CancelUpdateComponentRequest::decode(payload).map_err(|_| errors::CODEC_ERROR)?;
        let completion_code = if should_cancel {
            PldmBaseCompletionCode::Success as u8
        } else {
            PldmBaseCompletionCode::Error as u8
        };

        let resp = CancelUpdateComponentResponse::new(req.hdr.instance_id(), completion_code);
        match resp.encode(payload) {
            Ok(bytes) => {
                if should_cancel {
                    // Set FD state to 'ReadyTransfer'
                    self.internal.set_fd_state(FirmwareDeviceState::ReadyXfer);
                }
                Ok(bytes)
            }
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::InvalidLength as u8)
            }
        }
    }

    pub async fn cancel_update_rsp(&self, payload: &mut [u8]) -> McuResult<usize> {
        // If FD is not in update mode, return 'NOT_IN_UPDATE_MODE' completion code
        if !self.internal.is_update_mode() {
            return generate_failure_response(
                payload,
                FwUpdateCompletionCode::NotInUpdateMode as u8,
            );
        }

        // Set timestamp for FD T1 timeout
        self.set_fd_t1_ts().await;

        let fd_state = self.internal.get_fd_state();
        let should_cancel = match fd_state {
            FirmwareDeviceState::Download | FirmwareDeviceState::Verify => true,
            FirmwareDeviceState::Apply => {
                // In apply state, only cancel if not completed successfully
                !(self.internal.get_fd_req().complete
                    && self.internal.get_fd_req().result == Some(ApplyResult::ApplySuccess as u8))
            }
            _ => false,
        };

        if should_cancel {
            // Signal cancellation to the download loop
            self.cancellation_flag.cancel();
            self.ops
                .cancel_update_component(&self.internal.get_component())
                .map_err(|_| errors::FD_OPS_ERROR)?;
        }

        // Decode the request message
        let req = CancelUpdateRequest::decode(payload).map_err(|_| errors::CODEC_ERROR)?;
        let completion_code = if should_cancel {
            PldmBaseCompletionCode::Success as u8
        } else {
            PldmBaseCompletionCode::Error as u8
        };

        let (non_functioning_component_indication, non_functioning_component_bitmap) = self
            .ops
            .get_non_functional_component_info()
            .await
            .map_err(|_| errors::FD_OPS_ERROR)?;

        let resp = CancelUpdateResponse::new(
            req.hdr.instance_id(),
            completion_code,
            non_functioning_component_indication,
            non_functioning_component_bitmap,
        );

        match resp.encode(payload) {
            Ok(bytes) => {
                if should_cancel {
                    // Set FD state to 'Idle'
                    self.internal.set_fd_idle(GetStatusReasonCode::CancelUpdate);
                }
                Ok(bytes)
            }
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::InvalidLength as u8)
            }
        }
    }

    pub async fn get_status_rsp(&self, payload: &mut [u8]) -> McuResult<usize> {
        let req = GetStatusRequest::decode(payload).map_err(|_| errors::CODEC_ERROR)?;

        let cur_state = self.internal.get_fd_state();
        let prev_state = self.internal.get_fd_prev_state();
        let (progress_percent, update_flags) = match cur_state {
            FirmwareDeviceState::Download => {
                let mut progress = ProgressPercent::default();
                let _ = self
                    .ops
                    .query_download_progress(&self.internal.get_component(), &mut progress);
                let update_flags = self.internal.get_update_flags();
                (progress, update_flags)
            }
            FirmwareDeviceState::Verify => {
                let progress = if let Some(percent) = self.internal.get_fd_verify_progress() {
                    ProgressPercent::new(percent).unwrap()
                } else {
                    ProgressPercent::default()
                };
                let update_flags = self.internal.get_update_flags();
                (progress, update_flags)
            }
            FirmwareDeviceState::Apply => {
                let progress = if let Some(percent) = self.internal.get_fd_apply_progress() {
                    ProgressPercent::new(percent).unwrap()
                } else {
                    ProgressPercent::default()
                };
                let update_flags = self.internal.get_update_flags();
                (progress, update_flags)
            }
            _ => (ProgressPercent::default(), self.internal.get_update_flags()),
        };

        let (aux_state, aux_state_status) = match self.internal.get_fd_req_state() {
            FdReqState::Unused => (
                AuxState::IdleLearnComponentsReadXfer,
                AuxStateStatus::AuxStateInProgressOrSuccess as u8,
            ),
            FdReqState::Sent => (
                AuxState::OperationInProgress,
                AuxStateStatus::AuxStateInProgressOrSuccess as u8,
            ),
            FdReqState::Ready => {
                if self.internal.is_fd_req_complete() {
                    (
                        AuxState::OperationSuccessful,
                        AuxStateStatus::AuxStateInProgressOrSuccess as u8,
                    )
                } else {
                    (
                        AuxState::OperationInProgress,
                        AuxStateStatus::AuxStateInProgressOrSuccess as u8,
                    )
                }
            }
            FdReqState::Failed => {
                let status = self
                    .internal
                    .get_fd_req_result()
                    .unwrap_or(AuxStateStatus::GenericError as u8);
                (AuxState::OperationFailed, status)
            }
        };

        let resp = GetStatusResponse::new(
            req.hdr.instance_id(),
            PldmBaseCompletionCode::Success as u8,
            cur_state,
            prev_state,
            aux_state,
            aux_state_status,
            progress_percent,
            self.internal
                .get_fd_reason()
                .unwrap_or(GetStatusReasonCode::Initialization),
            if update_flags.request_force_update() {
                UpdateOptionResp::ForceUpdate
            } else {
                UpdateOptionResp::NoForceUpdate
            },
        );

        match resp.encode(payload) {
            Ok(bytes) => Ok(bytes),
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::InvalidLength as u8)
            }
        }
    }

    pub async fn set_fd_t1_ts(&self) {
        self.internal.set_fd_t1_update_ts(self.ops.now());
    }

    pub async fn should_start_initiator_mode(&self) -> bool {
        self.internal.get_fd_state() == FirmwareDeviceState::Download
    }

    pub async fn should_stop_initiator_mode(&self) -> bool {
        !matches!(
            self.internal.get_fd_state(),
            FirmwareDeviceState::Download
                | FirmwareDeviceState::Verify
                | FirmwareDeviceState::Apply
        )
    }

    pub async fn fd_progress(&self, payload: &mut [u8]) -> McuResult<usize> {
        let fd_state = self.internal.get_fd_state();

        let result = match fd_state {
            FirmwareDeviceState::Download => self.fd_progress_download(payload).await,
            FirmwareDeviceState::Verify => self.pldm_fd_progress_verify(payload).await,
            FirmwareDeviceState::Apply => self.pldm_fd_progress_apply(payload).await,
            _ => Err(errors::FD_INITIATOR_MODE_ERROR),
        }?;

        // Refresh T1 timestamp after verify/apply operations which may block
        // for extended periods while the firmware update task processes.
        if fd_state == FirmwareDeviceState::Verify || fd_state == FirmwareDeviceState::Apply {
            self.set_fd_t1_ts().await;
        }

        let now = self.ops.now();
        let ts = self.internal.get_fd_t1_update_ts();
        let elapsed = now.saturating_sub(ts);
        // If a response is not received within T1 in FD-driven states, cancel the update and transition to idle state.
        if (fd_state == FirmwareDeviceState::Download
            || fd_state == FirmwareDeviceState::Verify
            || fd_state == FirmwareDeviceState::Apply)
            && self.internal.get_fd_req_state() == FdReqState::Sent
            && elapsed > self.internal.get_fd_t1_timeout()
        {
            self.ops
                .cancel_update_component(&self.internal.get_component())
                .map_err(|_| errors::FD_OPS_ERROR)?;
            self.internal.fd_idle_timeout();
            return Ok(0);
        }

        Ok(result)
    }

    pub async fn handle_response(&self, payload: &mut [u8]) -> McuResult<()> {
        let rsp_header =
            PldmMsgHeader::<[u8; 3]>::decode(payload).map_err(|_| errors::CODEC_ERROR)?;
        let (cmd_code, instance_id) = (rsp_header.cmd_code(), rsp_header.instance_id());

        let fd_req = self.internal.get_fd_req();
        if fd_req.state != FdReqState::Sent
            || fd_req.instance_id != Some(instance_id)
            || fd_req.command != Some(cmd_code)
        {
            // Unexpected response
            return Err(errors::FD_INITIATOR_MODE_ERROR);
        }

        self.set_fd_t1_ts().await;

        match FwUpdateCmd::try_from(cmd_code) {
            Ok(FwUpdateCmd::RequestFirmwareData) => self.process_request_fw_data_rsp(payload).await,
            Ok(FwUpdateCmd::TransferComplete) => self.process_transfer_complete_rsp(payload).await,
            Ok(FwUpdateCmd::VerifyComplete) => self.process_verify_complete_rsp(payload).await,
            Ok(FwUpdateCmd::ApplyComplete) => self.process_apply_complete_rsp(payload).await,
            _ => Err(errors::FD_INITIATOR_MODE_ERROR),
        }
    }

    async fn process_request_fw_data_rsp(&self, payload: &mut [u8]) -> McuResult<()> {
        let fd_state = self.internal.get_fd_state();
        if fd_state != FirmwareDeviceState::Download {
            return Err(errors::FD_INITIATOR_MODE_ERROR);
        }

        let fd_req = self.internal.get_fd_req();
        if fd_req.complete {
            // Received data after completion
            return Err(errors::FD_INITIATOR_MODE_ERROR);
        }

        // Decode the response message fixed
        let fw_data_rsp_fixed: RequestFirmwareDataResponseFixed =
            RequestFirmwareDataResponseFixed::decode(payload).map_err(|_| errors::CODEC_ERROR)?;

        match fw_data_rsp_fixed.completion_code {
            code if code == PldmBaseCompletionCode::Success as u8 => {}
            code if code == FwUpdateCompletionCode::RetryRequestFwData as u8 => return Ok(()),
            _ => {
                self.internal.set_fd_req(
                    FdReqState::Ready,
                    true,
                    Some(TransferResult::FdAbortedTransfer as u8),
                    None,
                    None,
                    None,
                );
                return Ok(());
            }
        }

        let (offset, length) = self.internal.get_fd_download_state().unwrap();

        let fw_data = payload[core::mem::size_of::<RequestFirmwareDataResponseFixed>()..]
            .get(..length as usize)
            .ok_or(errors::CODEC_ERROR)?;

        let fw_component = &self.internal.get_component();
        let res = self
            .ops
            .download_fw_data(offset as usize, fw_data, fw_component)
            .await
            .map_err(|_| errors::FD_OPS_ERROR)?;

        if res == TransferResult::TransferSuccess {
            if self.ops.is_download_complete(fw_component) {
                // Mark as complete, next progress() call will send the TransferComplete request
                self.internal.set_fd_req(
                    FdReqState::Ready,
                    true,
                    Some(TransferResult::TransferSuccess as u8),
                    None,
                    None,
                    None,
                );
            } else {
                // Invoke another request if there is more data to download
                self.internal
                    .set_fd_req(FdReqState::Ready, false, None, None, None, None);
            }
        } else {
            // Pass the callback error as the TransferResult
            self.internal
                .set_fd_req(FdReqState::Ready, true, Some(res as u8), None, None, None);
        }
        Ok(())
    }

    async fn process_transfer_complete_rsp(&self, _payload: &mut [u8]) -> McuResult<()> {
        let fd_state = self.internal.get_fd_state();
        if fd_state != FirmwareDeviceState::Download {
            return Err(errors::FD_INITIATOR_MODE_ERROR);
        }

        let fd_req = self.internal.get_fd_req();
        if fd_req.state != FdReqState::Sent || !fd_req.complete {
            return Err(errors::FD_INITIATOR_MODE_ERROR);
        }

        /* Next state depends whether the transfer succeeded */
        if fd_req.result == Some(TransferResult::TransferSuccess as u8) {
            // Switch to Verify
            self.internal
                .set_initiator_mode(InitiatorModeState::Verify(VerifyState::default()));
            self.internal
                .set_fd_req(FdReqState::Ready, false, None, None, None, None);
            self.internal.set_fd_state(FirmwareDeviceState::Verify);
        } else {
            // Wait for UA to cancel
            self.internal
                .set_fd_req(FdReqState::Failed, true, fd_req.result, None, None, None);
        }

        Ok(())
    }

    async fn process_verify_complete_rsp(&self, _payload: &mut [u8]) -> McuResult<()> {
        let fd_state = self.internal.get_fd_state();
        if fd_state != FirmwareDeviceState::Verify {
            return Err(errors::FD_INITIATOR_MODE_ERROR);
        }

        let fd_req = self.internal.get_fd_req();
        if fd_req.state != FdReqState::Sent || !fd_req.complete {
            return Err(errors::FD_INITIATOR_MODE_ERROR);
        }

        /* Next state depends whether the verify succeeded */
        if fd_req.result == Some(VerifyResult::VerifySuccess as u8) {
            // Switch to Apply
            self.internal
                .set_initiator_mode(InitiatorModeState::Apply(ApplyState::default()));
            self.internal
                .set_fd_req(FdReqState::Ready, false, None, None, None, None);
            self.internal.set_fd_state(FirmwareDeviceState::Apply);
        } else {
            // Wait for UA to cancel
            self.internal
                .set_fd_req(FdReqState::Failed, true, fd_req.result, None, None, None);
        }

        Ok(())
    }

    async fn process_apply_complete_rsp(&self, _payload: &mut [u8]) -> McuResult<()> {
        let fd_state = self.internal.get_fd_state();
        if fd_state != FirmwareDeviceState::Apply {
            return Err(errors::FD_INITIATOR_MODE_ERROR);
        }

        let fd_req = self.internal.get_fd_req();
        if fd_req.state != FdReqState::Sent || !fd_req.complete {
            return Err(errors::FD_INITIATOR_MODE_ERROR);
        }

        if fd_req.result == Some(ApplyResult::ApplySuccess as u8) {
            // Switch to Xfer
            self.internal
                .set_fd_req(FdReqState::Unused, false, None, None, None, None);
            self.internal.set_fd_state(FirmwareDeviceState::ReadyXfer);
        } else {
            // Wait for UA to cancel
            self.internal
                .set_fd_req(FdReqState::Failed, true, fd_req.result, None, None, None);
        }

        Ok(())
    }

    /// Test-only wrapper for `process_apply_complete_rsp`.
    #[cfg(test)]
    pub async fn process_apply_complete_rsp_for_test(&self, payload: &mut [u8]) -> McuResult<()> {
        self.process_apply_complete_rsp(payload).await
    }

    async fn fd_progress_download(&self, payload: &mut [u8]) -> McuResult<usize> {
        // Get offset and length from ops first (this is async but outside the batch)
        // We need to do this before the batch because query_download_offset_and_length
        // needs the component, and getting it requires a lock.
        // For now, we'll get component separately to call query_download_offset_and_length.
        let component = self.internal.get_component();
        let (requested_offset, requested_length) = self
            .ops
            .query_download_offset_and_length(&component)
            .await
            .map_err(|_| errors::FD_OPS_ERROR)?;

        // Use batch operation to prepare the download request
        let info = self
            .internal
            .prepare_download_request(requested_offset as u32, requested_length as u32)
            .ok_or(errors::FD_INITIATOR_MODE_ERROR)?;

        // If the request is complete, send TransferComplete
        if info.is_complete {
            let result = info.result.ok_or(errors::FD_INITIATOR_MODE_ERROR)?;

            let msg_len = TransferCompleteRequest::new(
                info.instance_id,
                PldmMsgType::Request,
                TransferResult::try_from(result).unwrap(),
            )
            .encode(payload)
            .map_err(|_| errors::CODEC_ERROR)?;

            // Finalize request state in a single batch operation
            let req_sent_timestamp = self.ops.now();
            self.internal.finalize_download_request(
                0,
                0,
                info.instance_id,
                FwUpdateCmd::TransferComplete as u8,
                req_sent_timestamp,
                true,
                Some(result),
            );

            Ok(msg_len)
        } else {
            let (chunk_offset, chunk_length) =
                info.chunk_info.ok_or(errors::FD_INITIATOR_MODE_ERROR)?;

            let msg_len = RequestFirmwareDataRequest::new(
                info.instance_id,
                PldmMsgType::Request,
                chunk_offset,
                chunk_length,
            )
            .encode(payload)
            .map_err(|_| errors::CODEC_ERROR)?;

            // Finalize download state and request state in a single batch operation
            let req_sent_timestamp = self.ops.now();
            self.internal.finalize_download_request(
                chunk_offset,
                chunk_length,
                info.instance_id,
                FwUpdateCmd::RequestFirmwareData as u8,
                req_sent_timestamp,
                false,
                None,
            );

            Ok(msg_len)
        }
    }

    async fn pldm_fd_progress_verify(&self, _payload: &mut [u8]) -> McuResult<usize> {
        if !self.should_send_fd_request().await {
            return Err(errors::FD_INITIATOR_MODE_ERROR);
        }

        let mut res = VerifyResult::default();
        if !self.internal.is_fd_req_complete() {
            let mut progress_percent = ProgressPercent::default();
            res = self
                .ops
                .verify(&self.internal.get_component(), &mut progress_percent)
                .await
                .map_err(|_| errors::FD_OPS_ERROR)?;

            // Set the progress percent to VerifyState
            self.internal
                .set_fd_verify_progress(progress_percent.value());

            if res == VerifyResult::VerifySuccess && progress_percent.value() < 100 {
                // doing nothing and wait for the next call
                return Ok(0);
            }
        }

        let instance_id = self.internal.alloc_next_instance_id().unwrap();
        let verify_complete_req =
            VerifyCompleteRequest::new(instance_id, PldmMsgType::Request, res);

        // Encode the request message
        let msg_len = verify_complete_req
            .encode(_payload)
            .map_err(|_| errors::CODEC_ERROR)?;

        self.internal.set_fd_req(
            FdReqState::Sent,
            true,
            Some(res as u8),
            Some(instance_id),
            Some(FwUpdateCmd::VerifyComplete as u8),
            Some(self.ops.now()),
        );

        Ok(msg_len)
    }

    async fn pldm_fd_progress_apply(&self, _payload: &mut [u8]) -> McuResult<usize> {
        if !self.should_send_fd_request().await {
            return Err(errors::FD_INITIATOR_MODE_ERROR);
        }

        let mut res = ApplyResult::default();
        if !self.internal.is_fd_req_complete() {
            let mut progress_percent = ProgressPercent::default();
            res = self
                .ops
                .apply(&self.internal.get_component(), &mut progress_percent)
                .await
                .map_err(|_| errors::FD_OPS_ERROR)?;

            // Set the progress percent to ApplyState
            self.internal
                .set_fd_apply_progress(progress_percent.value());

            if res == ApplyResult::ApplySuccess && progress_percent.value() < 100 {
                // doing nothing and wait for the next call
                return Ok(0);
            }
        }

        // Allocate the next instance ID
        let instance_id = self.internal.alloc_next_instance_id().unwrap();
        let apply_complete_req = ApplyCompleteRequest::new(
            instance_id,
            PldmMsgType::Request,
            res,
            ComponentActivationMethods(0),
        );
        // Encode the request message
        let msg_len = apply_complete_req
            .encode(_payload)
            .map_err(|_| errors::CODEC_ERROR)?;

        self.internal.set_fd_req(
            FdReqState::Sent,
            true,
            Some(res as u8),
            Some(instance_id),
            Some(FwUpdateCmd::ApplyComplete as u8),
            Some(self.ops.now()),
        );

        Ok(msg_len)
    }

    async fn should_send_fd_request(&self) -> bool {
        let now = self.ops.now();

        let fd_req_state = self.internal.get_fd_req_state();
        match fd_req_state {
            FdReqState::Unused => false,
            FdReqState::Ready => true,
            FdReqState::Failed => false,
            FdReqState::Sent => {
                let fd_req_sent_time = self.internal.get_fd_sent_time().unwrap();
                if now < fd_req_sent_time {
                    // Time went backwards
                    return false;
                }

                // Send if retry time has elapsed
                (now - fd_req_sent_time) >= self.internal.get_fd_t2_retry_time()
            }
        }
    }

    /// Check if cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancellation_flag.is_cancelled()
    }

    /// Reset the cancellation flag (called when starting a new transfer).
    pub fn reset_cancellation(&self) {
        self.cancellation_flag.reset();
    }

    /// Create a transfer session for optimized download.
    /// This captures the current state to avoid mutex acquisitions in the hot path.
    pub async fn create_transfer_session(&self) -> super::transfer_session::TransferSession {
        self.reset_cancellation();
        self.internal.create_transfer_session(self.ops.now())
    }

    /// Sync state from a transfer session back to internal state.
    pub async fn sync_transfer_session(&self, session: &super::transfer_session::TransferSession) {
        self.internal.sync_from_transfer_session(session);
    }

    /// Get current timestamp from ops.
    pub fn now(&self) -> caliptra_mcu_pldm_common::protocol::firmware_update::PldmFdTime {
        self.ops.now()
    }

    /// Get the ops reference for download operations.
    pub fn ops(&self) -> &dyn FdOps {
        self.ops
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use caliptra_mcu_pldm_common::codec::PldmCodec;
    use caliptra_mcu_pldm_common::message::firmware_update::activate_fw::{
        ActivateFirmwareRequest, ActivateFirmwareResponse, SelfContainedActivationRequest,
    };
    use caliptra_mcu_pldm_common::message::firmware_update::apply_complete::ApplyResult;
    use caliptra_mcu_pldm_common::message::firmware_update::update_component::{
        UpdateComponentRequest, UpdateComponentResponse,
    };
    use caliptra_mcu_pldm_common::protocol::base::{
        PldmBaseCompletionCode, PldmFailureResponse, PldmMsgType,
    };
    use caliptra_mcu_pldm_common::protocol::firmware_update::{
        ComponentClassification, FirmwareDeviceState, FwUpdateCmd, FwUpdateCompletionCode,
        PldmFirmwareString, UpdateOptionFlags,
    };
    use futures::executor::block_on;

    use crate::firmware_device::fd_internal::FdReqState;
    use crate::firmware_device::fd_ops::FdOps;

    /// Minimal mock FdOps for testing.
    struct MockFdOps;

    #[async_trait::async_trait(?Send)]
    impl FdOps for MockFdOps {
        fn get_device_identifiers(
            &self,
            _device_identifiers: &mut [caliptra_mcu_pldm_common::protocol::firmware_update::Descriptor],
        ) -> McuResult<usize> {
            Ok(0)
        }
        fn get_firmware_parms(
            &self,
            _firmware_params: &mut caliptra_mcu_pldm_common::message::firmware_update::get_fw_params::FirmwareParameters,
        ) -> McuResult<()> {
            Ok(())
        }
        async fn get_xfer_size(&self, ua_transfer_size: usize) -> McuResult<usize> {
            Ok(ua_transfer_size)
        }
        fn handle_component(
            &self,
            _component: &caliptra_mcu_pldm_common::util::fw_component::FirmwareComponent,
            _fw_params: &caliptra_mcu_pldm_common::message::firmware_update::get_fw_params::FirmwareParameters,
            _op: ComponentOperation,
        ) -> McuResult<caliptra_mcu_pldm_common::protocol::firmware_update::ComponentResponseCode>
        {
            Ok(caliptra_mcu_pldm_common::protocol::firmware_update::ComponentResponseCode::CompCanBeUpdated)
        }
        async fn query_download_offset_and_length(
            &self,
            _component: &caliptra_mcu_pldm_common::util::fw_component::FirmwareComponent,
        ) -> McuResult<(usize, usize)> {
            Ok((0, 0))
        }
        async fn download_fw_data(
            &self,
            _offset: usize,
            _data: &[u8],
            _component: &caliptra_mcu_pldm_common::util::fw_component::FirmwareComponent,
        ) -> McuResult<
            caliptra_mcu_pldm_common::message::firmware_update::transfer_complete::TransferResult,
        > {
            Ok(caliptra_mcu_pldm_common::message::firmware_update::transfer_complete::TransferResult::TransferSuccess)
        }
        fn is_download_complete(
            &self,
            _component: &caliptra_mcu_pldm_common::util::fw_component::FirmwareComponent,
        ) -> bool {
            true
        }
        fn query_download_progress(
            &self,
            _component: &caliptra_mcu_pldm_common::util::fw_component::FirmwareComponent,
            _progress_percent: &mut caliptra_mcu_pldm_common::message::firmware_update::get_status::ProgressPercent,
        ) -> McuResult<()> {
            Ok(())
        }
        async fn verify(
            &self,
            _component: &caliptra_mcu_pldm_common::util::fw_component::FirmwareComponent,
            _progress_percent: &mut caliptra_mcu_pldm_common::message::firmware_update::get_status::ProgressPercent,
        ) -> McuResult<
            caliptra_mcu_pldm_common::message::firmware_update::verify_complete::VerifyResult,
        > {
            Ok(caliptra_mcu_pldm_common::message::firmware_update::verify_complete::VerifyResult::VerifySuccess)
        }
        async fn apply(
            &self,
            _component: &caliptra_mcu_pldm_common::util::fw_component::FirmwareComponent,
            _progress_percent: &mut caliptra_mcu_pldm_common::message::firmware_update::get_status::ProgressPercent,
        ) -> McuResult<ApplyResult> {
            Ok(ApplyResult::ApplySuccess)
        }
        fn activate(
            &self,
            _self_contained_activation: u8,
            _estimated_time: &mut u16,
        ) -> McuResult<u8> {
            Ok(PldmBaseCompletionCode::Success as u8)
        }
        fn cancel_update_component(
            &self,
            _component: &caliptra_mcu_pldm_common::util::fw_component::FirmwareComponent,
        ) -> McuResult<()> {
            Ok(())
        }
        fn now(&self) -> caliptra_mcu_pldm_common::protocol::firmware_update::PldmFdTime {
            0
        }
    }

    fn encode_activate_firmware_request(payload: &mut [u8]) -> usize {
        let req = ActivateFirmwareRequest::new(
            1,
            PldmMsgType::Request,
            SelfContainedActivationRequest::ActivateSelfContainedComponents,
        );
        req.encode(payload).unwrap()
    }

    fn encode_update_component_request(payload: &mut [u8]) -> usize {
        let ver_str = PldmFirmwareString::new("UTF-8", "fw-v2.0").unwrap();
        let req = UpdateComponentRequest::new(
            2,
            PldmMsgType::Request,
            ComponentClassification::Firmware,
            0x0001,
            0,
            0x12345678,
            1024,
            UpdateOptionFlags(0),
            &ver_str,
        );
        req.encode(payload).unwrap()
    }

    // =========================================================================
    // Signal mechanism tests
    // =========================================================================

    /// Verify the pending_response signal mechanism: set_pending_response(true)
    /// sets the flag, set_pending_response(false) clears it and signals.
    #[test]
    fn test_pending_response_signal_mechanism() {
        let mock_ops = MockFdOps;
        let fd_ctx = FirmwareDeviceContext::new(&mock_ops);

        // Initially no response pending
        assert!(!fd_ctx.internal.has_pending_response());

        // Set pending
        fd_ctx.set_pending_response(true);
        assert!(fd_ctx.internal.has_pending_response());

        // Clear pending (also signals)
        fd_ctx.set_pending_response(false);
        assert!(!fd_ctx.internal.has_pending_response());

        // wait_for_initiator returns immediately when no response pending
        block_on(fd_ctx.wait_for_initiator());
    }

    /// Verify that wait_for_initiator returns immediately after the signal
    /// has been sent (i.e. pending_response was cleared).
    #[test]
    fn test_wait_for_initiator_returns_after_signal() {
        let mock_ops = MockFdOps;
        let fd_ctx = FirmwareDeviceContext::new(&mock_ops);

        // Simulate: initiator sets pending, then clears (signal is sent).
        fd_ctx.set_pending_response(true);
        fd_ctx.set_pending_response(false);

        // Signal was already sent, so even if we re-set and check, the signal
        // has been consumed. Just verify no deadlock with no pending response.
        block_on(fd_ctx.wait_for_initiator());
    }

    // =========================================================================
    // Two-task simulation: initiator processes response first (guaranteed by
    // the signal), then responder handles the next command.
    // =========================================================================

    /// Simulate the correct two-task sequence for ActivateFirmware:
    /// 1. Initiator processes ApplyComplete response → transitions Apply→ReadyXfer
    /// 2. Responder handles ActivateFirmwareRequest → state is ReadyXfer → succeeds
    ///
    /// This is the ordering that the signal mechanism guarantees at runtime.
    #[test]
    fn test_two_task_activate_firmware_with_signal_ordering() {
        let mock_ops = MockFdOps;
        let fd_ctx = FirmwareDeviceContext::new(&mock_ops);

        // Setup: state=Apply, pending successful ApplyComplete
        fd_ctx.internal.set_fd_state(FirmwareDeviceState::Apply);
        fd_ctx.internal.set_fd_req(
            FdReqState::Sent,
            true,
            Some(ApplyResult::ApplySuccess as u8),
            Some(1),
            Some(FwUpdateCmd::ApplyComplete as u8),
            Some(0),
        );

        // === TASK 1 (Initiator) — processes ApplyComplete response first ===
        // The signal mechanism ensures this always runs before the responder.
        let mut apply_rsp_payload = [0u8; 256];
        let initiator_result =
            block_on(fd_ctx.process_apply_complete_rsp_for_test(&mut apply_rsp_payload));
        assert!(initiator_result.is_ok());
        assert_eq!(
            fd_ctx.internal.get_fd_state(),
            FirmwareDeviceState::ReadyXfer,
            "Initiator should transition to ReadyXfer"
        );

        // Initiator clears pending_response (signal fires, responder unblocks)
        fd_ctx.set_pending_response(false);

        // === TASK 2 (Responder) — handles ActivateFirmwareRequest ===
        // wait_for_initiator returns immediately (no pending response)
        let mut activate_payload = [0u8; 256];
        encode_activate_firmware_request(&mut activate_payload);

        let responder_result = block_on(fd_ctx.activate_firmware_rsp(&mut activate_payload));
        assert!(responder_result.is_ok());
        let resp = ActivateFirmwareResponse::decode(&activate_payload).unwrap();
        assert_eq!(resp.completion_code, PldmBaseCompletionCode::Success as u8);
        assert_eq!(
            fd_ctx.internal.get_fd_state(),
            FirmwareDeviceState::Activate,
        );
    }

    /// Simulate the correct two-task sequence for multi-component UpdateComponent:
    /// 1. Initiator processes ApplyComplete response → transitions Apply→ReadyXfer
    /// 2. Responder handles UpdateComponent for next component → succeeds
    #[test]
    fn test_two_task_update_component_with_signal_ordering() {
        let mock_ops = MockFdOps;
        let fd_ctx = FirmwareDeviceContext::new(&mock_ops);

        // Setup: state=Apply, pending successful ApplyComplete
        fd_ctx.internal.set_fd_state(FirmwareDeviceState::Apply);
        fd_ctx.internal.set_fd_req(
            FdReqState::Sent,
            true,
            Some(ApplyResult::ApplySuccess as u8),
            Some(1),
            Some(FwUpdateCmd::ApplyComplete as u8),
            Some(0),
        );

        // === TASK 1 (Initiator) — processes ApplyComplete response first ===
        let mut apply_rsp_payload = [0u8; 256];
        let initiator_result =
            block_on(fd_ctx.process_apply_complete_rsp_for_test(&mut apply_rsp_payload));
        assert!(initiator_result.is_ok());
        assert_eq!(
            fd_ctx.internal.get_fd_state(),
            FirmwareDeviceState::ReadyXfer,
        );

        fd_ctx.set_pending_response(false);

        // === TASK 2 (Responder) — handles UpdateComponent ===
        let mut payload = [0u8; 512];
        encode_update_component_request(&mut payload);

        let responder_result = block_on(fd_ctx.update_component_rsp(&mut payload));
        assert!(responder_result.is_ok());
        let resp = UpdateComponentResponse::decode(&payload).unwrap();
        assert_eq!(resp.completion_code, PldmBaseCompletionCode::Success as u8);
        assert_eq!(
            fd_ctx.internal.get_fd_state(),
            FirmwareDeviceState::Download,
        );
    }

    // =========================================================================
    // State validation tests (handlers reject invalid states)
    // =========================================================================

    /// Test that activate_firmware_rsp succeeds when state is ReadyXfer
    /// (the normal, non-racy case with no pending response).
    #[test]
    fn test_activate_firmware_in_ready_xfer_state() {
        let mock_ops = MockFdOps;
        let fd_ctx = FirmwareDeviceContext::new(&mock_ops);

        fd_ctx.internal.set_fd_state(FirmwareDeviceState::ReadyXfer);

        let mut payload = [0u8; 256];
        encode_activate_firmware_request(&mut payload);

        let result = block_on(fd_ctx.activate_firmware_rsp(&mut payload));
        assert!(result.is_ok());

        let resp = ActivateFirmwareResponse::decode(&payload).unwrap();
        assert_eq!(resp.completion_code, PldmBaseCompletionCode::Success as u8);
    }

    /// Verify that activate_firmware_rsp rejects requests in invalid states.
    #[test]
    fn test_activate_firmware_rejected_in_wrong_state() {
        let mock_ops = MockFdOps;
        let fd_ctx = FirmwareDeviceContext::new(&mock_ops);

        fd_ctx.internal.set_fd_state(FirmwareDeviceState::Download);

        let mut payload = [0u8; 256];
        encode_activate_firmware_request(&mut payload);

        let result = block_on(fd_ctx.activate_firmware_rsp(&mut payload));
        assert!(result.is_ok());

        let resp = PldmFailureResponse::decode(&payload).unwrap();
        assert_eq!(
            resp.completion_code,
            FwUpdateCompletionCode::InvalidStateForCommand as u8
        );
    }

    /// Verify that update_component_rsp rejects requests in invalid states.
    #[test]
    fn test_update_component_rejected_in_wrong_state() {
        let mock_ops = MockFdOps;
        let fd_ctx = FirmwareDeviceContext::new(&mock_ops);

        fd_ctx.internal.set_fd_state(FirmwareDeviceState::Download);

        let mut payload = [0u8; 512];
        encode_update_component_request(&mut payload);

        let result = block_on(fd_ctx.update_component_rsp(&mut payload));
        assert!(result.is_ok());

        let resp = PldmFailureResponse::decode(&payload).unwrap();
        assert_eq!(
            resp.completion_code,
            FwUpdateCompletionCode::InvalidStateForCommand as u8
        );
    }
}
