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
        // Check if FD is in 'ReadyTransfer' state. Otherwise returns 'INVALID_STATE' completion code
        if self.internal.get_fd_state() != FirmwareDeviceState::ReadyXfer {
            // Race condition (same pattern as activate_firmware_rsp): In a multi-component
            // update, the UA sends UpdateComponent for the next component immediately after
            // responding to ApplyComplete(Success). If the executor polls this responder
            // task before the initiator task processes the ApplyComplete response, the state
            // is still Apply. Detect this case and perform the pending transition.
            if self.internal.get_fd_state() == FirmwareDeviceState::Apply {
                let fd_req = self.internal.get_fd_req();
                if fd_req.state == FdReqState::Sent
                    && fd_req.complete
                    && fd_req.command == Some(FwUpdateCmd::ApplyComplete as u8)
                    && fd_req.result == Some(ApplyResult::ApplySuccess as u8)
                {
                    self.internal
                        .set_fd_req(FdReqState::Unused, false, None, None, None, None);
                    self.internal.set_fd_state(FirmwareDeviceState::ReadyXfer);
                } else {
                    return generate_failure_response(
                        payload,
                        FwUpdateCompletionCode::InvalidStateForCommand as u8,
                    );
                }
            } else {
                return generate_failure_response(
                    payload,
                    FwUpdateCompletionCode::InvalidStateForCommand as u8,
                );
            }
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
        // Check if FD is in 'ReadyTransfer' state. Otherwise returns 'INVALID_STATE' completion code
        if self.internal.get_fd_state() != FirmwareDeviceState::ReadyXfer {
            // Race condition: The UA may send ActivateFirmwareRequest immediately after
            // responding to ApplyComplete. If the executor polls this responder task before
            // the initiator task processes the ApplyComplete response, the state is still
            // Apply. Detect this case and perform the pending transition to ReadyXfer.
            if self.internal.get_fd_state() == FirmwareDeviceState::Apply {
                let fd_req = self.internal.get_fd_req();
                if fd_req.state == FdReqState::Sent
                    && fd_req.complete
                    && fd_req.command == Some(FwUpdateCmd::ApplyComplete as u8)
                    && fd_req.result == Some(ApplyResult::ApplySuccess as u8)
                {
                    // The ApplyComplete response has been received by the transport layer
                    // (evidenced by ActivateFirmwareRequest arriving), but the initiator
                    // task hasn't processed it yet. Perform the state transition now.
                    self.internal
                        .set_fd_req(FdReqState::Unused, false, None, None, None, None);
                    self.internal.set_fd_state(FirmwareDeviceState::ReadyXfer);
                } else {
                    return generate_failure_response(
                        payload,
                        FwUpdateCompletionCode::InvalidStateForCommand as u8,
                    );
                }
            } else {
                return generate_failure_response(
                    payload,
                    FwUpdateCompletionCode::InvalidStateForCommand as u8,
                );
            }
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
            // If the state has already advanced past Apply (e.g., the responder task
            // processed ActivateFirmwareRequest or UpdateComponent first and performed
            // the Apply→ReadyXfer transition), this is not an error — the transition
            // was already handled.
            if fd_state == FirmwareDeviceState::ReadyXfer
                || fd_state == FirmwareDeviceState::Activate
                || fd_state == FirmwareDeviceState::Download
            {
                return Ok(());
            }
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
    pub async fn handle_apply_complete_rsp_for_test(&self, payload: &mut [u8]) -> McuResult<()> {
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
    use caliptra_mcu_pldm_common::protocol::base::{
        PldmBaseCompletionCode, PldmFailureResponse, PldmMsgType,
    };
    use caliptra_mcu_pldm_common::protocol::firmware_update::{
        FirmwareDeviceState, FwUpdateCmd, FwUpdateCompletionCode,
    };
    use futures::executor::block_on;

    use crate::firmware_device::fd_internal::FdReqState;
    use crate::firmware_device::fd_ops::FdOps;

    /// Minimal mock FdOps for testing activate_firmware_rsp.
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

    /// Test that activate_firmware_rsp succeeds when the FD state is ReadyXfer
    /// (the normal, non-racy case).
    #[test]
    fn test_activate_firmware_in_ready_xfer_state() {
        let mock_ops = MockFdOps;
        let fd_ctx = FirmwareDeviceContext::new(&mock_ops);

        // Set state to ReadyXfer (the expected state)
        fd_ctx.internal.set_fd_state(FirmwareDeviceState::ReadyXfer);

        let mut payload = [0u8; 256];
        encode_activate_firmware_request(&mut payload);

        let result = block_on(fd_ctx.activate_firmware_rsp(&mut payload));
        assert!(result.is_ok());

        let resp = ActivateFirmwareResponse::decode(&payload).unwrap();
        assert_eq!(resp.completion_code, PldmBaseCompletionCode::Success as u8);
    }

    #[test]
    fn test_activate_firmware_race_condition_apply_state_with_pending_apply_complete() {
        let mock_ops = MockFdOps;
        let fd_ctx = FirmwareDeviceContext::new(&mock_ops);

        // Set state to Apply with a pending successful ApplyComplete request.
        // This simulates the state when:
        //   1. The initiator sent ApplyComplete(Success) to the UA
        //   2. The UA responded and immediately sent ActivateFirmwareRequest
        //   3. The responder task is polled before the initiator task processes the response
        fd_ctx.internal.set_fd_state(FirmwareDeviceState::Apply);
        fd_ctx.internal.set_fd_req(
            FdReqState::Sent,
            true, // complete
            Some(ApplyResult::ApplySuccess as u8),
            Some(1), // instance_id
            Some(FwUpdateCmd::ApplyComplete as u8),
            Some(0), // sent_time
        );

        let mut payload = [0u8; 256];
        encode_activate_firmware_request(&mut payload);

        // With the fix, activate_firmware_rsp should detect the pending transition,
        // perform Apply→ReadyXfer, and then succeed.
        let result = block_on(fd_ctx.activate_firmware_rsp(&mut payload));
        assert!(
            result.is_ok(),
            "activate_firmware_rsp should succeed during Apply→ReadyXfer race"
        );

        let resp = ActivateFirmwareResponse::decode(&payload).unwrap();
        assert_eq!(
            resp.completion_code,
            PldmBaseCompletionCode::Success as u8,
            "Expected success completion code, not InvalidStateForCommand"
        );

        // Verify the state has advanced to Activate (activate was successful)
        assert_eq!(
            fd_ctx.internal.get_fd_state(),
            FirmwareDeviceState::Activate
        );
    }

    /// Emulate the two-task race condition from issue #1764 end-to-end.
    ///
    /// In the real system, `pldm_responder_task` and `pldm_initiator_task` run
    /// as concurrent Embassy tasks sharing the same `FirmwareDeviceContext`.
    /// The race occurs during the Apply→Activate transition:
    ///
    ///   1. Initiator sends ApplyComplete(Success) and awaits response
    ///   2. UA responds to ApplyComplete + sends ActivateFirmwareRequest back-to-back
    ///   3. Both packets arrive: response → initiator, request → responder
    ///   4. Embassy executor polls tasks in arbitrary order
    ///
    /// This test simulates BOTH execution orderings to prove the fix handles either:
    ///   - "Responder first" (the racy order that triggers the bug)
    ///   - "Initiator first" (the normal order)
    #[test]
    fn test_two_task_race_responder_polled_before_initiator() {
        // Simulate two concurrent tasks sharing the same FirmwareDeviceContext.
        // Embassy is single-threaded: the "race" is which task the executor polls first.
        let mock_ops = MockFdOps;
        let fd_ctx = FirmwareDeviceContext::new(&mock_ops);

        // === Setup: Both tasks have received their packets ===
        // The initiator sent ApplyComplete(Success) and the response came back.
        // Simultaneously, the UA sent ActivateFirmwareRequest.
        // State reflects "initiator sent ApplyComplete but hasn't processed the response yet."
        fd_ctx.internal.set_fd_state(FirmwareDeviceState::Apply);
        fd_ctx.internal.set_fd_req(
            FdReqState::Sent,
            true, // complete (apply operation succeeded)
            Some(ApplyResult::ApplySuccess as u8),
            Some(1), // instance_id
            Some(FwUpdateCmd::ApplyComplete as u8),
            Some(0), // sent_time
        );

        // === TASK 1 (Responder) — polled FIRST by executor (the racy ordering) ===
        // Responder received ActivateFirmwareRequest from UA and calls activate_firmware_rsp.
        // Without the fix, this would fail because state is still Apply (not ReadyXfer).
        let mut activate_payload = [0u8; 256];
        encode_activate_firmware_request(&mut activate_payload);

        let responder_result = block_on(fd_ctx.activate_firmware_rsp(&mut activate_payload));
        assert!(
            responder_result.is_ok(),
            "Responder task: activate_firmware_rsp must not fail when polled before initiator"
        );
        let resp = ActivateFirmwareResponse::decode(&activate_payload).unwrap();
        assert_eq!(
            resp.completion_code,
            PldmBaseCompletionCode::Success as u8,
            "Responder task: expected Success, got InvalidStateForCommand (0x84) — the race bug!"
        );

        // After responder completes: state should be Activate
        assert_eq!(
            fd_ctx.internal.get_fd_state(),
            FirmwareDeviceState::Activate,
            "State should be Activate after successful activation"
        );

        // === TASK 2 (Initiator) — polled SECOND by executor ===
        // Initiator now processes the ApplyComplete response it received.
        // With the fix, this is a no-op because the responder already performed
        // the Apply→ReadyXfer→Activate transitions.
        let mut apply_rsp_payload = [0u8; 256];
        let initiator_result =
            block_on(fd_ctx.handle_apply_complete_rsp_for_test(&mut apply_rsp_payload));
        assert!(
            initiator_result.is_ok(),
            "Initiator task: process_apply_complete_rsp must tolerate state already advanced"
        );

        // Final state should remain Activate (initiator didn't break anything)
        assert_eq!(
            fd_ctx.internal.get_fd_state(),
            FirmwareDeviceState::Activate,
        );
    }

    /// The non-racy ordering: initiator processes ApplyComplete response first,
    /// then responder handles ActivateFirmwareRequest. This should always work
    /// regardless of the fix, but we verify it for completeness.
    #[test]
    fn test_two_task_normal_order_initiator_polled_before_responder() {
        let mock_ops = MockFdOps;
        let fd_ctx = FirmwareDeviceContext::new(&mock_ops);

        // Same setup: state=Apply, pending successful ApplyComplete
        fd_ctx.internal.set_fd_state(FirmwareDeviceState::Apply);
        fd_ctx.internal.set_fd_req(
            FdReqState::Sent,
            true,
            Some(ApplyResult::ApplySuccess as u8),
            Some(1),
            Some(FwUpdateCmd::ApplyComplete as u8),
            Some(0),
        );

        // === TASK 1 (Initiator) — polled FIRST (the normal/happy path) ===
        // Initiator processes ApplyComplete response → transitions Apply→ReadyXfer
        let mut apply_rsp_payload = [0u8; 256];
        let initiator_result =
            block_on(fd_ctx.handle_apply_complete_rsp_for_test(&mut apply_rsp_payload));
        assert!(initiator_result.is_ok());
        assert_eq!(
            fd_ctx.internal.get_fd_state(),
            FirmwareDeviceState::ReadyXfer,
            "Initiator should transition to ReadyXfer"
        );

        // === TASK 2 (Responder) — polled SECOND ===
        // Responder processes ActivateFirmwareRequest — state is now ReadyXfer (no race)
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

    /// Verify that activate_firmware_rsp still correctly rejects requests when
    /// the FD state is Apply but ApplyComplete was NOT successful (no race, genuine error).
    #[test]
    fn test_activate_firmware_rejected_in_apply_state_without_successful_apply_complete() {
        let mock_ops = MockFdOps;
        let fd_ctx = FirmwareDeviceContext::new(&mock_ops);

        // State is Apply but fd_req is not in the "pending successful ApplyComplete" state
        fd_ctx.internal.set_fd_state(FirmwareDeviceState::Apply);
        fd_ctx.internal.set_fd_req(
            FdReqState::Ready, // Not Sent - no pending response
            false,
            None,
            None,
            None,
            None,
        );

        let mut payload = [0u8; 256];
        encode_activate_firmware_request(&mut payload);

        let result = block_on(fd_ctx.activate_firmware_rsp(&mut payload));
        assert!(result.is_ok()); // Returns Ok with failure completion code

        let resp = PldmFailureResponse::decode(&payload).unwrap();
        assert_eq!(
            resp.completion_code,
            FwUpdateCompletionCode::InvalidStateForCommand as u8,
            "Should reject with InvalidStateForCommand when not a race condition"
        );
    }

    /// Verify that activate_firmware_rsp rejects requests in invalid states
    /// (e.g., Download, Verify) where the race condition logic should not apply.
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

    /// Test that process_apply_complete_rsp tolerates the state having already
    /// advanced past Apply (the other half of the race condition fix).
    /// When the responder already performed the Apply→ReadyXfer→Activate transition,
    /// the initiator's process_apply_complete_rsp should be a no-op.
    #[test]
    fn test_process_apply_complete_rsp_tolerates_advanced_state() {
        let mock_ops = MockFdOps;
        let fd_ctx = FirmwareDeviceContext::new(&mock_ops);

        // Simulate: responder already transitioned to Activate
        fd_ctx.internal.set_fd_state(FirmwareDeviceState::Activate);

        let mut payload = [0u8; 256];
        let result = block_on(fd_ctx.handle_apply_complete_rsp_for_test(&mut payload));
        assert!(
            result.is_ok(),
            "process_apply_complete_rsp should tolerate Activate state"
        );

        // Also test with ReadyXfer state
        fd_ctx.internal.set_fd_state(FirmwareDeviceState::ReadyXfer);

        let result = block_on(fd_ctx.handle_apply_complete_rsp_for_test(&mut payload));
        assert!(
            result.is_ok(),
            "process_apply_complete_rsp should tolerate ReadyXfer state"
        );
    }

    // =========================================================================
    // Multi-component race condition tests (UpdateComponent after ApplyComplete)
    // =========================================================================

    use caliptra_mcu_pldm_common::message::firmware_update::update_component::{
        UpdateComponentRequest, UpdateComponentResponse,
    };
    use caliptra_mcu_pldm_common::protocol::firmware_update::{
        ComponentClassification, PldmFirmwareString, UpdateOptionFlags,
    };

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

    /// Multi-component race condition: UA sends UpdateComponent for the next
    /// component immediately after responding to ApplyComplete(Success) for the
    /// previous component. Same root cause as issue #1764 but for multi-component
    /// firmware updates.
    #[test]
    fn test_two_task_race_update_component_after_apply_complete() {
        let mock_ops = MockFdOps;
        let fd_ctx = FirmwareDeviceContext::new(&mock_ops);

        // Setup: FD just sent ApplyComplete(Success) for component N.
        // The UA responded and immediately sent UpdateComponent for component N+1.
        // State is still Apply because initiator hasn't processed the response.
        fd_ctx.internal.set_fd_state(FirmwareDeviceState::Apply);
        fd_ctx.internal.set_fd_req(
            FdReqState::Sent,
            true,
            Some(ApplyResult::ApplySuccess as u8),
            Some(1),
            Some(FwUpdateCmd::ApplyComplete as u8),
            Some(0),
        );

        // === TASK 1 (Responder) — polled FIRST (racy ordering) ===
        // Responder receives UpdateComponent for the next component.
        // Without the fix, this returns InvalidStateForCommand (state=Apply, not ReadyXfer).
        let mut payload = [0u8; 512];
        encode_update_component_request(&mut payload);

        let result = block_on(fd_ctx.update_component_rsp(&mut payload));
        assert!(
            result.is_ok(),
            "Responder: update_component_rsp must not fail during Apply→ReadyXfer race"
        );

        let resp = UpdateComponentResponse::decode(&payload).unwrap();
        assert_eq!(
            resp.completion_code,
            PldmBaseCompletionCode::Success as u8,
            "Responder: expected Success, not InvalidStateForCommand (0x84)"
        );

        // State should now be Download (UpdateComponent succeeded, FD starts downloading)
        assert_eq!(
            fd_ctx.internal.get_fd_state(),
            FirmwareDeviceState::Download,
        );

        // === TASK 2 (Initiator) — polled SECOND ===
        // Initiator processes the ApplyComplete response; state already advanced past Apply.
        let mut apply_rsp_payload = [0u8; 256];
        let initiator_result =
            block_on(fd_ctx.handle_apply_complete_rsp_for_test(&mut apply_rsp_payload));
        assert!(
            initiator_result.is_ok(),
            "Initiator: process_apply_complete_rsp must tolerate state already advanced"
        );
    }

    /// Normal ordering for multi-component: initiator processes ApplyComplete first,
    /// then responder handles UpdateComponent. Should always work.
    #[test]
    fn test_two_task_normal_order_update_component_after_apply_complete() {
        let mock_ops = MockFdOps;
        let fd_ctx = FirmwareDeviceContext::new(&mock_ops);

        // Setup: same as above
        fd_ctx.internal.set_fd_state(FirmwareDeviceState::Apply);
        fd_ctx.internal.set_fd_req(
            FdReqState::Sent,
            true,
            Some(ApplyResult::ApplySuccess as u8),
            Some(1),
            Some(FwUpdateCmd::ApplyComplete as u8),
            Some(0),
        );

        // === TASK 1 (Initiator) — polled FIRST (normal ordering) ===
        let mut apply_rsp_payload = [0u8; 256];
        let initiator_result =
            block_on(fd_ctx.handle_apply_complete_rsp_for_test(&mut apply_rsp_payload));
        assert!(initiator_result.is_ok());
        assert_eq!(
            fd_ctx.internal.get_fd_state(),
            FirmwareDeviceState::ReadyXfer,
        );

        // === TASK 2 (Responder) — polled SECOND ===
        let mut payload = [0u8; 512];
        encode_update_component_request(&mut payload);

        let result = block_on(fd_ctx.update_component_rsp(&mut payload));
        assert!(result.is_ok());

        let resp = UpdateComponentResponse::decode(&payload).unwrap();
        assert_eq!(resp.completion_code, PldmBaseCompletionCode::Success as u8);
        assert_eq!(
            fd_ctx.internal.get_fd_state(),
            FirmwareDeviceState::Download,
        );
    }
}
