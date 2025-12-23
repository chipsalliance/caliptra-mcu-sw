// Licensed under the Apache-2.0 license

use crate::cmd_interface::generate_failure_response;
use crate::error::MsgHandlerError;
use crate::firmware_device::fd_internal::{FdInternal, FdReqState};
use crate::firmware_device::fd_ops::{ComponentOperation, FdOps};
use pldm_common::codec::PldmCodec;
use pldm_common::message::firmware_update::activate_fw::{
    ActivateFirmwareRequest, ActivateFirmwareResponse,
};
use pldm_common::message::firmware_update::get_fw_params::{
    FirmwareParameters, GetFirmwareParametersRequest, GetFirmwareParametersResponse,
};
use pldm_common::message::firmware_update::get_status::ProgressPercent;
use pldm_common::message::firmware_update::pass_component::{
    PassComponentTableRequest, PassComponentTableResponse,
};
use pldm_common::message::firmware_update::query_devid::{
    QueryDeviceIdentifiersRequest, QueryDeviceIdentifiersResponse,
};
use pldm_common::message::firmware_update::request_cancel::{
    CancelUpdateComponentRequest, CancelUpdateComponentResponse, CancelUpdateRequest,
    CancelUpdateResponse,
};
use pldm_common::message::firmware_update::request_update::{
    RequestUpdateRequest, RequestUpdateResponse,
};
use pldm_common::message::firmware_update::transfer_complete::{
    TransferCompleteRequest, TransferResult,
};
use pldm_common::message::firmware_update::update_component::{
    UpdateComponentRequest, UpdateComponentResponse,
};

use pldm_common::codec::PldmCodecError;
use pldm_common::message::firmware_update::apply_complete::{ApplyCompleteRequest, ApplyResult};
use pldm_common::message::firmware_update::get_status::{
    AuxState, AuxStateStatus, GetStatusReasonCode, GetStatusRequest, GetStatusResponse,
    UpdateOptionResp,
};
use pldm_common::message::firmware_update::request_fw_data::{
    RequestFirmwareDataRequest, RequestFirmwareDataResponseFixed,
};
use pldm_common::message::firmware_update::verify_complete::{VerifyCompleteRequest, VerifyResult};
use pldm_common::protocol::base::{
    PldmBaseCompletionCode, PldmMsgHeader, PldmMsgType, TransferRespFlag,
};
use pldm_common::protocol::firmware_update::{
    ComponentActivationMethods, ComponentCompatibilityResponse, ComponentCompatibilityResponseCode,
    ComponentResponse, ComponentResponseCode, Descriptor, FirmwareDeviceState, FwUpdateCmd,
    FwUpdateCompletionCode, PldmFirmwareString, UpdateOptionFlags, MAX_DESCRIPTORS_COUNT,
    PLDM_FWUP_BASELINE_TRANSFER_SIZE,
};
use pldm_common::util::fw_component::FirmwareComponent;

use crate::firmware_device::fd_internal::{
    ApplyState, DownloadState, InitiatorModeState, VerifyState,
};

pub struct FirmwareDeviceContext<'a> {
    ops: &'a dyn FdOps,
    internal: FdInternal,
}

impl<'a> FirmwareDeviceContext<'a> {
    #[allow(clippy::new_without_default)]
    pub fn new(ops: &'a dyn FdOps) -> Self {
        Self {
            ops,
            internal: FdInternal::default(),
        }
    }

    pub async fn query_devid_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        // Decode the request message
        let req = QueryDeviceIdentifiersRequest::decode(payload).map_err(MsgHandlerError::Codec)?;

        let mut device_identifiers: [Descriptor; MAX_DESCRIPTORS_COUNT] =
            [Descriptor::default(); MAX_DESCRIPTORS_COUNT];

        // Get the device identifiers
        let descriptor_cnt = self
            .ops
            .get_device_identifiers(&mut device_identifiers)
            .await
            .map_err(MsgHandlerError::FdOps)?;

        // Create the response message
        let resp = QueryDeviceIdentifiersResponse::new(
            req.hdr.instance_id(),
            PldmBaseCompletionCode::Success as u8,
            &device_identifiers[0],
            device_identifiers.get(1..descriptor_cnt),
        )
        .map_err(MsgHandlerError::PldmCommon)?;

        match resp.encode(payload) {
            Ok(bytes) => Ok(bytes),
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::InvalidLength as u8)
            }
        }
    }

    pub async fn get_firmware_parameters_rsp(
        &self,
        payload: &mut [u8],
    ) -> Result<usize, MsgHandlerError> {
        // Decode the request message
        let req = GetFirmwareParametersRequest::decode(payload).map_err(MsgHandlerError::Codec)?;

        let mut firmware_params = FirmwareParameters::default();
        self.ops
            .get_firmware_parms(&mut firmware_params)
            .await
            .map_err(MsgHandlerError::FdOps)?;

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

    pub async fn request_update_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        // Check if FD is in idle state. Otherwise returns 'ALREADY_IN_UPDATE_MODE' completion code
        if self.internal.is_update_mode().await {
            return generate_failure_response(
                payload,
                FwUpdateCompletionCode::AlreadyInUpdateMode as u8,
            );
        }

        // Set timestamp for FD T1 timeout
        self.set_fd_t1_ts().await;

        // Decode the request message
        let req = RequestUpdateRequest::decode(payload).map_err(MsgHandlerError::Codec)?;
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
            .map_err(MsgHandlerError::FdOps)?;

        // Set transfer size to the internal state
        self.internal.set_xfer_size(fd_transfer_size).await;

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
                    .set_fd_state(FirmwareDeviceState::LearnComponents)
                    .await;
                Ok(bytes)
            }
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::InvalidLength as u8)
            }
        }
    }

    pub async fn pass_component_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        // Check if FD is in 'LearnComponents' state. Otherwise returns 'INVALID_STATE' completion code
        if self.internal.get_fd_state().await != FirmwareDeviceState::LearnComponents {
            return generate_failure_response(
                payload,
                FwUpdateCompletionCode::InvalidStateForCommand as u8,
            );
        }

        // Set timestamp for FD T1 timeout
        self.set_fd_t1_ts().await;

        // Decode the request message
        let req = PassComponentTableRequest::decode(payload).map_err(MsgHandlerError::Codec)?;
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
            .await
            .map_err(MsgHandlerError::FdOps)?;

        let comp_resp_code = self
            .ops
            .handle_component(
                &pass_comp,
                &firmware_params,
                ComponentOperation::PassComponent,
            )
            .await
            .map_err(MsgHandlerError::FdOps)?;

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
                    self.internal
                        .set_fd_state(FirmwareDeviceState::ReadyXfer)
                        .await;
                }
                Ok(bytes)
            }
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::InvalidLength as u8)
            }
        }
    }

    pub async fn update_component_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        // Check if FD is in 'ReadyTransfer' state. Otherwise returns 'INVALID_STATE' completion code
        if self.internal.get_fd_state().await != FirmwareDeviceState::ReadyXfer {
            return generate_failure_response(
                payload,
                FwUpdateCompletionCode::InvalidStateForCommand as u8,
            );
        }

        // Set timestamp for FD T1 timeout
        self.set_fd_t1_ts().await;

        // Decode the request message
        let req = UpdateComponentRequest::decode(payload).map_err(MsgHandlerError::Codec)?;

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
        self.internal.set_component(&update_comp).await;

        // Adjust the update flags based on the device's capabilities if needed. Currently, the flags are set as received from the UA.
        self.internal
            .set_update_flags(UpdateOptionFlags(req.fixed.update_option_flags))
            .await;

        let mut firmware_params = FirmwareParameters::default();
        self.ops
            .get_firmware_parms(&mut firmware_params)
            .await
            .map_err(MsgHandlerError::FdOps)?;

        let comp_resp_code = self
            .ops
            .handle_component(
                &update_comp,
                &firmware_params,
                ComponentOperation::UpdateComponent, /* This indicates this is an update request */
            )
            .await
            .map_err(MsgHandlerError::FdOps)?;

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
                        .set_initiator_mode(InitiatorModeState::Download(DownloadState::default()))
                        .await;
                    // Set up the req for download.
                    self.internal
                        .set_fd_req(FdReqState::Ready, false, None, None, None, None)
                        .await;

                    // Move FD state machine to download state.
                    self.internal
                        .set_fd_state(FirmwareDeviceState::Download)
                        .await;
                }
                Ok(bytes)
            }
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::InvalidLength as u8)
            }
        }
    }

    pub async fn activate_firmware_rsp(
        &self,
        payload: &mut [u8],
    ) -> Result<usize, MsgHandlerError> {
        // Check if FD is in 'ReadyTransfer' state. Otherwise returns 'INVALID_STATE' completion code
        if self.internal.get_fd_state().await != FirmwareDeviceState::ReadyXfer {
            return generate_failure_response(
                payload,
                FwUpdateCompletionCode::InvalidStateForCommand as u8,
            );
        }

        // Decode the request message
        let req = ActivateFirmwareRequest::decode(payload).map_err(MsgHandlerError::Codec)?;
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
            .await
            .map_err(MsgHandlerError::FdOps)?;

        // Construct response
        let resp =
            ActivateFirmwareResponse::new(req.hdr.instance_id(), completion_code, estimated_time);

        match resp.encode(payload) {
            Ok(bytes) => {
                if completion_code == PldmBaseCompletionCode::Success as u8
                    || completion_code == FwUpdateCompletionCode::ActivationNotRequired as u8
                {
                    self.internal
                        .set_fd_state(FirmwareDeviceState::Activate)
                        .await;
                    if self_contained == 0 {
                        // If activation is not self-contained, then consider the FW already activated
                        self.internal
                            .set_fd_idle(GetStatusReasonCode::ActivateFw)
                            .await;
                    }
                }
                Ok(bytes)
            }
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::InvalidLength as u8)
            }
        }
    }

    pub async fn cancel_update_component_rsp(
        &self,
        payload: &mut [u8],
    ) -> Result<usize, MsgHandlerError> {
        // If FD is not in update mode, return 'NOT_IN_UPDATE_MODE' completion code
        if !self.internal.is_update_mode().await {
            return generate_failure_response(
                payload,
                FwUpdateCompletionCode::NotInUpdateMode as u8,
            );
        }

        let fd_state = self.internal.get_fd_state().await;
        let should_cancel = match fd_state {
            FirmwareDeviceState::Download | FirmwareDeviceState::Verify => true,
            FirmwareDeviceState::Apply => {
                // In apply state, only cancel if not completed successfully
                !(self.internal.get_fd_req().await.complete
                    && self.internal.get_fd_req().await.result
                        == Some(ApplyResult::ApplySuccess as u8))
            }
            _ => {
                return generate_failure_response(
                    payload,
                    FwUpdateCompletionCode::InvalidStateForCommand as u8,
                );
            }
        };

        if should_cancel {
            self.ops
                .cancel_update_component(&self.internal.get_component().await)
                .await
                .map_err(MsgHandlerError::FdOps)?;
        }

        // Decode the request message
        let req = CancelUpdateComponentRequest::decode(payload).map_err(MsgHandlerError::Codec)?;
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
                    self.internal
                        .set_fd_state(FirmwareDeviceState::ReadyXfer)
                        .await;
                }
                Ok(bytes)
            }
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::InvalidLength as u8)
            }
        }
    }

    pub async fn cancel_update_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        // If FD is not in update mode, return 'NOT_IN_UPDATE_MODE' completion code
        if !self.internal.is_update_mode().await {
            return generate_failure_response(
                payload,
                FwUpdateCompletionCode::NotInUpdateMode as u8,
            );
        }

        // Set timestamp for FD T1 timeout
        self.set_fd_t1_ts().await;

        let fd_state = self.internal.get_fd_state().await;
        let should_cancel = match fd_state {
            FirmwareDeviceState::Download | FirmwareDeviceState::Verify => true,
            FirmwareDeviceState::Apply => {
                // In apply state, only cancel if not completed successfully
                !(self.internal.get_fd_req().await.complete
                    && self.internal.get_fd_req().await.result
                        == Some(ApplyResult::ApplySuccess as u8))
            }
            _ => false,
        };

        if should_cancel {
            self.ops
                .cancel_update_component(&self.internal.get_component().await)
                .await
                .map_err(MsgHandlerError::FdOps)?;
        }

        // Decode the request message
        let req = CancelUpdateRequest::decode(payload).map_err(MsgHandlerError::Codec)?;
        let completion_code = if should_cancel {
            PldmBaseCompletionCode::Success as u8
        } else {
            PldmBaseCompletionCode::Error as u8
        };

        let (non_functioning_component_indication, non_functioning_component_bitmap) = self
            .ops
            .get_non_functional_component_info()
            .await
            .map_err(MsgHandlerError::FdOps)?;

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
                    self.internal
                        .set_fd_idle(GetStatusReasonCode::CancelUpdate)
                        .await;
                }
                Ok(bytes)
            }
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::InvalidLength as u8)
            }
        }
    }

    pub async fn get_status_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        let req = GetStatusRequest::decode(payload).map_err(MsgHandlerError::Codec)?;

        let cur_state = self.internal.get_fd_state().await;
        let prev_state = self.internal.get_fd_prev_state().await;
        let (progress_percent, update_flags) = match cur_state {
            FirmwareDeviceState::Download => {
                let mut progress = ProgressPercent::default();
                let _ = self
                    .ops
                    .query_download_progress(&self.internal.get_component().await, &mut progress)
                    .await;
                let update_flags = self.internal.get_update_flags().await;
                (progress, update_flags)
            }
            FirmwareDeviceState::Verify => {
                let progress = if let Some(percent) = self.internal.get_fd_verify_progress().await {
                    ProgressPercent::new(percent).unwrap()
                } else {
                    ProgressPercent::default()
                };
                let update_flags = self.internal.get_update_flags().await;
                (progress, update_flags)
            }
            FirmwareDeviceState::Apply => {
                let progress = if let Some(percent) = self.internal.get_fd_apply_progress().await {
                    ProgressPercent::new(percent).unwrap()
                } else {
                    ProgressPercent::default()
                };
                let update_flags = self.internal.get_update_flags().await;
                (progress, update_flags)
            }
            _ => (
                ProgressPercent::default(),
                self.internal.get_update_flags().await,
            ),
        };

        let (aux_state, aux_state_status) = match self.internal.get_fd_req_state().await {
            FdReqState::Unused => (
                AuxState::IdleLearnComponentsReadXfer,
                AuxStateStatus::AuxStateInProgressOrSuccess as u8,
            ),
            FdReqState::Sent => (
                AuxState::OperationInProgress,
                AuxStateStatus::AuxStateInProgressOrSuccess as u8,
            ),
            FdReqState::Ready => {
                if self.internal.is_fd_req_complete().await {
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
                    .await
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
                .await
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
        self.internal
            .set_fd_t1_update_ts(self.ops.now().await)
            .await;
    }

    pub async fn should_start_initiator_mode(&self) -> bool {
        self.internal.get_fd_state().await == FirmwareDeviceState::Download
    }

    pub async fn should_stop_initiator_mode(&self) -> bool {
        !matches!(
            self.internal.get_fd_state().await,
            FirmwareDeviceState::Download
                | FirmwareDeviceState::Verify
                | FirmwareDeviceState::Apply
        )
    }

    pub async fn fd_progress(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        let fd_state = self.internal.get_fd_state().await;

        let result = match fd_state {
            FirmwareDeviceState::Download => self.fd_progress_download(payload).await,
            FirmwareDeviceState::Verify => self.pldm_fd_progress_verify(payload).await,
            FirmwareDeviceState::Apply => self.pldm_fd_progress_apply(payload).await,
            _ => Err(MsgHandlerError::FdInitiatorModeError),
        }?;

        let now = self.ops.now().await;
        let ts = self.internal.get_fd_t1_update_ts().await;
        let elapsed = now.saturating_sub(ts);
        // If a response is not received within T1 in FD-driven states, cancel the update and transition to idle state.
        if (fd_state == FirmwareDeviceState::Download
            || fd_state == FirmwareDeviceState::Verify
            || fd_state == FirmwareDeviceState::Apply)
            && self.internal.get_fd_req_state().await == FdReqState::Sent
            && elapsed > self.internal.get_fd_t1_timeout().await
        {
            self.ops
                .cancel_update_component(&self.internal.get_component().await)
                .await
                .map_err(MsgHandlerError::FdOps)?;
            self.internal.fd_idle_timeout().await;
            return Ok(0);
        }

        Ok(result)
    }

    pub async fn handle_response(&self, payload: &mut [u8]) -> Result<(), MsgHandlerError> {
        let rsp_header =
            PldmMsgHeader::<[u8; 3]>::decode(payload).map_err(MsgHandlerError::Codec)?;
        let (cmd_code, instance_id) = (rsp_header.cmd_code(), rsp_header.instance_id());

        let fd_req = self.internal.get_fd_req().await;
        if fd_req.state != FdReqState::Sent
            || fd_req.instance_id != Some(instance_id)
            || fd_req.command != Some(cmd_code)
        {
            // Unexpected response
            return Err(MsgHandlerError::FdInitiatorModeError);
        }

        self.set_fd_t1_ts().await;

        match FwUpdateCmd::try_from(cmd_code) {
            Ok(FwUpdateCmd::RequestFirmwareData) => self.process_request_fw_data_rsp(payload).await,
            Ok(FwUpdateCmd::TransferComplete) => self.process_transfer_complete_rsp(payload).await,
            Ok(FwUpdateCmd::VerifyComplete) => self.process_verify_complete_rsp(payload).await,
            Ok(FwUpdateCmd::ApplyComplete) => self.process_apply_complete_rsp(payload).await,
            _ => Err(MsgHandlerError::FdInitiatorModeError),
        }
    }

    async fn process_request_fw_data_rsp(&self, payload: &mut [u8]) -> Result<(), MsgHandlerError> {
        let fd_state = self.internal.get_fd_state().await;
        if fd_state != FirmwareDeviceState::Download {
            return Err(MsgHandlerError::FdInitiatorModeError);
        }

        let fd_req = self.internal.get_fd_req().await;
        if fd_req.complete {
            // Received data after completion
            return Err(MsgHandlerError::FdInitiatorModeError);
        }

        // Decode the response message fixed
        let fw_data_rsp_fixed: RequestFirmwareDataResponseFixed =
            RequestFirmwareDataResponseFixed::decode(payload).map_err(MsgHandlerError::Codec)?;

        match fw_data_rsp_fixed.completion_code {
            code if code == PldmBaseCompletionCode::Success as u8 => {}
            code if code == FwUpdateCompletionCode::RetryRequestFwData as u8 => return Ok(()),
            _ => {
                self.internal
                    .set_fd_req(
                        FdReqState::Ready,
                        true,
                        Some(TransferResult::FdAbortedTransfer as u8),
                        None,
                        None,
                        None,
                    )
                    .await;
                return Ok(());
            }
        }

        let (offset, length) = self.internal.get_fd_download_state().await.unwrap();

        let fw_data = payload[core::mem::size_of::<RequestFirmwareDataResponseFixed>()..]
            .get(..length as usize)
            .ok_or(MsgHandlerError::Codec(PldmCodecError::BufferTooShort))?;

        let fw_component = &self.internal.get_component().await;
        let res = self
            .ops
            .download_fw_data(offset as usize, fw_data, fw_component)
            .await
            .map_err(MsgHandlerError::FdOps)?;

        if res == TransferResult::TransferSuccess {
            if self.ops.is_download_complete(fw_component).await {
                // Mark as complete, next progress() call will send the TransferComplete request
                self.internal
                    .set_fd_req(
                        FdReqState::Ready,
                        true,
                        Some(TransferResult::TransferSuccess as u8),
                        None,
                        None,
                        None,
                    )
                    .await;
            } else {
                // Invoke another request if there is more data to download
                self.internal
                    .set_fd_req(FdReqState::Ready, false, None, None, None, None)
                    .await;
            }
        } else {
            // Pass the callback error as the TransferResult
            self.internal
                .set_fd_req(FdReqState::Ready, true, Some(res as u8), None, None, None)
                .await;
        }
        Ok(())
    }

    async fn process_transfer_complete_rsp(
        &self,
        _payload: &mut [u8],
    ) -> Result<(), MsgHandlerError> {
        let fd_state = self.internal.get_fd_state().await;
        if fd_state != FirmwareDeviceState::Download {
            return Err(MsgHandlerError::FdInitiatorModeError);
        }

        let fd_req = self.internal.get_fd_req().await;
        if fd_req.state != FdReqState::Sent || !fd_req.complete {
            return Err(MsgHandlerError::FdInitiatorModeError);
        }

        /* Next state depends whether the transfer succeeded */
        if fd_req.result == Some(TransferResult::TransferSuccess as u8) {
            // Switch to Verify
            self.internal
                .set_initiator_mode(InitiatorModeState::Verify(VerifyState::default()))
                .await;
            self.internal
                .set_fd_req(FdReqState::Ready, false, None, None, None, None)
                .await;
            self.internal
                .set_fd_state(FirmwareDeviceState::Verify)
                .await;
        } else {
            // Wait for UA to cancel
            self.internal
                .set_fd_req(FdReqState::Failed, true, fd_req.result, None, None, None)
                .await;
        }

        Ok(())
    }

    async fn process_verify_complete_rsp(
        &self,
        _payload: &mut [u8],
    ) -> Result<(), MsgHandlerError> {
        let fd_state = self.internal.get_fd_state().await;
        if fd_state != FirmwareDeviceState::Verify {
            return Err(MsgHandlerError::FdInitiatorModeError);
        }

        let fd_req = self.internal.get_fd_req().await;
        if fd_req.state != FdReqState::Sent || !fd_req.complete {
            return Err(MsgHandlerError::FdInitiatorModeError);
        }

        /* Next state depends whether the verify succeeded */
        if fd_req.result == Some(VerifyResult::VerifySuccess as u8) {
            // Switch to Apply
            self.internal
                .set_initiator_mode(InitiatorModeState::Apply(ApplyState::default()))
                .await;
            self.internal
                .set_fd_req(FdReqState::Ready, false, None, None, None, None)
                .await;
            self.internal.set_fd_state(FirmwareDeviceState::Apply).await;
        } else {
            // Wait for UA to cancel
            self.internal
                .set_fd_req(FdReqState::Failed, true, fd_req.result, None, None, None)
                .await;
        }

        Ok(())
    }

    async fn process_apply_complete_rsp(&self, _payload: &mut [u8]) -> Result<(), MsgHandlerError> {
        let fd_state = self.internal.get_fd_state().await;
        if fd_state != FirmwareDeviceState::Apply {
            return Err(MsgHandlerError::FdInitiatorModeError);
        }

        let fd_req = self.internal.get_fd_req().await;
        if fd_req.state != FdReqState::Sent || !fd_req.complete {
            return Err(MsgHandlerError::FdInitiatorModeError);
        }

        if fd_req.result == Some(ApplyResult::ApplySuccess as u8) {
            // Switch to Xfer
            self.internal
                .set_fd_req(FdReqState::Unused, false, None, None, None, None)
                .await;
            self.internal
                .set_fd_state(FirmwareDeviceState::ReadyXfer)
                .await;
        } else {
            // Wait for UA to cancel
            self.internal
                .set_fd_req(FdReqState::Failed, true, fd_req.result, None, None, None)
                .await;
        }

        Ok(())
    }

    async fn fd_progress_download(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        if !self.should_send_fd_request().await {
            return Err(MsgHandlerError::FdInitiatorModeError);
        }

        let instance_id = self.internal.alloc_next_instance_id().await.unwrap();
        // If the request is complete, send TransferComplete
        if self.internal.is_fd_req_complete().await {
            let result = self
                .internal
                .get_fd_req_result()
                .await
                .ok_or(MsgHandlerError::FdInitiatorModeError)?;

            let msg_len = TransferCompleteRequest::new(
                instance_id,
                PldmMsgType::Request,
                TransferResult::try_from(result).unwrap(),
            )
            .encode(payload)
            .map_err(MsgHandlerError::Codec)?;

            // Set fd req state to sent
            let req_sent_timestamp = self.ops.now().await;
            self.internal
                .set_fd_req(
                    FdReqState::Sent,
                    true,
                    Some(result),
                    Some(instance_id),
                    Some(FwUpdateCmd::TransferComplete as u8),
                    Some(req_sent_timestamp),
                )
                .await;

            Ok(msg_len)
        } else {
            let (requested_offset, requested_length) = self
                .ops
                .query_download_offset_and_length(&self.internal.get_component().await)
                .await
                .map_err(MsgHandlerError::FdOps)?;

            if let Some((chunk_offset, chunk_length)) = self
                .internal
                .get_fd_download_chunk(requested_offset as u32, requested_length as u32)
                .await
            {
                let msg_len = RequestFirmwareDataRequest::new(
                    instance_id,
                    PldmMsgType::Request,
                    chunk_offset,
                    chunk_length,
                )
                .encode(payload)
                .map_err(MsgHandlerError::Codec)?;

                // Store offset and length into the internal state
                self.internal
                    .set_fd_download_state(chunk_offset, chunk_length)
                    .await;

                // Set fd req state to sent
                let req_sent_timestamp = self.ops.now().await;
                self.internal
                    .set_fd_req(
                        FdReqState::Sent,
                        false,
                        None,
                        Some(instance_id),
                        Some(FwUpdateCmd::RequestFirmwareData as u8),
                        Some(req_sent_timestamp),
                    )
                    .await;
                Ok(msg_len)
            } else {
                Err(MsgHandlerError::FdInitiatorModeError)
            }
        }
    }

    async fn pldm_fd_progress_verify(&self, _payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        if !self.should_send_fd_request().await {
            return Err(MsgHandlerError::FdInitiatorModeError);
        }

        let mut res = VerifyResult::default();
        if !self.internal.is_fd_req_complete().await {
            let mut progress_percent = ProgressPercent::default();
            res = self
                .ops
                .verify(&self.internal.get_component().await, &mut progress_percent)
                .await
                .map_err(MsgHandlerError::FdOps)?;

            // Set the progress percent to VerifyState
            self.internal
                .set_fd_verify_progress(progress_percent.value())
                .await;

            if res == VerifyResult::VerifySuccess && progress_percent.value() < 100 {
                // doing nothing and wait for the next call
                return Ok(0);
            }
        }

        let instance_id = self.internal.alloc_next_instance_id().await.unwrap();
        let verify_complete_req =
            VerifyCompleteRequest::new(instance_id, PldmMsgType::Request, res);

        // Encode the request message
        let msg_len = verify_complete_req
            .encode(_payload)
            .map_err(MsgHandlerError::Codec)?;

        self.internal
            .set_fd_req(
                FdReqState::Sent,
                true,
                Some(res as u8),
                Some(instance_id),
                Some(FwUpdateCmd::VerifyComplete as u8),
                Some(self.ops.now().await),
            )
            .await;

        Ok(msg_len)
    }

    async fn pldm_fd_progress_apply(&self, _payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        if !self.should_send_fd_request().await {
            return Err(MsgHandlerError::FdInitiatorModeError);
        }

        let mut res = ApplyResult::default();
        if !self.internal.is_fd_req_complete().await {
            let mut progress_percent = ProgressPercent::default();
            res = self
                .ops
                .apply(&self.internal.get_component().await, &mut progress_percent)
                .await
                .map_err(MsgHandlerError::FdOps)?;

            // Set the progress percent to ApplyState
            self.internal
                .set_fd_apply_progress(progress_percent.value())
                .await;

            if res == ApplyResult::ApplySuccess && progress_percent.value() < 100 {
                // doing nothing and wait for the next call
                return Ok(0);
            }
        }

        // Allocate the next instance ID
        let instance_id = self.internal.alloc_next_instance_id().await.unwrap();
        let apply_complete_req = ApplyCompleteRequest::new(
            instance_id,
            PldmMsgType::Request,
            res,
            ComponentActivationMethods(0),
        );
        // Encode the request message
        let msg_len = apply_complete_req
            .encode(_payload)
            .map_err(MsgHandlerError::Codec)?;

        self.internal
            .set_fd_req(
                FdReqState::Sent,
                true,
                Some(res as u8),
                Some(instance_id),
                Some(FwUpdateCmd::ApplyComplete as u8),
                Some(self.ops.now().await),
            )
            .await;

        Ok(msg_len)
    }

    async fn should_send_fd_request(&self) -> bool {
        let now = self.ops.now().await;

        let fd_req_state = self.internal.get_fd_req_state().await;
        match fd_req_state {
            FdReqState::Unused => false,
            FdReqState::Ready => true,
            FdReqState::Failed => false,
            FdReqState::Sent => {
                let fd_req_sent_time = self.internal.get_fd_sent_time().await.unwrap();
                if now < fd_req_sent_time {
                    // Time went backwards
                    return false;
                }

                // Send if retry time has elapsed
                return (now - fd_req_sent_time) >= self.internal.get_fd_t2_retry_time().await;
            }
        }
    }
}
