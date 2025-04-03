// Licensed under the Apache-2.0 license

use crate::cmd_interface::generate_failure_response;
use crate::error::MsgHandlerError;
use crate::firmware_device::fd_internal::{FdInternal, FdReqState};
use crate::firmware_device::fd_ops::{FdOps, FdOpsObject};
use libtock_platform::Syscalls;
use pldm_common::codec::PldmCodec;
use pldm_common::message::firmware_update::get_fw_params::{
    FirmwareParameters, GetFirmwareParametersRequest, GetFirmwareParametersResponse,
};
use pldm_common::message::firmware_update::pass_component::{
    PassComponentTableRequest, PassComponentTableResponse,
};
use pldm_common::message::firmware_update::query_devid::{
    QueryDeviceIdentifiersRequest, QueryDeviceIdentifiersResponse,
};
use pldm_common::message::firmware_update::request_update::{
    RequestUpdateRequest, RequestUpdateResponse,
};
use pldm_common::message::firmware_update::update_component::{
    UpdateComponentRequest, UpdateComponentResponse,
};
use pldm_common::protocol::base::{PldmBaseCompletionCode, TransferRespFlag};
use pldm_common::protocol::firmware_update::{
    ComponentCompatibilityResponse, ComponentCompatibilityResponseCode, ComponentResponse,
    ComponentResponseCode, Descriptor, FirmwareDeviceState, FwUpdateCompletionCode,
    PldmFirmwareString, UpdateOptionFlags, MAX_DESCRIPTORS_COUNT, PLDM_FWUP_BASELINE_TRANSFER_SIZE,
};
use pldm_common::util::fw_component::FirmwareComponent;

pub struct FirmwareDeviceContext<S: Syscalls> {
    ops: FdOpsObject<S>,
    // FD update internal states will be added here
    internal: FdInternal,
}

impl<S: Syscalls> FirmwareDeviceContext<S> {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            ops: FdOpsObject::new(),
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
            .get_transfer_size(ua_transfer_size)
            .await
            .map_err(MsgHandlerError::FdOps)?;

        // Set transfer size to the internal state
        self.internal.set_transfer_size(fd_transfer_size).await;

        // Construct response. No metadata or package data
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
            .update_component(&update_comp, &firmware_params, false)
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

    /*  Reference C:  update_comp handler
       LIBPLDM_CC_NONNULL
       static int pldm_fd_update_comp(struct pldm_fd *fd,
                       const struct pldm_header_info *hdr,
                       const struct pldm_msg *req,
                       size_t req_payload_len, struct pldm_msg *resp,
                       size_t *resp_payload_len)
       {
           struct pldm_update_component_req_full up;
           uint8_t comp_response_code;
           int rc;

           if (fd->state != PLDM_FD_STATE_READY_XFER) {
               return pldm_fd_reply_cc(PLDM_FWUP_INVALID_STATE_FOR_COMMAND,
                           hdr, resp, resp_payload_len);
           }

           rc = decode_update_component_req(req, req_payload_len, &up);
           if (rc) {
               return pldm_fd_reply_errno(rc, hdr, resp, resp_payload_len);
           }

           /* Store update_comp to pass to further callbacks. This persists
           * until the component update completes or is cancelled */
           fd->update_comp.comp_classification = up.comp_classification;
           fd->update_comp.comp_identifier = up.comp_identifier;
           fd->update_comp.comp_classification_index =
               up.comp_classification_index;
           fd->update_comp.comp_comparison_stamp = up.comp_comparison_stamp;
           fd->update_comp.comp_image_size = up.comp_image_size;
           fd->update_comp.update_option_flags = up.update_option_flags;
           memcpy(&fd->update_comp.version, &up.version, sizeof(up.version));

           comp_response_code =
               pldm_fd_check_update_component(fd, true, &fd->update_comp);

           // Mask to only the "Force Update" flag, others are not handled.
           bitfield32_t update_flags = {
               .bits.bit0 = fd->update_comp.update_option_flags.bits.bit0
           };

           const struct pldm_update_component_resp resp_data = {
               /* Component Response Code is 0 for ComponentResponse, 1 otherwise */
               .comp_compatibility_resp = (comp_response_code != 0),
               .comp_compatibility_resp_code = comp_response_code,
               .update_option_flags_enabled = update_flags,
               .time_before_req_fw_data = 0,
           };

           rc = encode_update_component_resp(hdr->instance, &resp_data, resp,
                           resp_payload_len);
           if (rc) {
               /* Encoding response failed */
               if (comp_response_code == PLDM_CRC_COMP_CAN_BE_UPDATED) {
                   /* Inform the application of cancellation. Call it directly
                   * rather than going through pldm_fd_maybe_cancel_component() */
                   fd->ops->cancel_update_component(fd->ops_ctx,
                                   &fd->update_comp);
               }
               return pldm_fd_reply_errno(rc, hdr, resp, resp_payload_len);
           }

           /* Set up download state */
           if (comp_response_code == PLDM_CRC_COMP_CAN_BE_UPDATED) {
               memset(&fd->specific, 0x0, sizeof(fd->specific));
               fd->update_flags = update_flags;
               fd->req.state = PLDM_FD_REQ_READY;
               fd->req.complete = false;
               pldm_fd_set_state(fd, PLDM_FD_STATE_DOWNLOAD);
           }

           return 0;
       }
    */

    pub async fn update_component_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        // Check if FD is in 'ReadyTransfer' state. Otherwise returns 'INVALID_STATE' completion code
        if self.internal.get_fd_state().await != FirmwareDeviceState::ReadyXfer {
            return generate_failure_response(
                payload,
                FwUpdateCompletionCode::InvalidStateForCommand as u8,
            );
        }

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
                ..Default::default()
            },
            Some(req.fixed.comp_image_size),
            Some(UpdateOptionFlags(req.fixed.update_option_flags)),
        );

        // Set the component onto the internal state
        self.internal.set_component(&update_comp).await;

        // TODO: update flags can be adjusted according to device-specific capabilities. For now, just set the flags as received from UA.
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
            .update_component(&update_comp, &firmware_params, true)
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
                /*
                /* Set up download state */
                if (comp_response_code == PLDM_CRC_COMP_CAN_BE_UPDATED) {
                    memset(&fd->specific, 0x0, sizeof(fd->specific));
                    fd->update_flags = update_flags;
                    fd->req.state = PLDM_FD_REQ_READY;
                    fd->req.complete = false;
                    pldm_fd_set_state(fd, PLDM_FD_STATE_DOWNLOAD);
                }
                 *
                 */
                if comp_resp_code == ComponentResponseCode::CompCanBeUpdated {
                    // Set up download state
                    self.internal
                        .set_fd_req(FdReqState::Ready, false, None, None, None, None)
                        .await;
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

    pub async fn set_update_timestamp(&self) {
        self.internal
            .set_update_timestamp_fd_t1(self.ops.now().await)
            .await;
    }
}
