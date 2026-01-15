// Licensed under the Apache-2.0 license

use crate::events::PldmEvents;
use crate::timer::Timer;
use crate::transport::{PldmSocket, RxPacket, MAX_PLDM_PAYLOAD_SIZE};
use log::{debug, error, info};
use pldm_common::codec::PldmCodec;
use pldm_common::message::firmware_update as pldm_packet;
use pldm_common::message::firmware_update::activate_fw::SelfContainedActivationRequest;
use pldm_common::message::firmware_update::transfer_complete::TransferResult;
use pldm_common::message::firmware_update::verify_complete::VerifyResult;
use pldm_common::protocol::base::{
    InstanceId, PldmBaseCompletionCode, PldmMsgHeader, PldmMsgType, PldmSupportedType,
    TransferRespFlag,
};
use pldm_common::protocol::firmware_update::{
    ComponentClassification, ComponentCompatibilityResponse, ComponentParameterEntry,
    ComponentResponseCode, FirmwareDeviceState, FwUpdateCmd, FwUpdateCompletionCode,
    PldmFirmwareString, UpdateOptionFlags, VersionStringType, PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN,
};
use pldm_fw_pkg::manifest::{ComponentImageInformation, FirmwareDeviceIdRecord};
use pldm_fw_pkg::FirmwareManifest;
use smlang::statemachine;
use std::cmp::{max, min};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_TRANSFER_SIZE: u32 = 180; // Maximum bytes to transfer in one request
const BASELINE_TRANSFER_SIZE: u32 = 32; // Minimum bytes to transfer in one request
const MAX_OUTSTANDING_TRANSFER_REQ: u8 = 1;
const GET_STATUS_ACTIVATION_POLL_INTERVAL: Duration = Duration::from_secs(1);
const SELF_ACTIVATION_FIELD_BIT: u16 = 0x0001;
const SELF_ACTIVATION_FIELD_MASK: u16 = 0x0001;
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_RETRY_COUNT: u8 = 3;

// Define the state machine
statemachine! {
    derive_states: [Debug, Clone],
    derive_events: [Clone, Debug],
    transitions: {
        *Idle + StartUpdate  / on_start_update = QueryDeviceIdentifiersSent,
        QueryDeviceIdentifiersSent + QueryDeviceIdentifiersResponse(pldm_packet::query_devid::QueryDeviceIdentifiersResponse) / on_query_device_identifiers_response = ReceivedQueryDeviceIdentifiers,
        ReceivedQueryDeviceIdentifiers + SendGetFirmwareParameters / on_send_get_firmware_parameters = GetFirmwareParametersSent,
        GetFirmwareParametersSent + GetFirmwareParametersResponse(pldm_packet::get_fw_params::GetFirmwareParametersResponse)  / on_get_firmware_parameters_response = ReceivedFirmwareParameters,
        ReceivedFirmwareParameters + SendRequestUpdate / on_send_request_update = RequestUpdateSent,
        RequestUpdateSent + RequestUpdateResponse(pldm_packet::request_update::RequestUpdateResponse) / on_request_update_response = LearnComponents,
        LearnComponents + SendPassComponentRequest [!are_all_components_passed] / on_send_pass_component_request = LearnComponents,
        LearnComponents + SendPassComponentRequest [are_all_components_passed]  / on_all_components_passed = ReadyXfer,
        LearnComponents + PassComponentResponse(pldm_packet::pass_component::PassComponentTableResponse) / on_pass_component_response = LearnComponents,
        LearnComponents + CancelUpdateOrTimeout  / on_stop_update = Idle,

        ReadyXfer + SendUpdateComponent / on_send_update_component = ReadyXfer,
        ReadyXfer + UpdateComponentResponse(pldm_packet::update_component::UpdateComponentResponse) / on_update_component_response = ReadyXfer,
        ReadyXfer + StartDownload / on_start_download = Download,
        ReadyXfer + CancelUpdateComponent  / on_stop_update = Idle,
        ReadyXfer + ActivateFirmware / on_activate_firmware = Activate,


        Download + RequestFirmwareData(pldm_packet::request_fw_data::RequestFirmwareDataRequest) / on_request_firmware = Download,
        Download + TransferComplete(pldm_packet::transfer_complete::TransferCompleteRequest) / on_transfer_complete_request = Download,
        Download + TransferCompleteFail / on_transfer_fail = Idle,
        Download + TransferCompletePass / on_transfer_success = Verify,
        Download + CancelUpdate  / on_stop_update = Idle,

        Verify + VerifyComplete(pldm_packet::verify_complete::VerifyCompleteRequest) / on_verify_complete_request = Verify,
        Verify + VerifyCompletePass / on_verify_success = Apply,
        Verify + VerifyCompleteFail / on_verify_fail = Idle,
        Verify + CancelUpdate  / on_stop_update = Idle,

        Apply + ApplyComplete(pldm_packet::apply_complete::ApplyCompleteRequest) / on_apply_complete_request = Apply,
        Apply + ApplyCompleteFail / on_apply_fail = Idle,
        Apply + ApplyCompletePass / on_apply_success = ReadyXfer,
        Apply + CancelUpdateComponent  / on_stop_update = Idle,

        Activate + ActivateFirmwareResponse(pldm_packet::activate_fw::ActivateFirmwareResponse) / on_activate_firmware_response = Activate,
        Activate + GetStatus / on_get_status = Activate,
        Activate + GetStatusResponse(pldm_packet::get_status::GetStatusResponse) / on_get_status_response = Activate,
        Activate + CancelUpdate  / on_stop_update = Idle,

        _ + CancelUpdateComponentResponse(pldm_packet::request_cancel::CancelUpdateComponentResponse) / on_cancel_update_component_response = Idle,
        _ + StopUpdateOnError / on_stop_update_error = Done,
        _ + StopUpdate / on_stop_update = Done
    }
}

fn send_message_helper<P: PldmCodec>(
    ctx: &mut InnerContext<impl PldmSocket + Send + 'static + Send + 'static>,
    message: &P,
) -> Result<(), ()> {
    let mut buffer = [0u8; MAX_PLDM_PAYLOAD_SIZE];
    ctx.response_timer.cancel();
    let sz = message.encode(&mut buffer).map_err(|_| ())?;
    ctx.socket.send(&buffer[..sz]).map_err(|_| ())?;
    debug!("Sent message: {:?}", std::any::type_name::<P>());
    let packet_buf = buffer[..sz].to_vec();
    *ctx.retry_count.lock().unwrap() = 0;
    if ctx.is_initiator {
        ctx.response_timer.schedule_periodic(
            RESPONSE_TIMEOUT,
            (
                ctx.socket.clone(),
                packet_buf.clone(),
                ctx.retry_count.clone(),
            ),
            |(socket, packet_buf, retry_count)| {
                if *retry_count.lock().unwrap() < MAX_RETRY_COUNT {
                    *retry_count.lock().unwrap() += 1;
                    info!(
                        "Retrying request, attempt: {}",
                        *retry_count.lock().unwrap()
                    );
                    socket.send(&packet_buf[..]).unwrap();
                } else {
                    error!("Max retry count reached, giving up on request");
                }
            },
        );
    }
    Ok(())
}

fn is_pkg_descriptor_in_response_descriptor(
    pkg_descriptor: &pldm_fw_pkg::manifest::Descriptor,
    response_descriptor: &pldm_common::protocol::firmware_update::Descriptor,
) -> bool {
    if response_descriptor.descriptor_type != pkg_descriptor.descriptor_type as u16 {
        return false;
    }
    if response_descriptor.descriptor_length != pkg_descriptor.descriptor_data.len() as u16 {
        return false;
    }
    if &response_descriptor.descriptor_data[..response_descriptor.descriptor_length as usize]
        != pkg_descriptor.descriptor_data.as_slice()
    {
        return false;
    }
    true
}

fn is_pkg_device_id_in_response(
    pkg_dev_id: &FirmwareDeviceIdRecord,
    response: &pldm_packet::query_devid::QueryDeviceIdentifiersResponse,
) -> bool {
    if response.descriptor_count < 1 {
        error!("No descriptors in response");
        return false;
    }

    // Check initial descriptor
    if !is_pkg_descriptor_in_response_descriptor(
        &pkg_dev_id.initial_descriptor,
        &response.initial_descriptor,
    ) {
        error!("Initial descriptor does not match");
        return false;
    }

    // Check additional descriptors
    if let Some(additional_descriptors) = &pkg_dev_id.additional_descriptors {
        if response.descriptor_count < additional_descriptors.len() as u8 + 1 {
            error!("Not enough descriptors in response");
            return false;
        }

        for additional_descriptor in additional_descriptors {
            let mut additional_descriptor_in_response = false;
            if let Some(response_descriptors) = &response.additional_descriptors {
                for i in 0..response.descriptor_count {
                    if is_pkg_descriptor_in_response_descriptor(
                        additional_descriptor,
                        &response_descriptors[i as usize],
                    ) {
                        additional_descriptor_in_response = true;
                        break;
                    }
                }
            }

            if !additional_descriptor_in_response {
                error!("Additional descriptor not found in response");
                return false;
            }
        }
    }
    true
}
pub trait StateMachineActions {
    // Guards
    fn are_all_components_passed(
        &self,
        ctx: &InnerContext<impl PldmSocket + Send + 'static>,
    ) -> Result<bool, ()> {
        if ctx.component_response_codes.len() >= ctx.components.len() {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    // Actions
    fn on_start_update(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
    ) -> Result<(), ()> {
        send_message_helper(
            ctx,
            &pldm_packet::query_devid::QueryDeviceIdentifiersRequest::new(
                ctx.instance_id,
                PldmMsgType::Request,
            ),
        )
    }
    fn on_request_update_response(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
        response: pldm_packet::request_update::RequestUpdateResponse,
    ) -> Result<(), ()> {
        ctx.instance_id += 1; // Response received, increment instance id
        if response.fixed.completion_code == PldmBaseCompletionCode::Success as u8 {
            debug!("RequestUpdate response success");
            ctx.event_queue
                .send(PldmEvents::Update(Events::SendPassComponentRequest))
                .map_err(|_| ())?;
            Ok(())
        } else {
            error!("RequestUpdate response failed");
            ctx.event_queue
                .send(PldmEvents::Update(Events::StopUpdate))
                .map_err(|_| ())?;
            Err(())
        }
    }

    fn on_send_pass_component_request(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
    ) -> Result<(), ()> {
        let num_of_components_to_pass = ctx.components.len();
        let num_components_passed = ctx.component_response_codes.len();

        if num_components_passed >= num_of_components_to_pass {
            debug!("All components passed");
            return Ok(());
        }

        let component_idx: usize;
        let pass_component_flag: TransferRespFlag;

        if num_of_components_to_pass == 0 {
            error!("No components to pass");
            return Err(());
        } else if num_of_components_to_pass == 1 {
            component_idx = 0;
            pass_component_flag = TransferRespFlag::StartAndEnd;
        } else if num_components_passed == 0 {
            component_idx = 0;
            pass_component_flag = TransferRespFlag::Start;
        } else if num_components_passed < num_of_components_to_pass - 1 {
            component_idx = 0;
            pass_component_flag = TransferRespFlag::Middle;
        } else if num_components_passed == num_of_components_to_pass - 1 {
            component_idx = 0;
            pass_component_flag = TransferRespFlag::End;
        } else {
            // This should never happen
            panic!("Unhandled case");
        }
        debug!(
            "Passing component: {} Flag: {:?}",
            component_idx, pass_component_flag
        );
        let component = &ctx.components[component_idx];
        let component_version_string = component.version_string.clone().unwrap_or("".to_string());
        let request = pldm_packet::pass_component::PassComponentTableRequest::new(
            ctx.instance_id,
            PldmMsgType::Request,
            pass_component_flag,
            ComponentClassification::try_from(component.classification).map_err(|_| ())?,
            component.identifier,
            0, // todo: support classification index
            component.comparison_stamp.unwrap(),
            &PldmFirmwareString {
                str_type: component.version_string_type as u8,
                str_len: component_version_string.len() as u8,
                str_data: {
                    let mut arr = [0u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN];
                    arr[..component_version_string.len()]
                        .copy_from_slice(component_version_string.as_bytes());
                    arr
                },
            },
        );
        send_message_helper(ctx, &request)
    }

    fn on_next_component(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
    ) -> Result<(), ()> {
        ctx.current_component_index = self.find_next_component_to_update(ctx);
        if ctx.current_component_index.is_none() {
            debug!("No more component to update");
            ctx.event_queue
                .send(PldmEvents::Update(Events::ActivateFirmware))
                .map_err(|_| ())?;
        } else {
            ctx.event_queue
                .send(PldmEvents::Update(Events::SendUpdateComponent))
                .map_err(|_| ())?;
        }
        Ok(())
    }

    fn on_all_components_passed(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
    ) -> Result<(), ()> {
        self.on_next_component(ctx)
    }

    fn find_next_component_to_update(
        &self,
        ctx: &InnerContext<impl PldmSocket + Send + 'static>,
    ) -> Option<usize> {
        let start_idx = if let Some(index) = ctx.current_component_index {
            index + 1
        } else {
            0
        };
        // Find the next component to update
        (start_idx..ctx.components.len())
            .find(|&i| ctx.component_response_codes[i] == ComponentResponseCode::CompCanBeUpdated)
    }

    fn on_send_update_component(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
    ) -> Result<(), ()> {
        if ctx.current_component_index.is_none() {
            error!("No component to update");
            return Err(());
        }
        let component = &ctx.components[ctx.current_component_index.unwrap()];
        let request = pldm_packet::update_component::UpdateComponentRequest::new(
            ctx.instance_id,
            PldmMsgType::Request,
            ComponentClassification::try_from(component.classification).map_err(|_| ())?,
            component.identifier,
            0, // not supported
            component.comparison_stamp.unwrap_or(0),
            component.size,
            UpdateOptionFlags(component.options as u32),
            &PldmFirmwareString {
                str_type: component.version_string_type as u8,
                str_len: component
                    .version_string
                    .clone()
                    .unwrap_or("".to_string())
                    .len() as u8,
                str_data: {
                    let mut arr = [0u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN];
                    if let Some(ref component) = component.version_string {
                        arr[..component.len()].copy_from_slice(component.as_bytes());
                    }
                    arr
                },
            },
        );
        send_message_helper(ctx, &request)
    }

    fn on_update_component_response(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
        response: pldm_packet::update_component::UpdateComponentResponse,
    ) -> Result<(), ()> {
        ctx.instance_id += 1; // Response received, increment instance id
        if response.completion_code == PldmBaseCompletionCode::Success as u8
            && response.comp_compatibility_resp
                == ComponentCompatibilityResponse::CompCanBeUpdated as u8
        {
            debug!("UpdateComponent response success, start download");
            ctx.event_queue
                .send(PldmEvents::Update(Events::StartDownload))
                .map_err(|_| ())?;

            Ok(())
        } else {
            error!("UpdateComponent response failed, continuing to next component");
            // Update the component response code
            ctx.component_response_codes[ctx.current_component_index.unwrap()] =
                ComponentResponseCode::try_from(response.comp_compatibility_resp)
                    .map_err(|_| ())?;
            self.on_next_component(ctx)
        }
    }

    fn on_query_device_identifiers_response(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
        response: pldm_packet::query_devid::QueryDeviceIdentifiersResponse,
    ) -> Result<(), ()> {
        for pkg_dev_id in &ctx.pldm_fw_pkg.firmware_device_id_records {
            if is_pkg_device_id_in_response(pkg_dev_id, &response) {
                ctx.device_id = Some(pkg_dev_id.clone());
                break;
            }
        }
        if ctx.device_id.is_some() {
            ctx.event_queue
                .send(PldmEvents::Update(Events::SendGetFirmwareParameters))
                .map_err(|_| ())?;
            Ok(())
        } else {
            error!("No matching device id found");
            ctx.event_queue
                .send(PldmEvents::Update(Events::StopUpdateOnError))
                .map_err(|_| ())?;
            Err(())
        }
    }

    fn on_send_get_firmware_parameters(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
    ) -> Result<(), ()> {
        send_message_helper(
            ctx,
            &pldm_packet::get_fw_params::GetFirmwareParametersRequest::new(
                ctx.instance_id,
                PldmMsgType::Request,
            ),
        )
    }

    fn on_send_request_update(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
    ) -> Result<(), ()> {
        if let Some(dev_id_record) = ctx.device_id.as_ref() {
            let version_string: PldmFirmwareString =
                match dev_id_record.component_image_set_version_string {
                    Some(ref version_string) => PldmFirmwareString {
                        str_type: dev_id_record.component_image_set_version_string_type as u8,
                        str_len: version_string.len() as u8,
                        str_data: {
                            let mut arr = [0u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN];
                            arr[..version_string.len()].copy_from_slice(version_string.as_bytes());
                            arr
                        },
                    },
                    None => PldmFirmwareString {
                        str_type: VersionStringType::Unspecified as u8,
                        str_len: 0,
                        str_data: [0u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN],
                    },
                };
            send_message_helper(
                ctx,
                &pldm_packet::request_update::RequestUpdateRequest::new(
                    ctx.instance_id,
                    PldmMsgType::Request,
                    MAX_TRANSFER_SIZE,
                    ctx.components.len() as u16,
                    MAX_OUTSTANDING_TRANSFER_REQ,
                    0, // pkg_data_len is optional, not supported
                    &version_string,
                ),
            )
        } else {
            error!("Cannot send RequestUpdate request, no device id found");
            Err(())
        }
    }

    fn find_component_in_package(
        pkg_components: &[pldm_fw_pkg::manifest::ComponentImageInformation],
        comp_entry: &ComponentParameterEntry,
    ) -> Result<usize, ()> {
        // iterate over the components in the package and get the index
        for (i, item) in pkg_components.iter().enumerate() {
            let pkg_component = item;
            if pkg_component.classification != comp_entry.comp_param_entry_fixed.comp_classification
            {
                continue;
            }

            if pkg_component.identifier != comp_entry.comp_param_entry_fixed.comp_identifier {
                continue;
            }
            return Ok(i);
        }

        Err(())
    }

    fn is_in_device_applicable_components(
        comp_index: usize,
        device_id_record: &FirmwareDeviceIdRecord,
    ) -> bool {
        if let Some(applicable_components) = &device_id_record.applicable_components {
            if !applicable_components.is_empty() {
                for item in applicable_components {
                    if *item == comp_index as u8 {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn is_need_component_update(
        pkg_component: &ComponentImageInformation,
        comp_entry: &ComponentParameterEntry,
    ) -> bool {
        if let Some(comp_timestamp) = pkg_component.comparison_stamp {
            let device_comp_timestamp = comp_entry
                .comp_param_entry_fixed
                .active_comp_comparison_stamp;
            debug!(
                "Component id: {}, Package timestamp : {} , Device timestamp : {}",
                pkg_component.identifier, comp_timestamp, device_comp_timestamp
            );
            if comp_timestamp <= device_comp_timestamp {
                debug!("Component is already up to date");
                return false;
            }
        }
        true
    }

    fn on_get_firmware_parameters_response(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
        response: pldm_packet::get_fw_params::GetFirmwareParametersResponse,
    ) -> Result<(), ()> {
        ctx.instance_id += 1; // Response received, increment instance id
        for i in 0..response.parms.params_fixed.comp_count {
            if let Ok(comp_idx) = Self::find_component_in_package(
                &ctx.pldm_fw_pkg.component_image_information,
                &response.parms.comp_param_table[i as usize],
            ) {
                if Self::is_in_device_applicable_components(
                    comp_idx,
                    ctx.device_id.as_ref().unwrap(),
                ) {
                    debug!(
                        "Component id: {} is in applicable components",
                        ctx.pldm_fw_pkg.component_image_information[comp_idx].identifier
                    );
                } else {
                    debug!(
                        "Component id: {} is not applicable",
                        ctx.pldm_fw_pkg.component_image_information[comp_idx].identifier
                    );
                    continue;
                }
                let component = &ctx.pldm_fw_pkg.component_image_information[comp_idx];
                if Self::is_need_component_update(
                    component,
                    &response.parms.comp_param_table[i as usize],
                ) {
                    debug!("Component id: {} will be updated,", component.identifier);
                    info!(
                        "Component id: {} requested_activation_method {:b}",
                        component.identifier, component.requested_activation_method
                    );
                    ctx.components.push(component.clone());
                }
            }
        }

        if !ctx.components.is_empty() {
            ctx.event_queue
                .send(PldmEvents::Update(Events::SendRequestUpdate))
                .map_err(|_| ())
        } else {
            debug!("No component needs update");
            ctx.event_queue
                .send(PldmEvents::Update(Events::StopUpdateOnError))
                .map_err(|_| ())?;
            Err(())
        }
    }

    fn on_pass_component_response(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
        response: pldm_packet::pass_component::PassComponentTableResponse,
    ) -> Result<(), ()> {
        ctx.instance_id += 1; // Response received, increment instance id
                              // If unsuccessful, stop the update
        if response.completion_code != PldmBaseCompletionCode::Success as u8 {
            error!("PassComponent response failed");
            ctx.event_queue
                .send(PldmEvents::Update(Events::StopUpdateOnError))
                .map_err(|_| ())?;
            return Err(());
        }

        // Record the response code
        ctx.component_response_codes
            .push(ComponentResponseCode::try_from(response.comp_resp_code).map_err(|_| ())?);

        // Send the next component info
        ctx.event_queue
            .send(PldmEvents::Update(Events::SendPassComponentRequest))
            .map_err(|_| ())?;

        Ok(())
    }

    fn on_start_download(
        &mut self,
        _ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
    ) -> Result<(), ()> {
        // TODO
        Ok(())
    }

    fn on_request_firmware(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
        request: pldm_packet::request_fw_data::RequestFirmwareDataRequest,
    ) -> Result<(), ()> {
        if request.length > MAX_TRANSFER_SIZE || request.length < BASELINE_TRANSFER_SIZE {
            error!("RequestFirmwareDataRequest length is invalid");
            let response = pldm_packet::request_fw_data::RequestFirmwareDataResponse::new(
                request.hdr.instance_id(),
                PldmBaseCompletionCode::InvalidLength as u8,
                &[],
            );
            return send_message_helper(ctx, &response);
        }

        let component = &ctx.components[ctx.current_component_index.unwrap()];
        if let Some(data) = &component.image_data {
            if (request.offset + request.length) as usize
                >= data.len() + BASELINE_TRANSFER_SIZE as usize
            {
                error!("RequestFirmwareDataRequest offset is out of bounds");
                let response = pldm_packet::request_fw_data::RequestFirmwareDataResponse::new(
                    request.hdr.instance_id(),
                    FwUpdateCompletionCode::DataOutOfRange as u8,
                    &[],
                );
                return send_message_helper(ctx, &response);
            }
            let mut buffer = [0u8; MAX_TRANSFER_SIZE as usize];
            let mut to_copy = min(
                data.len() as i32 - request.offset as i32,
                request.length as i32,
            );
            to_copy = max(to_copy, 0); // Ensure to_copy is not negative
            let mut to_pad = min(
                request.length as i32,
                request.length as i32 - (data.len() as i32 - request.offset as i32),
            );
            to_pad = max(to_pad, 0); // Ensure to_pad is not negative

            if to_copy > 0 {
                buffer[..to_copy as usize].copy_from_slice(
                    &data[request.offset as usize..(request.offset as usize + to_copy as usize)],
                );
            }
            if to_pad > 0 {
                buffer[to_copy as usize..(to_copy + to_pad) as usize].fill(0);
            }

            let response = pldm_packet::request_fw_data::RequestFirmwareDataResponse::new(
                request.hdr.instance_id(),
                PldmBaseCompletionCode::Success as u8,
                &buffer[..request.length as usize],
            );

            ctx.transferred_bytes += request.length;
            if ctx.transferred_bytes % 1024 < request.length {
                info!(
                    "Transferred {} bytes so far out of {} bytes",
                    ctx.transferred_bytes,
                    data.len()
                );
            }

            send_message_helper(ctx, &response)
        } else {
            error!("No image data found, make sure the image is decoded correctly");
            Err(())
        }
    }

    fn on_transfer_complete_request(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
        request: pldm_packet::transfer_complete::TransferCompleteRequest,
    ) -> Result<(), ()> {
        let response = pldm_packet::transfer_complete::TransferCompleteResponse::new(
            request.hdr.instance_id(),
            PldmBaseCompletionCode::Success as u8,
        );
        ctx.is_initiator = false;
        send_message_helper(ctx, &response)?;

        if request.tranfer_result == TransferResult::TransferSuccess as u8 {
            info!("Transfer complete success");
            ctx.event_queue
                .send(PldmEvents::Update(Events::TransferCompletePass))
                .map_err(|_| ())?;
        } else {
            error!("Transfer complete failed");
            ctx.event_queue
                .send(PldmEvents::Update(Events::TransferCompleteFail))
                .map_err(|_| ())?;
        }
        Ok(())
    }
    fn on_transfer_fail(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
    ) -> Result<(), ()> {
        let request = pldm_packet::request_cancel::CancelUpdateComponentRequest::new(
            ctx.instance_id,
            PldmMsgType::Request,
        );
        send_message_helper(ctx, &request)?;
        Ok(())
    }

    fn on_transfer_success(
        &mut self,
        _ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
    ) -> Result<(), ()> {
        // No action, wait for VerifyComplete from device
        Ok(())
    }

    fn on_verify_complete_request(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
        request: pldm_packet::verify_complete::VerifyCompleteRequest,
    ) -> Result<(), ()> {
        let response = pldm_packet::verify_complete::VerifyCompleteResponse::new(
            request.hdr.instance_id(),
            PldmBaseCompletionCode::Success as u8,
        );
        send_message_helper(ctx, &response)?;

        if request.verify_result == VerifyResult::VerifySuccess as u8 {
            ctx.event_queue
                .send(PldmEvents::Update(Events::VerifyCompletePass))
                .map_err(|_| ())?;
        } else {
            ctx.event_queue
                .send(PldmEvents::Update(Events::VerifyCompleteFail))
                .map_err(|_| ())?;
        }
        Ok(())
    }

    fn on_get_status(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
    ) -> Result<(), ()> {
        if ctx.activation_time.is_some() {
            if Instant::now() < ctx.activation_time.unwrap() {
                // If the activation time is not yet reached, continue scheduling another get status request, this will be automatically cancelled
                // when the expected status is received or a activation timeout occurs
                ctx.timer.schedule(
                    GET_STATUS_ACTIVATION_POLL_INTERVAL,
                    ctx.event_queue.clone(),
                    |event_queue| Self::poll_activation_status(event_queue),
                );
            } else {
                // Activation timeout
                error!("Activation timer timed out");
                ctx.event_queue
                    .send(PldmEvents::Update(Events::StopUpdate))
                    .map_err(|_| ())?;
                ctx.timer.cancel();
                return Ok(());
            }
        }

        // Send get status request
        let request =
            pldm_packet::get_status::GetStatusRequest::new(ctx.instance_id, PldmMsgType::Request);
        send_message_helper(ctx, &request)
    }

    fn on_get_status_response(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
        response: pldm_packet::get_status::GetStatusResponse,
    ) -> Result<(), ()> {
        ctx.instance_id += 1; // Response received, increment instance id
        if response.completion_code == PldmBaseCompletionCode::Success as u8 {
            debug!("GetStatus response success");

            if ctx.activation_time.is_some() {
                // Currently waiting for activation
                if response.current_state == FirmwareDeviceState::Idle as u8 {
                    // Activation is done
                    info!("Activation is done response {}", response.current_state);
                    ctx.activation_time = None;
                    ctx.timer.cancel();
                    ctx.event_queue
                        .send(PldmEvents::Update(Events::StopUpdate))
                        .map_err(|_| ())?;
                } else {
                    // Still waiting for activation
                    debug!(
                        "Still waiting for activation. Current state: {:?}",
                        response.current_state
                    );
                    let current_time = Instant::now();
                    if current_time > ctx.activation_time.unwrap() {
                        // Activation timeout
                        error!("Activation timer timed out");
                        ctx.event_queue
                            .send(PldmEvents::Update(Events::StopUpdate))
                            .map_err(|_| ())?;
                        ctx.timer.cancel();
                    }
                }
            } else {
                info!(
                    "Getstatus response current state: {:?}",
                    response.current_state
                );
            }
            Ok(())
        } else {
            error!("GetStatus response failed");
            Err(())
        }
    }

    fn on_verify_success(
        &mut self,
        _ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
    ) -> Result<(), ()> {
        info!("Verify success");
        Ok(())
    }

    fn on_verify_fail(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
    ) -> Result<(), ()> {
        error!("Verify failed");
        let request = pldm_packet::request_cancel::CancelUpdateComponentRequest::new(
            ctx.instance_id,
            PldmMsgType::Request,
        );
        send_message_helper(ctx, &request)?;
        Ok(())
    }

    fn on_apply_complete_request(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
        request: pldm_packet::apply_complete::ApplyCompleteRequest,
    ) -> Result<(), ()> {
        let response = pldm_packet::apply_complete::ApplyCompleteResponse::new(
            request.hdr.instance_id(),
            PldmBaseCompletionCode::Success as u8,
        );
        send_message_helper(ctx, &response)?;

        let apply_result = pldm_packet::apply_complete::ApplyResult::try_from(request.apply_result)
            .map_err(|_| {
                error!("Unsupported apply result");
            })?;

        match apply_result {
            pldm_packet::apply_complete::ApplyResult::ApplySuccess => {
                ctx.event_queue
                    .send(PldmEvents::Update(Events::ApplyCompletePass))
                    .map_err(|_| ())?;
            }
            pldm_packet::apply_complete::ApplyResult::ApplySuccessWithActivationMethod => {
                // Update the activation method
                ctx.components[ctx.current_component_index.unwrap()].requested_activation_method =
                    request.comp_activation_methods_modification;
                ctx.event_queue
                    .send(PldmEvents::Update(Events::ApplyCompletePass))
                    .map_err(|_| ())?;
            }
            pldm_packet::apply_complete::ApplyResult::ApplyFailureMemoryIssue
            | pldm_packet::apply_complete::ApplyResult::ApplyTimeOut
            | pldm_packet::apply_complete::ApplyResult::ApplyGenericError => {
                error!("Apply failed");
                ctx.event_queue
                    .send(PldmEvents::Update(Events::ApplyCompleteFail))
                    .map_err(|_| ())?;
            }
            pldm_packet::apply_complete::ApplyResult::VendorDefined => {
                error!("Vendor defined apply result, not supported");
                ctx.event_queue
                    .send(PldmEvents::Update(Events::ApplyCompleteFail))
                    .map_err(|_| ())?;
            }
        }
        Ok(())
    }

    fn on_apply_success(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
    ) -> Result<(), ()> {
        info!("Apply success");
        ctx.is_initiator = true;
        self.on_next_component(ctx)
    }

    fn on_apply_fail(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
    ) -> Result<(), ()> {
        error!("Apply failed");
        let request =
            pldm_packet::request_cancel::CancelUpdateComponentRequest::new(0, PldmMsgType::Request);
        send_message_helper(ctx, &request)?;
        Ok(())
    }

    fn on_activate_firmware(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
    ) -> Result<(), ()> {
        let mut is_activation_needed = false;
        let mut num_components_downloaded = 0;
        for (i, item) in ctx.component_response_codes.iter().enumerate() {
            if *item != ComponentResponseCode::CompCanBeUpdated {
                continue;
            }
            num_components_downloaded += 1;
            if (ctx.components[i].requested_activation_method >> SELF_ACTIVATION_FIELD_BIT)
                & SELF_ACTIVATION_FIELD_MASK
                == SELF_ACTIVATION_FIELD_BIT
            {
                // Option for self-activation is set
                is_activation_needed = true;
                break;
            }
        }
        info!("Num components downloaded: {}", num_components_downloaded);
        if num_components_downloaded > 0 {
            if is_activation_needed {
                let request = pldm_packet::activate_fw::ActivateFirmwareRequest::new(
                    ctx.instance_id,
                    PldmMsgType::Request,
                    SelfContainedActivationRequest::ActivateSelfContainedComponents,
                );
                send_message_helper(ctx, &request)?;
            } else {
                info!("No activation needed");
                let request = pldm_packet::activate_fw::ActivateFirmwareRequest::new(
                    ctx.instance_id,
                    PldmMsgType::Request,
                    SelfContainedActivationRequest::NotActivateSelfContainedComponents,
                );
                send_message_helper(ctx, &request)?;

                ctx.event_queue
                    .send(PldmEvents::Update(Events::StopUpdate))
                    .map_err(|_| ())?;
            }
        } else {
            error!("No components downloaded");
            ctx.event_queue
                .send(PldmEvents::Update(Events::StopUpdateOnError))
                .map_err(|_| ())?;
        }
        Ok(())
    }

    fn poll_activation_status(event_queue: Sender<PldmEvents>) {
        event_queue
            .send(PldmEvents::Update(Events::GetStatus))
            .unwrap();
    }

    fn on_activate_firmware_response(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
        response: pldm_packet::activate_fw::ActivateFirmwareResponse,
    ) -> Result<(), ()> {
        ctx.instance_id += 1; // Response received, increment instance id
        if response.completion_code == PldmBaseCompletionCode::Success as u8 {
            info!("ActivateFirmware response success");

            if response.estimated_time_activation > 0 {
                // Record the expected activation time
                ctx.activation_time = Some(
                    Instant::now() + Duration::from_secs(response.estimated_time_activation as u64),
                );

                ctx.timer.schedule(
                    GET_STATUS_ACTIVATION_POLL_INTERVAL,
                    ctx.event_queue.clone(),
                    |event_queue| Self::poll_activation_status(event_queue),
                );
            } else {
                info!("ActivateFirmware response success, no activation needed");
                ctx.event_queue
                    .send(PldmEvents::Update(Events::StopUpdate))
                    .map_err(|_| ())?;
            }

            Ok(())
        } else {
            error!("ActivateFirmware response failed");
            ctx.event_queue
                .send(PldmEvents::Update(Events::StopUpdateOnError))
                .map_err(|_| ())?;
            Err(())
        }
    }

    fn on_stop_update(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
    ) -> Result<(), ()> {
        info!("Stopping update");
        ctx.response_timer.cancel();
        Ok(())
    }
    fn on_stop_update_error(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
    ) -> Result<(), ()> {
        error!("Stopping update with error");
        ctx.response_timer.cancel();
        Ok(())
    }
    fn on_cancel_update_component_response(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
        response: pldm_packet::request_cancel::CancelUpdateComponentResponse,
    ) -> Result<(), ()> {
        ctx.instance_id += 1; // Response received, increment instance id
        ctx.response_timer.cancel();
        if response.completion_code == PldmBaseCompletionCode::Success as u8 {
            info!("CancelUpdateComponent response success");
            Ok(())
        } else {
            error!("CancelUpdateComponent response failed");
            Err(())
        }
    }
}

fn packet_to_event<T: PldmCodec>(
    header: &PldmMsgHeader<impl AsRef<[u8]>>,
    packet: &RxPacket,
    is_response: bool,
    event_constructor: fn(T) -> Events,
) -> Result<PldmEvents, ()> {
    debug!("Parsing command: {:?}", std::any::type_name::<T>());
    if is_response && !(header.rq() == 0 && header.datagram() == 0) {
        error!("Not a response");
        return Err(());
    }

    let response = T::decode(&packet.payload.data[..packet.payload.len]).map_err(|_| ())?;
    Ok(PldmEvents::Update(event_constructor(response)))
}

pub fn process_packet(packet: &RxPacket) -> Result<PldmEvents, ()> {
    debug!("Handling packet: {}", packet);
    let header = PldmMsgHeader::decode(&packet.payload.data[..packet.payload.len])
        .map_err(|_| (error!("Error decoding packet!")))?;
    if !header.is_hdr_ver_valid() {
        error!("Invalid header version!");
        return Err(());
    }
    if header.pldm_type() != PldmSupportedType::FwUpdate as u8 {
        info!("Not a discovery message");
        return Err(());
    }

    // Convert packet to state machine event
    match FwUpdateCmd::try_from(header.cmd_code()) {
        Ok(cmd) => match cmd {
            FwUpdateCmd::QueryDeviceIdentifiers => packet_to_event(
                &header,
                packet,
                true,
                Events::QueryDeviceIdentifiersResponse,
            ),
            FwUpdateCmd::GetFirmwareParameters => {
                packet_to_event(&header, packet, true, Events::GetFirmwareParametersResponse)
            }
            FwUpdateCmd::RequestUpdate => {
                packet_to_event(&header, packet, true, Events::RequestUpdateResponse)
            }
            FwUpdateCmd::PassComponentTable => {
                packet_to_event(&header, packet, true, Events::PassComponentResponse)
            }
            FwUpdateCmd::UpdateComponent => {
                packet_to_event(&header, packet, true, Events::UpdateComponentResponse)
            }
            FwUpdateCmd::RequestFirmwareData => {
                packet_to_event(&header, packet, false, Events::RequestFirmwareData)
            }
            FwUpdateCmd::TransferComplete => {
                packet_to_event(&header, packet, false, Events::TransferComplete)
            }
            FwUpdateCmd::VerifyComplete => {
                packet_to_event(&header, packet, false, Events::VerifyComplete)
            }
            FwUpdateCmd::ApplyComplete => {
                packet_to_event(&header, packet, false, Events::ApplyComplete)
            }
            FwUpdateCmd::ActivateFirmware => {
                packet_to_event(&header, packet, true, Events::ActivateFirmwareResponse)
            }
            FwUpdateCmd::GetStatus => {
                packet_to_event(&header, packet, true, Events::GetStatusResponse)
            }
            FwUpdateCmd::CancelUpdateComponent => {
                packet_to_event(&header, packet, true, Events::CancelUpdateComponentResponse)
            }
            _ => {
                debug!("Unknown firmware update command");
                Err(())
            }
        },
        Err(_) => Err(()),
    }
}

// Implement the context struct
pub struct DefaultActions;
impl StateMachineActions for DefaultActions {}

pub struct DefaultActionsExitOnError;
impl StateMachineActions for DefaultActionsExitOnError {
    fn on_stop_update_error(
        &mut self,
        _ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
    ) -> Result<(), ()> {
        error!("Stopping update with error");
        // Exit the application with a non-zero error code
        std::process::exit(1);
    }
}

pub struct InnerContext<S: PldmSocket> {
    socket: S,
    pub pldm_fw_pkg: FirmwareManifest,
    pub event_queue: Sender<PldmEvents>,
    instance_id: InstanceId,
    // The device id of the firmware device
    pub device_id: Option<FirmwareDeviceIdRecord>,
    // The components that need to be updated
    pub components: Vec<ComponentImageInformation>,
    // The device responses to the component info passed
    pub component_response_codes: Vec<ComponentResponseCode>,
    // The current component being updated
    // This an index to the components vector
    pub current_component_index: Option<usize>,
    timer: Timer,
    activation_time: Option<Instant>,

    transferred_bytes: u32,
    response_timer: Timer,
    retry_count: Arc<Mutex<u8>>,
    is_initiator: bool,
}

pub struct Context<T: StateMachineActions, S: PldmSocket> {
    inner: T,
    pub inner_ctx: InnerContext<S>,
}

impl<T: StateMachineActions, S: PldmSocket> Context<T, S> {
    pub fn new(
        context: T,
        socket: S,
        pldm_fw_pkg: FirmwareManifest,
        event_queue: Sender<PldmEvents>,
    ) -> Self {
        Self {
            inner: context,
            inner_ctx: InnerContext {
                socket,
                pldm_fw_pkg,
                event_queue,
                instance_id: 0,
                device_id: None,
                components: Vec::new(),
                component_response_codes: Vec::new(),
                current_component_index: None,
                timer: Timer::new(),
                activation_time: None,
                transferred_bytes: 0,
                response_timer: Timer::new(),
                retry_count: Arc::new(Mutex::new(0)),
                is_initiator: true,
            },
        }
    }
}

// Macros to delegate the state machine actions to the custom StateMachineActions passed to the state machine
// This allows overriding the implementation of the actions and guards
macro_rules! delegate_to_inner_action {
    ($($fn_name:ident ($($arg:ident : $arg_ty:ty),*) -> $ret:ty),* $(,)?) => {
        $(
            fn $fn_name(&mut self, $($arg: $arg_ty),*) -> $ret {
                debug!("Fw Upgrade Action: {}", stringify!($fn_name));
                self.inner.$fn_name(&mut self.inner_ctx, $($arg),*)
            }
        )*
    };
}

macro_rules! delegate_to_inner_guard {
    ($($fn_name:ident ($($arg:ident : $arg_ty:ty),*) -> $ret:ty),* $(,)?) => {
        $(
            fn $fn_name(&self, $($arg: $arg_ty),*) -> $ret {
                debug!("Fw Upgrade Guard: {}", stringify!($fn_name));
                self.inner.$fn_name(&self.inner_ctx, $($arg),*)
            }
        )*
    };
}

impl<T: StateMachineActions, S: PldmSocket + Send + 'static> StateMachineContext for Context<T, S> {
    // Actions with packet events
    delegate_to_inner_action! {
        on_start_update() -> Result<(),()>,
        on_query_device_identifiers_response(response : pldm_packet::query_devid::QueryDeviceIdentifiersResponse) -> Result<(),()>,
        on_send_get_firmware_parameters() -> Result<(),()>,
        on_send_request_update() -> Result<(),()>,
        on_get_firmware_parameters_response(response : pldm_packet::get_fw_params::GetFirmwareParametersResponse) -> Result<(), ()>,
        on_request_update_response(response: pldm_packet::request_update::RequestUpdateResponse) -> Result<(),()>,
        on_send_pass_component_request() -> Result<(),()>,
        on_all_components_passed() -> Result<(),()>,
        on_send_update_component() -> Result<(),()>,
        on_pass_component_response(response : pldm_packet::pass_component::PassComponentTableResponse) -> Result<(),()>,
        on_start_download() -> Result<(),()>,
        on_update_component_response(response : pldm_packet::update_component::UpdateComponentResponse) -> Result<(),()>,
        on_request_firmware(request: pldm_packet::request_fw_data::RequestFirmwareDataRequest) -> Result<(),()>,
        on_transfer_complete_request(request: pldm_packet::transfer_complete::TransferCompleteRequest) -> Result<(),()>,
        on_transfer_fail() -> Result<(),()>,
        on_transfer_success() -> Result<(),()>,
        on_verify_complete_request(request: pldm_packet::verify_complete::VerifyCompleteRequest) -> Result<(),()>,
        on_get_status() -> Result<(),()>,
        on_get_status_response(response: pldm_packet::get_status::GetStatusResponse) -> Result<(),()>,
        on_stop_update() -> Result<(),()>,
        on_stop_update_error() -> Result<(),()>,
        on_cancel_update_component_response(response: pldm_packet::request_cancel::CancelUpdateComponentResponse) -> Result<(),()>,
        on_verify_success() -> Result<(),()>,
        on_verify_fail() -> Result<(),()>,
        on_apply_complete_request(request: pldm_packet::apply_complete::ApplyCompleteRequest) -> Result<(),()>,
        on_apply_success() -> Result<(),()>,
        on_apply_fail() -> Result<(),()>,
        on_activate_firmware() -> Result<(),()>,
        on_activate_firmware_response(response : pldm_packet::activate_fw::ActivateFirmwareResponse) -> Result<(),()>,
    }

    // Guards
    delegate_to_inner_guard! {
        are_all_components_passed() -> Result<bool, ()>,
    }
}
