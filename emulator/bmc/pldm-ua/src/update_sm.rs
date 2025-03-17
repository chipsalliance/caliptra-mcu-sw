// Licensed under the Apache-2.0 license

use crate::events::PldmEvents;
use crate::transport::MAX_PLDM_PAYLOAD_SIZE;
use crate::transport::{PldmSocket, RxPacket};
use log::{debug, error, info};
use pldm_common::codec::PldmCodec;
use pldm_common::message::firmware_update as pldm_packet;
use pldm_common::protocol::base::{
    InstanceId, PldmBaseCompletionCode, PldmMsgHeader, PldmMsgType, PldmSupportedType,
    TransferRespFlag,
};
use pldm_common::protocol::firmware_update::{
    ComponentClassification, ComponentCompatibilityResponse, ComponentParameterEntry,
    ComponentResponseCode, FwUpdateCmd, PldmFirmwareString, UpdateOptionFlags, VersionStringType,
    PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN,
};
use pldm_fw_pkg::manifest::{ComponentImageInformation, FirmwareDeviceIdRecord};
use pldm_fw_pkg::FirmwareManifest;
use smlang::statemachine;
use std::sync::mpsc::Sender;

const MAX_TRANSFER_SIZE: u32 = 64;
const MAX_OUTSTANDING_TRANSFER_REQ: u8 = 1;

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

        Download + RequestFirmwareData / on_request_firmware = Download,
        Download + TransferCompleteFail / on_transfer_fail = Idle,
        Download + TransferCompletePass / on_transfer_success = Verify,
        Download + CancelUpdate  / on_stop_update = Idle,

        Verify + GetStatus / on_get_status = Verify,
        Verify + VerifyCompletePass / on_verify_success = Apply,
        Verify + VerifyCompleteFail / on_verify_fail = Idle,
        Verify + CancelUpdate  / on_stop_update = Idle,

        Apply + GetStatus / on_get_status = Apply,
        Apply + ApplyCompleteFail / on_apply_fail = Idle,
        Apply + ApplyCompletePass / on_apply_success = Activate,
        Apply + CancelUpdateComponent  / on_stop_update = Idle,

        Activate + GetStatus / on_get_status = Activate,
        Activate + GetMetaData / on_get_metadata = Activate,
        Activate + ActivateFirmware / on_activate_firmware = Idle,
        Activate + CancelUpdate  / on_stop_update = Idle,

        _ + StopUpdate / on_stop_update = Done
    }
}

fn send_request_helper<S: PldmSocket, P: PldmCodec>(socket: &S, message: &P) -> Result<(), ()> {
    let mut buffer = [0u8; MAX_PLDM_PAYLOAD_SIZE];
    let sz = message.encode(&mut buffer).map_err(|_| ())?;
    socket.send(&buffer[..sz]).map_err(|_| ())?;
    debug!("Sent request: {:?}", std::any::type_name::<P>());
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
    fn are_all_components_passed(&self, ctx: &InnerContext<impl PldmSocket>) -> Result<bool, ()> {
        if ctx.component_response_codes.len() >= ctx.components.len() {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    // Actions
    fn on_start_update(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        send_request_helper(
            &ctx.socket,
            &pldm_packet::query_devid::QueryDeviceIdentifiersRequest::new(
                ctx.instance_id,
                PldmMsgType::Request,
            ),
        )
    }
    fn on_request_update_response(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket>,
        response: pldm_packet::request_update::RequestUpdateResponse,
    ) -> Result<(), ()> {
        if response.fixed.completion_code == PldmBaseCompletionCode::Success as u8 {
            info!("RequestUpdate response success");
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
        ctx: &mut InnerContext<impl PldmSocket>,
    ) -> Result<(), ()> {
        let num_of_components_to_pass = ctx.components.len();
        let num_components_passed = ctx.component_response_codes.len();

        if num_components_passed >= num_of_components_to_pass {
            info!("All components passed");
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
        send_request_helper(&ctx.socket, &request)
    }

    fn on_next_component(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        ctx.current_component_index = self.find_next_component_to_update(ctx);
        if ctx.current_component_index.is_none() {
            error!("No component to update");
            // TODO, send Activate
            return Err(());
        } else {
            ctx.event_queue
                .send(PldmEvents::Update(Events::SendUpdateComponent))
                .map_err(|_| ())?;
        }
        Ok(())
    }

    fn on_all_components_passed(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket>,
    ) -> Result<(), ()> {
        self.on_next_component(ctx)
    }

    fn find_next_component_to_update(&self, ctx: &InnerContext<impl PldmSocket>) -> Option<usize> {
        // Find the next component to update
        for (i, item) in ctx.component_response_codes.iter().enumerate() {
            if *item == ComponentResponseCode::CompCanBeUpdated {
                return Some(i);
            }
        }
        None
    }

    fn on_send_update_component(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket>,
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
        send_request_helper(&ctx.socket, &request)
    }

    fn on_update_component_response(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket>,
        response: pldm_packet::update_component::UpdateComponentResponse,
    ) -> Result<(), ()> {
        if response.completion_code == PldmBaseCompletionCode::Success as u8
            && response.comp_compatibility_resp
                == ComponentCompatibilityResponse::CompCanBeUpdated as u8
        {
            info!("UpdateComponent response success, start download");
            ctx.event_queue
                .send(PldmEvents::Update(Events::StartDownload))
                .map_err(|_| ())?;

            Ok(())
        } else {
            error!("UpdateComponent response failed, continuing to next component");
            // Mark the component as can not be updated
            if let Some(index) = ctx.current_component_index {
                ctx.component_response_codes[index] = ComponentResponseCode::CompNotSupported;
            }
            self.on_next_component(ctx)
        }
    }

    fn on_query_device_identifiers_response(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket>,
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
                .send(PldmEvents::Update(Events::StopUpdate))
                .map_err(|_| ())?;
            Err(())
        }
    }

    fn on_send_get_firmware_parameters(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket>,
    ) -> Result<(), ()> {
        send_request_helper(
            &ctx.socket,
            &pldm_packet::get_fw_params::GetFirmwareParametersRequest::new(
                ctx.instance_id,
                PldmMsgType::Request,
            ),
        )
    }

    fn on_send_request_update(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket>,
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
            send_request_helper(
                &ctx.socket,
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
            info!(
                "Component id: {}, Package timestamp : {} , Device timestamp : {}",
                pkg_component.identifier, comp_timestamp, device_comp_timestamp
            );
            if comp_timestamp <= device_comp_timestamp {
                info!("Component is already up to date");
                return false;
            }
        }
        true
    }

    fn on_get_firmware_parameters_response(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket>,
        response: pldm_packet::get_fw_params::GetFirmwareParametersResponse,
    ) -> Result<(), ()> {
        for i in 0..response.parms.params_fixed.comp_count {
            if let Ok(comp_idx) = Self::find_component_in_package(
                &ctx.pldm_fw_pkg.component_image_information,
                &response.parms.comp_param_table[i as usize],
            ) {
                if Self::is_in_device_applicable_components(
                    comp_idx,
                    ctx.device_id.as_ref().unwrap(),
                ) {
                    info!(
                        "Component id: {} is in applicable components",
                        ctx.pldm_fw_pkg.component_image_information[comp_idx].identifier
                    );
                } else {
                    info!(
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
                    info!("Component id: {} will be updated,", component.identifier);
                    ctx.components.push(component.clone());
                }
            }
        }

        if !ctx.components.is_empty() {
            ctx.event_queue
                .send(PldmEvents::Update(Events::SendRequestUpdate))
                .map_err(|_| ())
        } else {
            info!("No component needs update");
            ctx.event_queue
                .send(PldmEvents::Update(Events::StopUpdate))
                .map_err(|_| ())?;
            Err(())
        }
    }

    fn on_pass_component_response(
        &mut self,
        ctx: &mut InnerContext<impl PldmSocket>,
        response: pldm_packet::pass_component::PassComponentTableResponse,
    ) -> Result<(), ()> {
        // If unsuccessful, stop the update
        if response.completion_code != PldmBaseCompletionCode::Success as u8 {
            error!("PassComponent response failed");
            ctx.event_queue
                .send(PldmEvents::Update(Events::StopUpdate))
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

    fn on_start_download(&mut self, _ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        // TODO
        Ok(())
    }

    fn on_request_firmware(&mut self, _ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        // TODO
        Ok(())
    }

    fn on_transfer_fail(&mut self, _ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        // TODO
        Ok(())
    }

    fn on_transfer_success(&mut self, _ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        // TODO
        Ok(())
    }

    fn on_get_status(&mut self, _ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        // TODO
        Ok(())
    }

    fn on_verify_success(&mut self, _ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        // TODO
        Ok(())
    }

    fn on_verify_fail(&mut self, _ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        // TODO
        Ok(())
    }

    fn on_apply_success(&mut self, _ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        // TODO
        Ok(())
    }

    fn on_apply_fail(&mut self, _ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        // TODO
        Ok(())
    }

    fn on_activate_firmware(&mut self, _ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        // TODO
        Ok(())
    }

    fn on_get_metadata(&mut self, _ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        // TODO
        Ok(())
    }

    fn on_stop_update(&mut self, _ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        // TODO
        Ok(())
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

impl<T: StateMachineActions, S: PldmSocket> StateMachineContext for Context<T, S> {
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
        on_request_firmware() -> Result<(),()>,
        on_transfer_fail() -> Result<(),()>,
        on_transfer_success() -> Result<(),()>,
        on_get_status() -> Result<(),()>,
        on_stop_update() -> Result<(),()>,
        on_verify_success() -> Result<(),()>,
        on_verify_fail() -> Result<(),()>,
        on_apply_success() -> Result<(),()>,
        on_apply_fail() -> Result<(),()>,
        on_activate_firmware() -> Result<(),()>,
        on_get_metadata() -> Result<(),()>,
    }

    // Guards
    delegate_to_inner_guard! {
        are_all_components_passed() -> Result<bool, ()>,
    }
}
