// Licensed under the Apache-2.0 license

use crate::events::PldmEvents;
use crate::{event_queue::EventQueue, transport::MAX_PLDM_PAYLOAD_SIZE};
use crate::transport::{PldmSocket, RxPacket};
use pldm_common::message::control::{is_bit_set, GetPldmCommandsRequest};
use pldm_common::message::firmware_update as pldm_packet;
use pldm_common::codec::PldmCodec;
use pldm_common::protocol::base::{InstanceId, PldmMsgHeader, PldmMsgType};
use pldm_common::protocol::firmware_update::{FwUpdateCmd, PldmFirmwareString};
use smlang::statemachine;
use log::{debug, error};


const MAX_TRANSFER_SIZE: u32 = 64;
const MAX_OUTSTANDING_TRANSFER_REQ : u8 = 1;

// Define the state machine
statemachine! {
    derive_states: [Debug],
    derive_events: [Clone, Debug],
    transitions: {
        *Idle + StartUpdate / on_start_update = QueryDeviceIdentifiersSent,
        QueryDeviceIdentifiersSent + QueryDeviceIdentifiersResponse(pldm_packet::query_devid::QueryDeviceIdentifiersResponse) / on_query_device_identifiers_response = GetFirmwareParametersSent,
        GetFirmwareParametersSent + GetFirmwareParametersResponse(pldm_packet::get_fw_params::GetFirmwareParametersResponse) / on_get_firmware_parameters_response = RequestUpdateSent,
        RequestUpdateSent + RequestUpdateResponse(pldm_packet::request_update::RequestUpdateResponse) [is_request_update_response_valid] / on_request_update_response = LearnComponents,
        LearnComponents + PassComponentResponse [is_pass_component_response_valid && !are_all_components_passed] / on_pass_component_response = LearnComponents,
        LearnComponents + PassComponentResponse [is_pass_component_response_valid && are_all_components_passed] / on_pass_component_response = ReadyXfer,
        LearnComponents + CancelUpdateOrTimeout  / on_cancel_update = Idle,

        ReadyXfer + UpdateComponent [can_update_component] / on_update_component = Download,
        ReadyXfer + UpdateComponentInvalidData [can_update_invalid] / on_update_invalid = ReadyXfer,
        ReadyXfer + CancelUpdateComponent  / on_cancel_update = Idle,

        Download + RequestFirmwareData [can_request_firmware] / on_request_firmware = Download,
        Download + TransferCompleteFail [can_transfer_fail] / on_transfer_fail = Idle,
        Download + TransferCompletePass [can_transfer_success] / on_transfer_success = Verify,
        Download + CancelUpdate  / on_cancel_update = Idle,

        Verify + GetStatus [can_get_status] / on_get_status = Verify,
        Verify + VerifyCompletePass [can_verify_success] / on_verify_success = Apply,
        Verify + VerifyCompleteFail [can_verify_fail] / on_verify_fail = Idle,
        Verify + CancelUpdate  / on_cancel_update = Idle,

        Apply + GetStatus [can_get_status] / on_get_status = Apply,
        Apply + ApplyCompleteFail [can_apply_fail] / on_apply_fail = Idle,
        Apply + ApplyCompletePass [can_apply_success] / on_apply_success = Activate,
        Apply + CancelUpdateComponent  / on_cancel_update = Idle,

        Activate + GetStatus [can_get_status] / on_get_status = Activate,
        Activate + GetMetaData [can_get_metadata] / on_get_metadata = Activate,
        Activate + ActivateFirmware [can_activate_firmware] / on_activate_firmware = Idle,
        Activate + CancelUpdate  / on_cancel_update = Idle,

        _ + StopUpdate = End
    }
}

fn send_request_helper<S: PldmSocket, P: PldmCodec>(socket: &S, message: &P) -> Result<(), ()> {
    let mut buffer = [0u8; MAX_PLDM_PAYLOAD_SIZE];
    let sz = message.encode(&mut buffer).map_err(|_| ())?;
    socket.send(&buffer[..sz]).map_err(|_| ())?;
    debug!("Sent request: {:?}", std::any::type_name::<P>());
    Ok(())
}
pub trait StateMachineActions {
    // Guards
    fn is_request_update_response_valid(&self, ctx: &InnerContext<impl PldmSocket>, response: &pldm_packet::request_update::RequestUpdateResponse) -> Result<bool, ()> {
        Ok(true)
    }

    fn is_pass_component_response_valid(&self, ctx: &InnerContext<impl PldmSocket>) -> Result<bool, ()> {
        Ok(true)
    }

    fn are_all_components_passed(&self, ctx: &InnerContext<impl PldmSocket>) -> Result<bool, ()> {
        Ok(true)
    }

    fn can_update_component(&self, ctx: &InnerContext<impl PldmSocket>) -> Result<bool, ()> {
        Ok(true)
    }

    fn can_update_invalid(&self, ctx: &InnerContext<impl PldmSocket>) -> Result<bool, ()> {
        Ok(false) // Example case where invalid data should not allow transition
    }

    fn can_request_firmware(&self, ctx: &InnerContext<impl PldmSocket>) -> Result<bool, ()> {
        Ok(true)
    }

    fn can_transfer_fail(&self, ctx: &InnerContext<impl PldmSocket>) -> Result<bool, ()> {
        Ok(true)
    }

    fn can_transfer_success(&self, ctx: &InnerContext<impl PldmSocket>) -> Result<bool, ()> {
        Ok(true)
    }

    fn can_get_status(&self, ctx: &InnerContext<impl PldmSocket>) -> Result<bool, ()> {
        Ok(true)
    }

    fn can_verify_success(&self, ctx: &InnerContext<impl PldmSocket>) -> Result<bool, ()> {
        Ok(true)
    }

    fn can_verify_fail(&self, ctx: &InnerContext<impl PldmSocket>) -> Result<bool, ()> {
        Ok(true)
    }

    fn can_apply_success(&self, ctx: &InnerContext<impl PldmSocket>) -> Result<bool, ()> {
        Ok(true)
    }

    fn can_apply_fail(&self, ctx: &InnerContext<impl PldmSocket>) -> Result<bool, ()> {
        Ok(true)
    }

    fn can_activate_firmware(&self, ctx: &InnerContext<impl PldmSocket>) -> Result<bool, ()> {
        Ok(true)
    }

    fn can_get_metadata(&self, ctx: &InnerContext<impl PldmSocket>) -> Result<bool, ()> {
        Ok(true)
    }

    // Actions
    fn on_start_update(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        send_request_helper(
            &ctx.socket,
            
            &pldm_packet::request_update::RequestUpdateRequest::new(
                ctx.instance_id,
                PldmMsgType::Request,
                MAX_TRANSFER_SIZE,
                0,
                MAX_OUTSTANDING_TRANSFER_REQ,
                0,
                &PldmFirmwareString::new("ASCII", "1.0.0").unwrap()
            ),
        )
    }
    fn on_request_update_response(&mut self, ctx: &mut InnerContext<impl PldmSocket>, response: pldm_packet::request_update::RequestUpdateResponse) -> Result<(), ()> {
        println!("Requesting Update");
        Ok(())
    }

    fn on_query_device_identifiers_response(&mut self, ctx: &mut InnerContext<impl PldmSocket>, response : pldm_packet::query_devid::QueryDeviceIdentifiersResponse) -> Result<(), ()> {
        Ok(())
    }

    fn on_get_firmware_parameters_response(&mut self, ctx: &mut InnerContext<impl PldmSocket>, response : pldm_packet::get_fw_params::GetFirmwareParametersResponse) -> Result<(), ()> {
        Ok(())
    }

    

    fn on_pass_component_response(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        println!("Passing Component");
        Ok(())
    }

    fn on_update_component(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        println!("Updating Component");
        Ok(())
    }

    fn on_update_invalid(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        println!("Invalid Update Data");
        Ok(())
    }

    fn on_request_firmware(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        println!("Requesting Firmware Data");
        Ok(())
    }

    fn on_transfer_fail(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        println!("Transfer Failed");
        Ok(())
    }

    fn on_transfer_success(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        println!("Transfer Successful");
        Ok(())
    }

    fn on_get_status(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        println!("Getting Status");
        Ok(())
    }

    fn on_verify_success(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        println!("Verification Successful");
        Ok(())
    }

    fn on_verify_fail(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        println!("Verification Failed");
        Ok(())
    }

    fn on_apply_success(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        println!("Apply Successful");
        Ok(())
    }

    fn on_apply_fail(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        println!("Apply Failed");
        Ok(())
    }

    fn on_activate_firmware(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        println!("Activating Firmware");
        Ok(())
    }

    fn on_get_metadata(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        println!("Getting Metadata");
        Ok(())
    }

    fn on_cancel_update(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        println!("Cancelling Update");
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

    // Convert packet to state machine event

    match FwUpdateCmd::try_from(header.cmd_code()) {
        Ok(cmd) => match cmd {
            FwUpdateCmd::QueryDeviceIdentifiers => packet_to_event(&header, packet, true, Events::QueryDeviceIdentifiersResponse),
            FwUpdateCmd::GetFirmwareParameters => packet_to_event(&header, packet, true, Events::GetFirmwareParametersResponse),
            FwUpdateCmd::RequestUpdate => packet_to_event(&header, packet, true, Events::RequestUpdateResponse),

            _ => {
                error!("Unknown discovery command");
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
    instance_id: InstanceId,
}

pub struct Context<T: StateMachineActions, S: PldmSocket> {
    inner: T,
    inner_ctx: InnerContext<S>,
}

impl<T: StateMachineActions, S: PldmSocket> Context<T, S> {
    pub fn new(context: T, socket: S) -> Self {
        Self {
            inner: context,
            inner_ctx: InnerContext {
                socket,
                instance_id: 0,
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
        on_get_firmware_parameters_response(response : pldm_packet::get_fw_params::GetFirmwareParametersResponse) -> Result<(), ()>,
        on_request_update_response(response: pldm_packet::request_update::RequestUpdateResponse) -> Result<(),()>,
        on_pass_component_response() -> Result<(),()>,
        on_update_component() -> Result<(),()>,
        on_update_invalid() -> Result<(),()>,
        on_request_firmware() -> Result<(),()>,
        on_transfer_fail() -> Result<(),()>,
        on_transfer_success() -> Result<(),()>,
        on_get_status() -> Result<(),()>,
        on_cancel_update() -> Result<(),()>,
        on_verify_success() -> Result<(),()>,
        on_verify_fail() -> Result<(),()>,
        on_apply_success() -> Result<(),()>,
        on_apply_fail() -> Result<(),()>,
        on_activate_firmware() -> Result<(),()>,
        on_get_metadata() -> Result<(),()>,
    }

    // Guards
    delegate_to_inner_guard! {
        is_request_update_response_valid(response: &pldm_packet::request_update::RequestUpdateResponse) -> Result<bool, ()>,
        is_pass_component_response_valid() -> Result<bool, ()>,
        are_all_components_passed() -> Result<bool, ()>,
        can_update_component() -> Result<bool, ()>,
        can_update_invalid() -> Result<bool, ()>,
        can_request_firmware() -> Result<bool, ()>,
        can_transfer_fail() -> Result<bool, ()>,
        can_transfer_success() -> Result<bool, ()>,
        can_get_status() -> Result<bool, ()>,
        can_verify_success() -> Result<bool, ()>,
        can_verify_fail() -> Result<bool, ()>,
        can_apply_success() -> Result<bool, ()>,
        can_apply_fail() -> Result<bool, ()>,
        can_activate_firmware() -> Result<bool, ()>,
        can_get_metadata() -> Result<bool, ()>,
    }
}

