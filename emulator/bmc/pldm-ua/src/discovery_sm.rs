// Licensed under the Apache-2.0 license

use crate::events::PldmEvents;
use crate::timer::Timer;
use crate::transport::{PldmSocket, RxPacket, MAX_PLDM_PAYLOAD_SIZE};
use crate::update_sm;
use log::{debug, error, info};
use pldm_common::codec::PldmCodec;
use pldm_common::message::control::{self as pldm_packet, is_bit_set, GetPldmCommandsRequest};
use pldm_common::protocol::base::{
    InstanceId, PldmBaseCompletionCode, PldmControlCmd, PldmMsgHeader, PldmMsgType,
    PldmSupportedType, TransferOperationFlag, TransferRespFlag,
};
use pldm_common::protocol::firmware_update::FwUpdateCmd;
use pldm_common::protocol::version::{PLDM_BASE_PROTOCOL_VERSION, PLDM_FW_UPDATE_PROTOCOL_VERSION};
use smlang::statemachine;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RETRY_COUNT: u8 = 3;

// Define the state machine for PLDM Discovery Requester
statemachine! {
    derive_states: [Debug],
    derive_events: [Clone, Debug],
    transitions: {
        *Idle + StartDiscovery / on_start_discovery = SetTidSent,

        SetTidSent + SetTidResponse(pldm_packet::SetTidResponse) / on_set_tid_response = GetTIDSent,

        GetTIDSent + GetTIDResponse(pldm_packet::GetTidResponse) / on_get_tid_response = GetPLDMTypesSent,

        GetPLDMTypesSent + GetPLDMTypesResponse(pldm_packet::GetPldmTypeResponse) [is_valid_pldm_types_response0] / on_pldm_types_response = GetPLDMVersionType0Sent,

        GetPLDMVersionType0Sent + GetPLDMVersionResponse(pldm_packet::GetPldmVersionResponse) [is_pldm_version_response_valid] / on_pldm_version_response_type0 = GetPLDMCommandsType0Sent,

        GetPLDMCommandsType0Sent + GetPLDMCommandsResponse(pldm_packet::GetPldmCommandsResponse)  [is_pldm_commands_response_type0_valid] / on_pldm_commands_response_type0 = GetPLDMVersionType5Sent,

        GetPLDMVersionType5Sent + GetPLDMVersionResponse(pldm_packet::GetPldmVersionResponse) [is_pldm_version_response_valid] / on_pldm_version_response_type5 = GetPLDMCommandsType5Sent,

        GetPLDMCommandsType5Sent + GetPLDMCommandsResponse(pldm_packet::GetPldmCommandsResponse) [is_pldm_commands_response_type5_valid] / on_pldm_commands_response_type5 = Done,

        _ + CancelDiscovery / on_cancel_discovery = Done
    }
}

fn send_request_helper<P: PldmCodec>(
    ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
    message: &P,
) -> Result<(), ()> {
    debug!("Sending request");
    let mut buffer = [0u8; MAX_PLDM_PAYLOAD_SIZE];
    let sz = message.encode(&mut buffer).map_err(|_| ())?;
    ctx.response_timer.cancel();
    ctx.socket.send(&buffer[..sz]).map_err(|_| ())?;
    debug!("Sent request: {:?}", std::any::type_name::<P>());
    let packet_buf = buffer[..sz].to_vec();
    *ctx.retry_count.lock().unwrap() = 0;
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
    Ok(())
}

pub trait StateMachineActions {
    // Actions
    fn on_start_discovery(
        &self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
    ) -> Result<(), ()> {
        send_request_helper(
            ctx,
            &pldm_packet::SetTidRequest::new(ctx.instance_id, PldmMsgType::Request, ctx.fd_tid),
        )
    }
    fn on_set_tid_response(
        &self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
        _response: pldm_packet::SetTidResponse,
    ) -> Result<(), ()> {
        ctx.instance_id += 1;
        send_request_helper(
            ctx,
            &pldm_packet::GetTidRequest::new(ctx.instance_id, PldmMsgType::Request),
        )
    }
    fn on_get_tid_response(
        &self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
        _response: pldm_packet::GetTidResponse,
    ) -> Result<(), ()> {
        ctx.instance_id += 1;
        send_request_helper(
            ctx,
            &pldm_packet::GetPldmTypeRequest::new(ctx.instance_id, PldmMsgType::Request),
        )
    }
    fn on_pldm_types_response(
        &self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
        _response: pldm_packet::GetPldmTypeResponse,
    ) -> Result<(), ()> {
        ctx.instance_id += 1;
        send_request_helper(
            ctx,
            &pldm_packet::GetPldmVersionRequest::new(
                ctx.instance_id,
                PldmMsgType::Request,
                0, // data_transfer_handle
                TransferOperationFlag::GetFirstPart,
                PldmSupportedType::Base,
            ),
        )
    }
    fn on_pldm_version_response_type0(
        &self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
        _response: pldm_packet::GetPldmVersionResponse,
    ) -> Result<(), ()> {
        ctx.instance_id += 1;
        send_request_helper(
            ctx,
            &GetPldmCommandsRequest::new(
                ctx.instance_id,
                PldmMsgType::Request,
                PldmSupportedType::Base as u8,
                PLDM_BASE_PROTOCOL_VERSION,
            ),
        )
    }
    fn on_pldm_commands_response_type0(
        &self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
        _response: pldm_packet::GetPldmCommandsResponse,
    ) -> Result<(), ()> {
        ctx.instance_id += 1;
        send_request_helper(
            ctx,
            &pldm_packet::GetPldmVersionRequest::new(
                ctx.instance_id,
                PldmMsgType::Request,
                0, // data_transfer_handle
                TransferOperationFlag::GetFirstPart,
                PldmSupportedType::FwUpdate,
            ),
        )
    }
    fn on_pldm_version_response_type5(
        &self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
        _response: pldm_packet::GetPldmVersionResponse,
    ) -> Result<(), ()> {
        ctx.instance_id += 1;
        send_request_helper(
            ctx,
            &GetPldmCommandsRequest::new(
                ctx.instance_id,
                PldmMsgType::Request,
                PldmSupportedType::FwUpdate as u8,
                PLDM_FW_UPDATE_PROTOCOL_VERSION,
            ),
        )
    }
    fn on_pldm_commands_response_type5(
        &self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
        _response: pldm_packet::GetPldmCommandsResponse,
    ) -> Result<(), ()> {
        ctx.response_timer.cancel();
        ctx.event_queue
            .send(PldmEvents::Update(update_sm::Events::StartUpdate))
            .map_err(|_| ())?;
        Ok(())
    }
    fn on_cancel_discovery(
        &self,
        ctx: &mut InnerContext<impl PldmSocket + Send + 'static>,
    ) -> Result<(), ()> {
        ctx.response_timer.cancel();
        Ok(())
    }

    // Guards
    fn is_valid_pldm_types_response0(
        &self,
        ctx: &InnerContext<impl PldmSocket + Send + 'static>,
        response: &pldm_packet::GetPldmTypeResponse,
    ) -> Result<bool, ()> {
        // Verify correct instance id
        if response.hdr.instance_id() != ctx.instance_id {
            return Ok(false);
        }

        // Verify completion code is successful
        if response.completion_code != PldmBaseCompletionCode::Success as u8 {
            return Ok(false);
        }

        // Verify both base and fwupdate pldm types are supported
        if is_bit_set(&response.pldm_types, PldmSupportedType::Base as u8)
            && is_bit_set(&response.pldm_types, PldmSupportedType::FwUpdate as u8)
        {
            return Ok(true);
        }
        Ok(false)
    }
    fn is_pldm_version_response_valid(
        &self,
        ctx: &InnerContext<impl PldmSocket + Send + 'static>,
        response: &pldm_packet::GetPldmVersionResponse,
    ) -> Result<bool, ()> {
        // Verify correct instance id
        if response.hdr.instance_id() != ctx.instance_id {
            return Ok(false);
        }

        // Verify completion code is successful
        if response.completion_code != PldmBaseCompletionCode::Success as u8 {
            return Ok(false);
        }

        // Verify transfer flag
        if response.transfer_rsp_flag != TransferRespFlag::StartAndEnd as u8 {
            return Ok(false);
        }

        Ok(true)
    }
    fn is_pldm_commands_response_type0_valid(
        &self,
        ctx: &InnerContext<impl PldmSocket + Send + 'static>,
        response: &pldm_packet::GetPldmCommandsResponse,
    ) -> Result<bool, ()> {
        // Verify correct instance id
        if response.hdr.instance_id() != ctx.instance_id {
            return Ok(false);
        }
        if response.completion_code != PldmBaseCompletionCode::Success as u8 {
            return Ok(false);
        }
        let supported_cmds = [
            PldmControlCmd::GetTid,
            PldmControlCmd::SetTid,
            PldmControlCmd::GetPldmTypes,
            PldmControlCmd::GetPldmVersion,
            PldmControlCmd::GetPldmCommands,
        ];
        for cmd in supported_cmds {
            if !is_bit_set(&response.supported_cmds, cmd as u8) {
                return Ok(false);
            }
        }
        Ok(true)
    }
    fn is_pldm_commands_response_type5_valid(
        &self,
        ctx: &InnerContext<impl PldmSocket + Send + 'static>,
        response: &pldm_packet::GetPldmCommandsResponse,
    ) -> Result<bool, ()> {
        // Verify correct instance id
        if response.hdr.instance_id() != ctx.instance_id {
            return Ok(false);
        }
        if response.completion_code != PldmBaseCompletionCode::Success as u8 {
            return Ok(false);
        }
        let supported_cmds = [
            FwUpdateCmd::QueryDeviceIdentifiers,
            FwUpdateCmd::GetFirmwareParameters,
            FwUpdateCmd::RequestUpdate,
            FwUpdateCmd::PassComponentTable,
            FwUpdateCmd::UpdateComponent,
            FwUpdateCmd::RequestFirmwareData,
            FwUpdateCmd::TransferComplete,
            FwUpdateCmd::VerifyComplete,
            FwUpdateCmd::ApplyComplete,
            FwUpdateCmd::ActivateFirmware,
            FwUpdateCmd::GetStatus,
            FwUpdateCmd::CancelUpdateComponent,
            FwUpdateCmd::CancelUpdate,
        ];
        for cmd in supported_cmds {
            if !is_bit_set(&response.supported_cmds, cmd as u8) {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

fn packet_to_event<T: PldmCodec>(
    header: &PldmMsgHeader<impl AsRef<[u8]>>,
    packet: &RxPacket,
    event_constructor: fn(T) -> Events,
) -> Result<PldmEvents, ()> {
    debug!("Parsing command: {:?}", std::any::type_name::<T>());
    if !(header.rq() == 0 && header.datagram() == 0) {
        error!("Not a response");
        return Err(());
    }

    let response = T::decode(&packet.payload.data[..packet.payload.len]).map_err(|_| ())?;
    Ok(PldmEvents::Discovery(event_constructor(response)))
}

pub fn process_packet(packet: &RxPacket) -> Result<PldmEvents, ()> {
    debug!("Handling packet: {}", packet);
    let header = PldmMsgHeader::decode(&packet.payload.data[..packet.payload.len])
        .map_err(|_| (error!("Error decoding packet!")))?;
    if !header.is_hdr_ver_valid() {
        error!("Invalid header version!");
        return Err(());
    }
    if header.pldm_type() != PldmSupportedType::Base as u8 {
        return Err(());
    }

    // Convert packet to state machine event
    match PldmControlCmd::try_from(header.cmd_code()) {
        Ok(cmd) => match cmd {
            PldmControlCmd::SetTid => packet_to_event(&header, packet, Events::SetTidResponse),
            PldmControlCmd::GetTid => packet_to_event(&header, packet, Events::GetTIDResponse),
            PldmControlCmd::GetPldmTypes => {
                packet_to_event(&header, packet, Events::GetPLDMTypesResponse)
            }
            PldmControlCmd::GetPldmVersion => {
                packet_to_event(&header, packet, Events::GetPLDMVersionResponse)
            }
            PldmControlCmd::GetPldmCommands => {
                packet_to_event(&header, packet, Events::GetPLDMCommandsResponse)
            }
        },
        Err(_) => Err(()),
    }
}
// Implement the context struct
pub struct DefaultActions;
impl StateMachineActions for DefaultActions {}

pub struct InnerContext<S: PldmSocket + Send + 'static> {
    pub socket: S,
    pub event_queue: Sender<PldmEvents>,
    pub instance_id: InstanceId,
    fd_tid: u8,
    response_timer: Timer,
    retry_count: Arc<Mutex<u8>>,
}

pub struct Context<T: StateMachineActions, S: PldmSocket + Send + 'static> {
    inner: T,
    inner_ctx: InnerContext<S>,
}

impl<T: StateMachineActions, S: PldmSocket + Send + 'static> Context<T, S> {
    pub fn new(context: T, socket: S, fd_tid: u8, event_queue: Sender<PldmEvents>) -> Self {
        Self {
            inner: context,
            inner_ctx: InnerContext {
                socket,
                event_queue,
                instance_id: 0,
                fd_tid,
                response_timer: Timer::new(),
                retry_count: Arc::new(Mutex::new(0)),
            },
        }
    }
}

// Macros to delegate the state machine actions to the custom StateMachineActions passed to the state machine
// This allows overriding the implementation of the actions and guards
macro_rules! delegate_to_inner {
    ($($fn_name:ident ($($arg:ident : $arg_ty:ty),*) -> $ret:ty),* $(,)?) => {
        $(
            fn $fn_name(&mut self, $($arg: $arg_ty),*) -> $ret {
                debug!("Discovery Action: {}", stringify!($fn_name));
                self.inner.$fn_name(&mut self.inner_ctx, $($arg),*)
            }
        )*
    };

    ($($fn_name:ident (&$($arg:ident : $arg_ty:ty),*) -> $ret:ty),* $(,)?) => {
        $(
            fn $fn_name(&self, $($arg: $arg_ty),*) -> $ret {
                self.inner.$fn_name(&self.inner_ctx, $($arg),*)
            }
        )*
    };
}

impl<T: StateMachineActions, S: PldmSocket + Send + 'static> StateMachineContext for Context<T, S> {
    // Actions
    delegate_to_inner! {
        on_start_discovery() -> Result<(), ()>,
        on_set_tid_response(response: pldm_packet::SetTidResponse) -> Result<(), ()>,
        on_get_tid_response(response: pldm_packet::GetTidResponse) -> Result<(), ()>,
        on_pldm_types_response(response: pldm_packet::GetPldmTypeResponse) -> Result<(), ()>,
        on_pldm_version_response_type0(response: pldm_packet::GetPldmVersionResponse) -> Result<(), ()>,
        on_pldm_commands_response_type0(response: pldm_packet::GetPldmCommandsResponse) -> Result<(), ()>,
        on_pldm_version_response_type5(response: pldm_packet::GetPldmVersionResponse) -> Result<(), ()>,
        on_pldm_commands_response_type5(response: pldm_packet::GetPldmCommandsResponse) -> Result<(), ()>,
        on_cancel_discovery() -> Result<(), ()>,
    }

    // Guards
    delegate_to_inner! {
        is_valid_pldm_types_response0(&response: &pldm_packet::GetPldmTypeResponse) -> Result<bool, ()>,
        is_pldm_version_response_valid(&response: &pldm_packet::GetPldmVersionResponse) -> Result<bool, ()>,
        is_pldm_commands_response_type0_valid(&response: &pldm_packet::GetPldmCommandsResponse) -> Result<bool, ()>,
        is_pldm_commands_response_type5_valid(&response: &pldm_packet::GetPldmCommandsResponse) -> Result<bool, ()>
    }
}
