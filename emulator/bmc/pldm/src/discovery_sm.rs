use core::error;

use crate::event_queue::EventQueue;
use crate::transport::{PldmSocket, RxPacket, MAX_PLDM_PAYLOAD_SIZE};
use log::{debug, error, info, trace, warn};
use pldm_common::codec::PldmCodec;
use pldm_common::message::control as pldm_packet;
use pldm_common::protocol::base::{InstanceId, PldmControlCmd, PldmMsgHeader, PldmMsgType};
use smlang::statemachine;

#[derive(Debug, Clone, Default)]
pub enum DiscoveryAgentEvents {
    Sm(Events),
    #[default]
    Rx,
    DeferredTx,
}

// Define the state machine for PLDM Discovery Requester
statemachine! {
    derive_states: [Debug],
    derive_events: [Clone, Debug],
    transitions: {
        *Idle + StartDiscovery / on_start_discovery = GetTIDSent,

        GetTIDSent + GetTIDResponse(pldm_packet::GetTidResponse) [is_tid_response_valid] / on_tid_response = GetPLDMTypesSent,

        GetPLDMTypesSent + GetPLDMTypesResponse(pldm_packet::GetPldmTypeResponse) [is_pldm_types_response_valid] / on_pldm_types_response = GetPLDMVersionType0Sent,

        GetPLDMVersionType0Sent + GetPLDMVersionResponse(pldm_packet::GetPldmVersionResponse) [is_pldm_version_response_valid] / on_pldm_version_response_type0 = GetPLDMCommandsType0Sent,

        GetPLDMCommandsType0Sent + GetPLDMCommandsResponse(pldm_packet::GetPldmCommandsResponse)  [is_pldm_commands_response_valid] / on_pldm_commands_response_type0 = GetPLDMVersionType1Sent,

        GetPLDMVersionType1Sent + GetPLDMVersionResponse(pldm_packet::GetPldmVersionResponse) [is_pldm_version_response_valid] / on_pldm_version_response_type1 = GetPLDMCommandsType1Sent,

        GetPLDMCommandsType1Sent + GetPLDMCommandsResponse(pldm_packet::GetPldmCommandsResponse) [is_pldm_commands_response_valid] / on_pldm_commands_response_type1 = Done,

        _ + CancelDiscovery / on_cancel_discovery = Idle
    }
}

pub trait StateMachineActions {
    // Actions
    fn on_start_discovery(&self, ctx: &InnerContext<impl PldmSocket>) -> Result<(), ()> {
        debug!("on_start_discovery");
        let request = pldm_packet::GetTidRequest::new(ctx.instance_id, PldmMsgType::Request);
        let mut buffer = [0u8; MAX_PLDM_PAYLOAD_SIZE];
        let sz = request.encode(&mut buffer).map_err(|_| ())?;
        ctx.socket.send(&buffer[..sz])?;
        Ok(())
    }
    fn on_tid_response(
        &self,
        ctx: &InnerContext<impl PldmSocket>,
        response: pldm_packet::GetTidResponse,
    ) -> Result<(), ()> {
        debug!("on_tid_response");
        Ok(())
    }
    fn on_pldm_types_response(
        &self,
        ctx: &InnerContext<impl PldmSocket>,
        response: pldm_packet::GetPldmTypeResponse,
    ) -> Result<(), ()> {
        debug!("on_pldm_types_response");
        Ok(())
    }
    fn on_pldm_version_response_type0(
        &self,
        ctx: &InnerContext<impl PldmSocket>,
        response: pldm_packet::GetPldmVersionResponse,
    ) -> Result<(), ()> {
        debug!("on_pldm_version_response_type0");
        Ok(())
    }
    fn on_pldm_commands_response_type0(
        &self,
        ctx: &InnerContext<impl PldmSocket>,
        response: pldm_packet::GetPldmCommandsResponse,
    ) -> Result<(), ()> {
        debug!("on_pldm_commands_response_type0");
        Ok(())
    }
    fn on_pldm_version_response_type1(
        &self,
        ctx: &InnerContext<impl PldmSocket>,
        response: pldm_packet::GetPldmVersionResponse,
    ) -> Result<(), ()> {
        debug!("on_pldm_version_response_type1");
        Ok(())
    }
    fn on_pldm_commands_response_type1(
        &self,
        ctx: &InnerContext<impl PldmSocket>,
        response: pldm_packet::GetPldmCommandsResponse,
    ) -> Result<(), ()> {
        debug!("on_pldm_commands_response_type1");
        Ok(())
    }
    fn on_cancel_discovery(&self, ctx: &InnerContext<impl PldmSocket>) -> Result<(), ()> {
        debug!("on_cancel_discovery");
        Ok(())
    }

    // Guards
    fn is_tid_response_valid(
        &self,
        ctx: &InnerContext<impl PldmSocket>,
        response: &pldm_packet::GetTidResponse,
    ) -> Result<bool, ()> {
        debug!("is_tid_response_valid");
        Ok(true)
    }
    fn is_pldm_types_response_valid(
        &self,
        ctx: &InnerContext<impl PldmSocket>,
        response: &pldm_packet::GetPldmTypeResponse,
    ) -> Result<bool, ()> {
        debug!("is_pldm_types_response_valid");
        Ok(true)
    }
    fn is_pldm_version_response_valid(
        &self,
        ctx: &InnerContext<impl PldmSocket>,
        response: &pldm_packet::GetPldmVersionResponse,
    ) -> Result<bool, ()> {
        debug!("is_pldm_version_response_valid");
        Ok(true)
    }
    fn is_pldm_commands_response_valid(
        &self,
        ctx: &InnerContext<impl PldmSocket>,
        response: &pldm_packet::GetPldmCommandsResponse,
    ) -> Result<bool, ()> {
        debug!("is_pldm_commands_response_valid");
        Ok(true)
    }
}

pub fn process_packet(packet: &RxPacket) -> Result<DiscoveryAgentEvents, ()> {
    debug!("Handling packet: {:?}", packet);
    let header = PldmMsgHeader::decode(&packet.payload.data[..packet.payload.len])
        .map_err(|_| (error!("Error decoding packet!")))?;
    if !header.is_hdr_ver_valid() {
        error!("Invalid header version!");
        return Err(());
    }

    if !header.is_valid_msg_type() {
        error!("Invalid msg type!");
        return Err(());
    }

    match PldmControlCmd::try_from(header.cmd_code()) {
        Ok(cmd) => {
            debug!("Command: {:?}", cmd);
            match cmd {
                PldmControlCmd::GetTid => {
                    debug!("GetTID command");
                    if header.rq() == 0 && header.datagram() == 0 {
                        error!("Not a GetTid response");
                        return Err(());
                    }
                    Ok(DiscoveryAgentEvents::Sm(Events::GetTIDResponse(
                        pldm_packet::GetTidResponse::decode(
                            &packet.payload.data[..packet.payload.len],
                        )
                        .map_err(|_| ())?,
                    )))
                }
                PldmControlCmd::GetPldmTypes => {
                    debug!("GetPLDMTypes command");
                    if header.rq() == 0 && header.datagram() == 0 {
                        error!("Not a GetPldmTypes response");
                        return Err(());
                    }
                    Ok(DiscoveryAgentEvents::Sm(Events::GetPLDMTypesResponse(
                        pldm_packet::GetPldmTypeResponse::decode(
                            &packet.payload.data[..packet.payload.len],
                        )
                        .map_err(|_| ())?,
                    )))
                }
                PldmControlCmd::GetPldmVersion => {
                    debug!("GetPLDMVersion command");
                    if header.rq() == 0 && header.datagram() == 0 {
                        error!("Not a GetPldmVersion response");
                        return Err(());
                    }
                    Ok(DiscoveryAgentEvents::Sm(Events::GetPLDMVersionResponse(
                        pldm_packet::GetPldmVersionResponse::decode(
                            &packet.payload.data[..packet.payload.len],
                        )
                        .map_err(|_| ())?,
                    )))
                }
                PldmControlCmd::GetPldmCommands => {
                    debug!("GetPLDMCommands command");
                    if header.rq() == 0 && header.datagram() == 0 {
                        error!("Not a GetPldmCommands response");
                        return Err(());
                    }
                    Ok(DiscoveryAgentEvents::Sm(Events::GetPLDMCommandsResponse(
                        pldm_packet::GetPldmCommandsResponse::decode(
                            &packet.payload.data[..packet.payload.len],
                        )
                        .map_err(|_| ())?,
                    )))
                }
                _ => Err(()),
            }
        }
        Err(_) => Err(()),
    }
}
// Implement the context struct
pub struct DefaultActions;
impl StateMachineActions for DefaultActions {}

pub struct InnerContext<S: PldmSocket> {
    event_queue: EventQueue<DiscoveryAgentEvents>,
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
                event_queue: EventQueue::new(),
                socket,
                instance_id: 0,
            },
        }
    }
}

impl<T: StateMachineActions, S: PldmSocket> StateMachineContext for Context<T, S> {
    // Actions
    fn on_start_discovery(&mut self) -> Result<(), ()> {
        self.inner.on_start_discovery(&mut self.inner_ctx)
    }
    fn on_tid_response(&mut self, response: pldm_packet::GetTidResponse) -> Result<(), ()> {
        self.inner.on_tid_response(&mut self.inner_ctx, response)
    }
    fn on_pldm_types_response(
        &mut self,
        response: pldm_packet::GetPldmTypeResponse,
    ) -> Result<(), ()> {
        self.inner
            .on_pldm_types_response(&mut self.inner_ctx, response)
    }
    fn on_pldm_version_response_type0(
        &mut self,
        response: pldm_packet::GetPldmVersionResponse,
    ) -> Result<(), ()> {
        self.inner
            .on_pldm_version_response_type0(&mut self.inner_ctx, response)
    }
    fn on_pldm_commands_response_type0(
        &mut self,
        response: pldm_packet::GetPldmCommandsResponse,
    ) -> Result<(), ()> {
        self.inner
            .on_pldm_commands_response_type0(&mut self.inner_ctx, response)
    }
    fn on_pldm_version_response_type1(
        &mut self,
        response: pldm_packet::GetPldmVersionResponse,
    ) -> Result<(), ()> {
        self.inner
            .on_pldm_version_response_type1(&mut self.inner_ctx, response)
    }
    fn on_pldm_commands_response_type1(
        &mut self,
        response: pldm_packet::GetPldmCommandsResponse,
    ) -> Result<(), ()> {
        self.inner
            .on_pldm_commands_response_type1(&mut self.inner_ctx, response)
    }
    fn on_cancel_discovery(&mut self) -> Result<(), ()> {
        self.inner.on_cancel_discovery(&mut self.inner_ctx)
    }

    // Guards
    fn is_tid_response_valid(&self, response: &pldm_packet::GetTidResponse) -> Result<bool, ()> {
        self.inner.is_tid_response_valid(&self.inner_ctx, response)
    }
    fn is_pldm_types_response_valid(
        &self,
        response: &pldm_packet::GetPldmTypeResponse,
    ) -> Result<bool, ()> {
        self.inner
            .is_pldm_types_response_valid(&self.inner_ctx, response)
    }
    fn is_pldm_version_response_valid(
        &self,
        response: &pldm_packet::GetPldmVersionResponse,
    ) -> Result<bool, ()> {
        self.inner
            .is_pldm_version_response_valid(&self.inner_ctx, response)
    }
    fn is_pldm_commands_response_valid(
        &self,
        response: &pldm_packet::GetPldmCommandsResponse,
    ) -> Result<bool, ()> {
        self.inner
            .is_pldm_commands_response_valid(&self.inner_ctx, response)
    }
}
