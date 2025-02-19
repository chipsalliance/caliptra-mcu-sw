use pldm_common::codec::PldmCodec;
use smlang::statemachine;
use crate::event_queue::EventQueue;
use crate::transport::{PldmSocket, MAX_PLDM_PAYLOAD_SIZE};
use pldm_common::message::control::{GetTidRequest, GetTidResponse};
use pldm_common::protocol::base::{InstanceId, PldmControlCmd, PldmMsgHeader, PldmMsgType};
use log::{debug, error, info, trace, warn};

#[derive(Debug, Clone, Default)]
pub enum DiscoveryAgentEvents {
    Sm(Events),
    #[default] Rx,
    DeferredTx,
}

// Define the state machine for PLDM Discovery Requester
statemachine! {
    derive_states: [Debug],
    derive_events: [Clone, Debug],
    transitions: {
        *Idle + StartDiscovery / on_start_discovery = GetTIDSent,
        
        GetTIDSent + GetTIDResponse [is_tid_response_valid] / on_tid_response = GetPLDMTypesSent,
        
        GetPLDMTypesSent + GetPLDMTypesResponse [is_pldm_types_response_valid] / on_pldm_types_response = GetPLDMVersionType0Sent,
        
        GetPLDMVersionType0Sent + GetPLDMVersionResponse [is_pldm_version_response_valid] / on_pldm_version_response_type0 = GetPLDMCommandsType0Sent,
        
        GetPLDMCommandsType0Sent + GetPLDMCommandsResponse [is_pldm_commands_response_valid] / on_pldm_commands_response_type0 = GetPLDMVersionType1Sent,

        GetPLDMVersionType1Sent + GetPLDMVersionResponse [is_pldm_version_response_valid] / on_pldm_version_response_type1 = GetPLDMCommandsType1Sent,

        GetPLDMCommandsType1Sent + GetPLDMCommandsResponse [is_pldm_commands_response_valid] / on_pldm_commands_response_type1 = Done,

        _ + CancelDiscovery / on_cancel_discovery = Idle
    }
}

pub trait StateMachineActions {
    // Guards
    fn is_tid_response_valid(&self, ctx: &InnerContext<impl PldmSocket>) -> Result<bool, ()> {
        debug!("Checking TID Response validity...");
        Ok(true)
    }

    fn is_pldm_types_response_valid(&self, ctx: &InnerContext<impl PldmSocket>) -> Result<bool, ()> {
        debug!("Checking PLDM Types Response validity...");
        Ok(true)
    }

    fn is_pldm_version_response_valid(&self, ctx: &InnerContext<impl PldmSocket>) -> Result<bool, ()> {
        debug!("Checking PLDM Version Response validity...");
        Ok(true)
    }

    fn is_pldm_commands_response_valid(&self, ctx: &InnerContext<impl PldmSocket>) -> Result<bool, ()> {
        debug!("Checking PLDM Commands Response validity...");
        Ok(true)
    }

    // Actions
    fn on_start_discovery(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        debug!("Send GetTID Request");
        let request = GetTidRequest::new(ctx.instance_id, PldmMsgType::Request);
        let mut buffer = [0u8; MAX_PLDM_PAYLOAD_SIZE];
        let sz = request.encode(&mut buffer).map_err(|_| ())?;
        ctx.socket.send(&buffer[..sz])
    }

    fn on_tid_response(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        debug!("Received GetTID Response");
        Ok(())
    }

    fn on_pldm_types_response(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        debug!("Received GetPLDMTypes Response");
        Ok(())
    }

    fn on_pldm_version_response_type0(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        debug!("Received GetPLDMVersion Response for Type 0");
        Ok(())
    }

    fn on_pldm_commands_response_type0(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        debug!("Received GetPLDMCommands Response for Type 0");
        Ok(())
    }

    fn on_pldm_version_response_type1(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        debug!("Received GetPLDMVersion Response for Type 1");
        Ok(())
    }

    fn on_pldm_commands_response_type1(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        debug!("Received GetPLDMCommands Response for Type 1");
        Ok(())
    }

    fn on_cancel_discovery(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        debug!("Cancelling PLDM Discovery...");
        Ok(())
    }
}


pub fn verify_discovery_packet_event(packet: &[u8])->Result<DiscoveryAgentEvents, ()> {
    debug!("Handling packet: {:?}", packet);
    let header = PldmMsgHeader::decode(packet).map_err(|_| (error!("Error decoding packet!")))?;
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
                    Ok(DiscoveryAgentEvents::Sm(Events::GetTIDResponse))
                },
                PldmControlCmd::GetPldmTypes => {
                    debug!("GetPLDMTypes command");
                    Ok(DiscoveryAgentEvents::Sm(Events::GetPLDMTypesResponse))
                },
                PldmControlCmd::GetPldmVersion => {
                    debug!("GetPLDMVersion command");
                    Ok(DiscoveryAgentEvents::Sm(Events::GetPLDMVersionResponse))
                },
                PldmControlCmd::GetPldmCommands => {
                    debug!("GetPLDMCommands command");
                    Ok(DiscoveryAgentEvents::Sm(Events::GetPLDMCommandsResponse))
                },
                _ => Err(()),
            }
        },
        Err(_) => Err(()),
    }
}
// Implement the context struct
pub struct DefaultActions;
impl StateMachineActions for DefaultActions {}

pub struct InnerContext<S :PldmSocket> {
    event_queue: EventQueue<DiscoveryAgentEvents>,
    socket : S,
    instance_id: InstanceId,
}

pub struct Context<T: StateMachineActions, S :PldmSocket> {
    inner: T,
    inner_ctx: InnerContext<S>,
}

impl<T: StateMachineActions, 

S: PldmSocket> Context<T,S> {
    pub fn new(context: T, socket : S) -> Self {
        Self { inner: context, inner_ctx: InnerContext { event_queue : EventQueue::new(), socket, instance_id : 0} }
    }
}

// Implement the state machine context
macro_rules! impl_state_machine_context {
    ($context_type:ty, $inner_type:ty, $inner_ctx:ident, 
        guards: [$($guard:ident $(($param:ident : $param_ty:ty))?),*], 
        actions: [$($action:ident $(($action_param:ident : $action_ty:ty))?),*]
    ) => {
        impl<T: StateMachineActions, S: PldmSocket> StateMachineContext for $context_type {
            $( 
                fn $guard(&self $(, $param: &$param_ty)?) -> Result<bool, ()> {
                    self.inner.$guard(&self.$inner_ctx $(, $param)?)
                }
            )*

            $( 
                fn $action(&mut self $(, $action_param: $action_ty)?) -> Result<(), ()> {
                    self.inner.$action(&mut self.$inner_ctx $(, $action_param)?)
                }
            )*
        }
    };
}

impl_state_machine_context!(
    Context<T,S>,
    StateMachineActions,
    inner_ctx,
    guards: [
        is_tid_response_valid,
        is_pldm_types_response_valid,
        is_pldm_version_response_valid,
        is_pldm_commands_response_valid
    ],
    actions: [
        on_start_discovery,
        on_tid_response,
        on_pldm_types_response,
        on_pldm_version_response_type0,
        on_pldm_commands_response_type0,
        on_pldm_version_response_type1,
        on_pldm_commands_response_type1,
        on_cancel_discovery
    ]
);
