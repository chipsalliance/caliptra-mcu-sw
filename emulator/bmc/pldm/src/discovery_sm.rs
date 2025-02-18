use smlang::statemachine;
use crate::event_queue::EventQueue;
use crate::transport::PldmSocket;
use crate::pldm_codec;

#[derive(Debug)]
pub enum DiscoveryAgentEvents {
    Sm(Events),
    Rx,
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
        println!("Checking TID Response validity...");
        Ok(true)
    }

    fn is_pldm_types_response_valid(&self, ctx: &InnerContext<impl PldmSocket>) -> Result<bool, ()> {
        println!("Checking PLDM Types Response validity...");
        Ok(true)
    }

    fn is_pldm_version_response_valid(&self, ctx: &InnerContext<impl PldmSocket>) -> Result<bool, ()> {
        println!("Checking PLDM Version Response validity...");
        Ok(true)
    }

    fn is_pldm_commands_response_valid(&self, ctx: &InnerContext<impl PldmSocket>) -> Result<bool, ()> {
        println!("Checking PLDM Commands Response validity...");
        Ok(true)
    }

    // Actions
    fn on_start_discovery(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        println!("Starting PLDM Discovery...");
        



        Ok(())
    }

    fn on_tid_response(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        println!("Received GetTID Response");
        Ok(())
    }

    fn on_pldm_types_response(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        println!("Received GetPLDMTypes Response");
        Ok(())
    }

    fn on_pldm_version_response_type0(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        println!("Received GetPLDMVersion Response for Type 0");
        Ok(())
    }

    fn on_pldm_commands_response_type0(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        println!("Received GetPLDMCommands Response for Type 0");
        Ok(())
    }

    fn on_pldm_version_response_type1(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        println!("Received GetPLDMVersion Response for Type 1");
        Ok(())
    }

    fn on_pldm_commands_response_type1(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        println!("Received GetPLDMCommands Response for Type 1");
        Ok(())
    }

    fn on_cancel_discovery(&mut self, ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        println!("Cancelling PLDM Discovery...");
        Ok(())
    }
}

// Implement the context struct
pub struct DefaultActions;
impl StateMachineActions for DefaultActions {}

pub struct InnerContext<S :PldmSocket> {
    event_queue: EventQueue<DiscoveryAgentEvents>,
    socket : S,
}

pub struct Context<T: StateMachineActions, S :PldmSocket> {
    inner: T,
    inner_ctx: InnerContext<S>,
}

impl<T: StateMachineActions, 

S: PldmSocket> Context<T,S> {
    pub fn new(context: T, socket : S) -> Self {
        Self { inner: context, inner_ctx: InnerContext { event_queue : EventQueue::new(), socket } }
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
