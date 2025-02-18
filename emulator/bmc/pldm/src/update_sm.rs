use smlang::statemachine;
use crate::event_queue::EventQueue;
use crate::transport::PldmSocket;

#[derive(Debug)]
pub enum UpdateAgentEvents {
    Sm(Events),
    Rx,
    DeferredTx,
}


// Define the state machine
statemachine! {
    derive_states: [Debug],
    derive_events: [Clone, Debug],
    transitions: {
        *Idle + StartUpdate(u32) [can_start] / on_start_update = RequestUpdateSent,
        RequestUpdateSent + RequestUpdateResponse [is_request_update_response_valid] / on_request_update_response = LearnComponents,
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

pub trait StateMachineActions {
    // Guards
    fn can_start(&self, ctx : &InnerContext, some_value : &u32) -> Result<bool, ()> {
        println!("Can Start Update {}", some_value);
        Ok(true)
    }
    fn is_request_update_response_valid(&self, ctx : &InnerContext) -> Result<bool, ()> {
        Ok(true)
    }

    fn is_pass_component_response_valid(&self, ctx : &InnerContext) -> Result<bool, ()> {
        Ok(true)
    }

    fn are_all_components_passed(&self, ctx : &InnerContext) -> Result<bool, ()> {
        Ok(true)
    }

    fn can_update_component(&self, ctx : &InnerContext) -> Result<bool, ()> {
        Ok(true)
    }

    fn can_update_invalid(&self, ctx : &InnerContext) -> Result<bool, ()> {
        Ok(false)  // Example case where invalid data should not allow transition
    }

    fn can_request_firmware(&self, ctx : &InnerContext) -> Result<bool, ()> {
        Ok(true)
    }

    fn can_transfer_fail(&self, ctx : &InnerContext) -> Result<bool, ()> {
        Ok(true)
    }

    fn can_transfer_success(&self, ctx : &InnerContext) -> Result<bool, ()> {
        Ok(true)
    }

    fn can_get_status(&self, ctx : &InnerContext) -> Result<bool, ()> {
        Ok(true)
    }

    fn can_verify_success(&self, ctx : &InnerContext) -> Result<bool, ()> {
        Ok(true)
    }

    fn can_verify_fail(&self, ctx : &InnerContext) -> Result<bool, ()> {
        Ok(true)
    }

    fn can_apply_success(&self, ctx : &InnerContext) -> Result<bool, ()> {
        Ok(true)
    }

    fn can_apply_fail(&self, ctx : &InnerContext) -> Result<bool, ()> {
        Ok(true)
    }

    fn can_activate_firmware(&self, ctx : &InnerContext) -> Result<bool, ()> {
        Ok(true)
    }

    fn can_get_metadata(&self, ctx : &InnerContext) -> Result<bool, ()> {
        Ok(true)
    }

    // Actions
    fn on_start_update(&mut self, ctx : &mut InnerContext, some_value : u32) -> Result<(), ()> {
        println!("Starting Update {}", some_value);
        ctx.event_queue.enqueue(UpdateAgentEvents::Rx);
        Ok(())
    }
    fn on_request_update_response(&mut self, ctx : &mut InnerContext) -> Result<(), ()> {
        println!("Requesting Update");
        Ok(())
    }

    fn on_pass_component_response(&mut self, ctx : &mut InnerContext) -> Result<(), ()> {
        println!("Passing Component");
        Ok(())
    }

    fn on_update_component(&mut self, ctx : &mut InnerContext) -> Result<(), ()> {
        println!("Updating Component");
        Ok(())
    }

    fn on_update_invalid(&mut self, ctx : &mut InnerContext) -> Result<(), ()> {
        println!("Invalid Update Data");
        Ok(())
    }

    fn on_request_firmware(&mut self, ctx : &mut InnerContext) -> Result<(), ()> {
        println!("Requesting Firmware Data");
        Ok(())
    }

    fn on_transfer_fail(&mut self, ctx : &mut InnerContext) -> Result<(), ()> {
        println!("Transfer Failed");
        Ok(())
    }

    fn on_transfer_success(&mut self, ctx : &mut InnerContext) -> Result<(), ()> {
        println!("Transfer Successful");
        Ok(())
    }

    fn on_get_status(&mut self, ctx : &mut InnerContext) -> Result<(), ()> {
        println!("Getting Status");
        Ok(())
    }

    fn on_verify_success(&mut self, ctx : &mut InnerContext) -> Result<(), ()> {
        println!("Verification Successful");
        Ok(())
    }

    fn on_verify_fail(&mut self, ctx : &mut InnerContext) -> Result<(), ()> {
        println!("Verification Failed");
        Ok(())
    }

    fn on_apply_success(&mut self, ctx : &mut InnerContext) -> Result<(), ()> {
        println!("Apply Successful");
        Ok(())
    }

    fn on_apply_fail(&mut self, ctx : &mut InnerContext) -> Result<(), ()> {
        println!("Apply Failed");
        Ok(())
    }

    fn on_activate_firmware(&mut self, ctx : &mut InnerContext) -> Result<(), ()> {
        println!("Activating Firmware");
        Ok(())
    }

    fn on_get_metadata(&mut self, ctx : &mut InnerContext) -> Result<(), ()> {
        println!("Getting Metadata");
        Ok(())
    }

    fn on_cancel_update(&mut self, ctx : &mut InnerContext) -> Result<(), ()> {
        println!("Cancelling Update");
        Ok(())
    }

}

// Implement the context struct
pub struct DefaultActions;
impl StateMachineActions for DefaultActions {}

pub struct InnerContext {
    event_queue: EventQueue<UpdateAgentEvents>,
}

pub struct Context<T: StateMachineActions> {
    inner: T,
    inner_ctx: InnerContext,
}

impl<T: StateMachineActions> Context<T> {
    pub fn new(context: T, event_queue : EventQueue<UpdateAgentEvents>) -> Self {
        Self { inner: context, inner_ctx: InnerContext { event_queue } }
    }
}


macro_rules! impl_state_machine_context {
    ($context_type:ty, $inner_type:ty, $inner_ctx:ident, 
        guards: [$($guard:ident $(($param:ident : $param_ty:ty))?),*], 
        actions: [$($action:ident $(($action_param:ident : $action_ty:ty))?),*]
    ) => {
        impl<T: StateMachineActions> StateMachineContext for $context_type {
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
    Context<T>,
    StateMachineActions,
    inner_ctx,
    guards: [
        can_start(some_value: u32),
        is_request_update_response_valid,
        is_pass_component_response_valid,
        are_all_components_passed,
        can_update_component,
        can_update_invalid,
        can_request_firmware,
        can_transfer_fail,
        can_transfer_success,
        can_get_status,
        can_verify_success,
        can_verify_fail,
        can_apply_success,
        can_apply_fail,
        can_activate_firmware,
        can_get_metadata
    ],
    actions: [
        on_start_update(some_value: u32),
        on_request_update_response,
        on_pass_component_response,
        on_update_component,
        on_update_invalid,
        on_request_firmware,
        on_transfer_fail,
        on_transfer_success,
        on_get_status,
        on_cancel_update,
        on_verify_success,
        on_verify_fail,
        on_apply_success,
        on_apply_fail,
        on_activate_firmware,
        on_get_metadata
    ]
);
