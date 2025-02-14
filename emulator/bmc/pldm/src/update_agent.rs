use crate::update_sm::{StateMachine, Context, StateMachineActions, States};
use crate::transport::PldmSocket;
use crate::event_queue::EventQueue;
use crate::update_sm::{UpdateAgentEvents,Events as SmEvents};
use crate::pldm_codec::PldmPacket;

pub struct UpdateAgent<T: StateMachineActions, S: PldmSocket> {
    sm: StateMachine<Context<T>>,
    socket : S,
    event_queue : EventQueue<UpdateAgentEvents>
}

impl<T: StateMachineActions, S: PldmSocket> UpdateAgent<T,S> {
    pub fn new(transitions: T, socket: S) -> Self {
        let q = EventQueue::new();
        Self {
            sm: StateMachine::new(Context::new(transitions, q.clone())),
            socket,
            event_queue: q
        }
    }

    pub fn start_update(&mut self) -> Result<(), ()> {
        self.event_queue.enqueue(UpdateAgentEvents::Sm(SmEvents::StartUpdate(5)));

        self.process_events()
    }

    fn process_event(&mut self, event: UpdateAgentEvents) -> Result<(), ()> {
        match event {
            UpdateAgentEvents::Sm(sm_event) => {
                println!("Processing state machine event: {:?}", sm_event);
                self.sm.process_event(sm_event)
                    .map(|_| ())
                    .map_err(|_| ())
            }
            UpdateAgentEvents::Rx => {
                self.listen()
            }
            UpdateAgentEvents::DeferredTx => {
                println!("Processing deferred transaction");
                Ok(())
            }
        }
    }

    fn process_events(&mut self) -> Result<(), ()> {
        while *self.sm.state() != States::End {
            match self.event_queue.dequeue() {
                Some(event) => {
                    println!("Processing event: {:?}", event);
                    self.process_event(event)?
                }
                None => {
                    println!("No events to process");
                    return Err(());
                }
            }
        } 
        println!("Update Agent Exiting");
        Ok(())

    }
    fn listen(&mut self) -> Result<(), ()> {

        match self.socket.receive(None).map_err(|_| ()) {
            Ok(rx_pkt) => {
                println!("Received request: {}", rx_pkt);
                let _x = self.socket.send(rx_pkt.src, &[1,2,3,4]);
                self.event_queue.enqueue(UpdateAgentEvents::Rx);
            },
            Err(_) => {
                println!("Error receiving packet");
                self.event_queue.enqueue(UpdateAgentEvents::Sm(SmEvents::StopUpdate));
            }
        }


 
        println!("Update Agent Exiting");
        Ok(())
    }
    fn handle_pldm_packet(&mut self, pkt: &[u8]) -> Result<(), ()> {

        Ok(())
    }

}