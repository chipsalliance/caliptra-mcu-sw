use std::thread::JoinHandle;

use crate::discovery_sm;
use crate::event_queue::EventQueue;
use crate::events::PldmEvents;
use crate::transport::{PldmSocket, RxPacket};
use log::{debug, error};

pub struct Daemon {}

impl Daemon {
    pub fn run<S: PldmSocket + Send + 'static, D: discovery_sm::StateMachineActions + Send + 'static>(socket: S, opts: Options<D>) -> JoinHandle<()> {
        debug!("Daemon is running...");
        
        let event_queue = EventQueue::<PldmEvents>::new();
        let event_queue_clone1 = event_queue.clone();
        let socket_clone1 = socket.clone();


       std::thread::spawn(move || {
            Daemon::rx_loop(socket_clone1, event_queue_clone1).unwrap();
        });

       std::thread::spawn(move || {
            Daemon::event_loop(socket, event_queue, opts.discovery_sm_actions).unwrap();
        })


        
    }

    fn rx_loop<S: PldmSocket>(
        socket: S,
        event_queue: EventQueue<PldmEvents>,
    ) -> Result<(), ()> {
        loop {
            match socket.receive(None).map_err(|_| ()) {
                Ok(rx_pkt) => {
                    debug!("Received response: {}", rx_pkt);
                    let ev = Self::handle_packet(&rx_pkt)?;
                    event_queue.enqueue(ev);
                }
                Err(_) => {
                    error!("Error receiving packet");
                    event_queue.enqueue(PldmEvents::Discovery(discovery_sm::DiscoveryAgentEvents::Sm(discovery_sm::Events::CancelDiscovery)));
                    return Err(());
                }
            }
        }
    }

    fn event_loop<S: PldmSocket, D: discovery_sm::StateMachineActions>(
        socket: S,
        event_queue: EventQueue<PldmEvents>,
        discovery_sm_actions: D,
    ) -> Result<(), ()> {
        let mut discovery_sm = discovery_sm::StateMachine::new(discovery_sm::Context::new(
            discovery_sm_actions,
            socket,
        ));

        let _ = discovery_sm.process_event(discovery_sm::Events::StartDiscovery);

        debug!("Daemon Event loop is running...");
        while *discovery_sm.state() != discovery_sm::States::Done {
            let ev = event_queue.dequeue();
            if let Some(ev) = ev {
                debug!("Event Loop processing event: {:?}", ev);
                match ev {
                    
                    PldmEvents::Discovery(event) => {
                        debug!("Discovery state machine state: {:?}", discovery_sm.state());
                        match event {
                            discovery_sm::DiscoveryAgentEvents::Sm(event) => {
                                debug!("Processing discovery event: {:?}", event);
                                let _ = discovery_sm.process_event(event);
                                debug!("Discovery state machine state: {:?}", discovery_sm.state());
                            }
                            _ => {
                                error!("Unhandled discovery event: {:?}", event);
                            }
                        }
                    }
                    _ => {
                        error!("Unknown event received: {:?}", ev);
                    }
                }
            }


        }
        

        Ok(())
    }

    fn handle_packet(packet: &RxPacket) -> Result<PldmEvents, ()> {
        debug!("Handling packet: {}", packet);
        let event = discovery_sm::process_packet(packet);
        if event.is_ok() {
            return Ok(PldmEvents::Discovery(event.unwrap()));
        }
        error!("Unhandled packet: {}", packet);
        Err(())
    }
}


pub struct Options <D: discovery_sm::StateMachineActions>{
    pub discovery_sm_actions: D,
}

impl Default for Options<discovery_sm::DefaultActions> {
    fn default() -> Self {
        Self {
            discovery_sm_actions: discovery_sm::DefaultActions {}
        }
    }
}