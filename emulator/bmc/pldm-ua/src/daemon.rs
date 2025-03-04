// Licensed under the Apache-2.0 license

use crate::discovery_sm;
use crate::event_queue::EventQueue;
use crate::events::PldmEvents;
use crate::transport::{PldmSocket, RxPacket};
use log::{debug, error, info};
use std::thread::JoinHandle;

/// `PldmDaemon` represents a process that provides PLDM Discovery and Firmware Update Agent services.
/// It manages the event loop and the reception loop for processing PLDM events and packets.
pub struct PldmDaemon {
    event_loop_handle: Option<JoinHandle<()>>,
    event_queue_tx: Option<EventQueue<PldmEvents>>,
}

impl PldmDaemon {
    /// Runs the PLDM daemon.
    ///
    /// This function starts the PLDM daemon by spawning two threads:
    /// - One for receiving packets (`rx_loop`).
    /// - One for processing events (`event_loop`).
    ///
    /// # Arguments
    ///
    /// * `socket` - The PLDM socket used for communication.
    /// * `opts` - Service Options
    ///
    /// # Returns
    ///
    /// Returns an instance of `PldmDaemon`.
    pub fn run<
        S: PldmSocket + Send + 'static,
        D: discovery_sm::StateMachineActions + Send + 'static,
    >(
        socket: S,
        opts: Options<D>,
    ) -> Self {
        info!("PldmDaemon is running...");

        let event_queue = EventQueue::<PldmEvents>::new();
        let event_queue_clone1 = event_queue.clone();
        let event_queue_clone2 = event_queue.clone();
        let socket_clone1 = socket.clone();

        std::thread::spawn(move || {
            PldmDaemon::rx_loop(socket_clone1, event_queue_clone1).unwrap();
        });

        event_queue.enqueue(PldmEvents::Start);

        let event_handle = std::thread::spawn(move || {
            PldmDaemon::event_loop(socket, event_queue, opts.discovery_sm_actions).unwrap();
        });

        Self {
            event_loop_handle: Some(event_handle),
            event_queue_tx: Some(event_queue_clone2),
        }
    }

    /// Stops the PLDM daemon.
    /// This function stops the PLDM daemon by enqueuing a `Stop` event and joining the event loop thread.
    pub fn stop(&mut self) {
        if let Some(event_queue) = self.event_queue_tx.take() {
            event_queue.enqueue(PldmEvents::Stop);
        }

        if let Some(handle) = self.event_loop_handle.take() {
            handle.join().unwrap();
        }
    }

    /// This thread receives PLDM packets and enqueues the corresponding events for processing.
    fn rx_loop<S: PldmSocket>(socket: S, event_queue: EventQueue<PldmEvents>) -> Result<(), ()> {
        loop {
            match socket.receive(None).map_err(|_| ()) {
                Ok(rx_pkt) => {
                    debug!("Received response: {}", rx_pkt);
                    let ev = Self::handle_packet(&rx_pkt)?;
                    event_queue.enqueue(ev);
                }
                Err(_) => {
                    error!("Error receiving packet");
                    event_queue.enqueue(PldmEvents::Stop);
                    return Err(());
                }
            }
        }
    }

    /// This thread processes PLDM events including dispatching events to the appropriate state machine.
    fn event_loop<S: PldmSocket, D: discovery_sm::StateMachineActions>(
        socket: S,
        event_queue: EventQueue<PldmEvents>,
        discovery_sm_actions: D,
    ) -> Result<(), ()> {
        let mut discovery_sm = discovery_sm::StateMachine::new(discovery_sm::Context::new(
            discovery_sm_actions,
            socket,
        ));

        while *discovery_sm.state() != discovery_sm::States::Done {
            let ev = event_queue.dequeue();
            if let Some(ev) = ev {
                info!("Event Loop processing event: {:?}", ev);
                match ev {
                    PldmEvents::Start => {
                        // Start Discovery
                        discovery_sm
                            .process_event(discovery_sm::Events::StartDiscovery)
                            .unwrap();
                    }
                    PldmEvents::Discovery(sm_event) => {
                        debug!("Discovery state machine state: {:?}", discovery_sm.state());
                        if discovery_sm.process_event(sm_event).is_err() {
                            error!("Error processing discovery event");
                            // Continue to process other events
                        }
                    }
                    PldmEvents::Stop => {
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_packet(packet: &RxPacket) -> Result<PldmEvents, ()> {
        debug!("Handling packet: {}", packet);
        let event = discovery_sm::process_packet(packet);
        if let Ok(event) = event {
            return Ok(event);
        }
        error!("Unhandled packet: {}", packet);
        Err(())
    }
}

pub struct Options<D: discovery_sm::StateMachineActions> {
    // Actions for the discovery state machine that can be customized as needed
    // Otherwise, the default actions will be used
    pub discovery_sm_actions: D,
}

impl Default for Options<discovery_sm::DefaultActions> {
    fn default() -> Self {
        Self {
            discovery_sm_actions: discovery_sm::DefaultActions {},
        }
    }
}
