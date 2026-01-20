// Licensed under the Apache-2.0 license

use crate::discovery_sm;
use crate::events::PldmEvents;
use crate::transport::{PldmSocket, RxPacket};
use crate::update_sm;
use log::{debug, error, info, warn};
use pldm_fw_pkg::manifest::FirmwareDeviceIdRecord;
use pldm_fw_pkg::FirmwareManifest;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// `PldmDaemon` represents a process that provides PLDM Discovery and Firmware Update Agent services.
/// It manages the event loop and the reception loop for processing PLDM events and packets.
pub struct PldmDaemon<
    S: PldmSocket + Send + 'static,
    D: discovery_sm::StateMachineActions + Send + 'static,
    U: update_sm::StateMachineActions + Send + 'static,
> {
    event_loop_handle: Option<JoinHandle<()>>,
    event_queue_tx: Option<Sender<PldmEvents>>,
    update_sm: Arc<Mutex<update_sm::StateMachine<update_sm::Context<U, S>>>>,
    _phantom: std::marker::PhantomData<D>,
}

impl<
        S: PldmSocket + Send + 'static,
        D: discovery_sm::StateMachineActions + Send + 'static,
        U: update_sm::StateMachineActions + Send + 'static,
    > PldmDaemon<S, D, U>
{
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
    pub fn run(socket: S, opts: Options<D, U>) -> Result<Self, ()> {
        info!("PldmDaemon is running...");

        if opts.pldm_fw_pkg.is_none() {
            warn!("PLDM firmware package is not provided.");
            return Err(());
        }

        let (event_queue_tx, event_queue_rx) = mpsc::channel();
        let event_queue_tx_clone1 = event_queue_tx.clone();
        let event_queue_tx_clone2 = event_queue_tx.clone();
        let event_queue_tx_clone3 = event_queue_tx.clone();
        let event_queue_tx_clone4 = event_queue_tx.clone();
        let socket_clone1 = socket.clone();

        let discovery_sm = Arc::new(Mutex::new(discovery_sm::StateMachine::new(
            discovery_sm::Context::new(
                opts.discovery_sm_actions,
                socket.clone(),
                opts.fd_tid,
                event_queue_tx_clone1,
            ),
        )));

        let update_sm = Arc::new(Mutex::new(update_sm::StateMachine::new(
            update_sm::Context::new(
                opts.update_sm_actions,
                socket_clone1.clone(),
                opts.pldm_fw_pkg.unwrap(),
                event_queue_tx_clone4,
            ),
        )));

        let update_sm_clone = update_sm.clone();
        let running = Arc::new(AtomicBool::new(true));

        std::thread::spawn(move || {
            let _ = PldmDaemon::<S, D, U>::rx_loop(socket_clone1, event_queue_tx_clone3);
        });

        event_queue_tx.send(PldmEvents::Start).unwrap();

        let event_handle = std::thread::spawn(move || {
            let _ = PldmDaemon::event_loop(event_queue_rx, discovery_sm, update_sm_clone, running);
        });

        Ok(Self {
            event_loop_handle: Some(event_handle),
            event_queue_tx: Some(event_queue_tx_clone2),
            update_sm,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Stops the PLDM daemon.
    /// This function stops the PLDM daemon by enqueuing a `Stop` event and joining the event loop thread.
    pub fn stop(&mut self) {
        if let Some(event_queue) = self.event_queue_tx.take() {
            event_queue.send(PldmEvents::Stop).unwrap();
        }

        if let Some(handle) = self.event_loop_handle.take() {
            handle.join().unwrap();
        }
    }

    pub fn cancel_update(&mut self) {
        let update_sm = &mut *self.update_sm.lock().unwrap();
        update_sm
            .process_event(update_sm::Events::StopUpdate)
            .unwrap();
    }

    /// This thread receives PLDM packets and enqueues the corresponding events for processing.
    fn rx_loop(socket: S, event_queue_tx: Sender<PldmEvents>) -> Result<(), ()> {
        loop {
            match socket.receive(None).map_err(|_| ()) {
                Ok(rx_pkt) => {
                    debug!("Received response: {}", rx_pkt);
                    let ev = Self::handle_packet(&rx_pkt);
                    if ev.is_err() {
                        error!("Error handling packet: {:?}", ev);
                        // Ignore unexpected packet and continue
                        continue;
                    }
                    event_queue_tx.send(ev.unwrap()).map_err(|_| ())?;
                }
                Err(_) => {
                    error!("Error receiving packet");
                    event_queue_tx.send(PldmEvents::Stop).map_err(|_| ())?;
                    return Err(());
                }
            }
        }
    }

    /// This thread processes PLDM events including dispatching events to the appropriate state machine.
    fn event_loop(
        event_queue_rx: Receiver<PldmEvents>,
        discovery_sm: Arc<Mutex<discovery_sm::StateMachine<discovery_sm::Context<D, S>>>>,
        update_sm: Arc<Mutex<update_sm::StateMachine<update_sm::Context<U, S>>>>,
        running: Arc<AtomicBool>,
    ) -> Result<(), ()> {
        while running.load(Ordering::Relaxed) {
            let ev = event_queue_rx.recv().ok();
            if let Some(ev) = ev {
                debug!("Event Loop processing event: {:?}", ev);
                match ev {
                    PldmEvents::Start => {
                        // Wait for device-side PLDM service to initialize
                        // This avoids a race condition where discovery requests arrive
                        // before the device is ready to process them.
                        // The delay needs to be long enough for the MCU to boot,
                        // start the runtime, and initialize the PLDM service.
                        std::thread::sleep(Duration::from_secs(2));

                        // Start Discovery
                        let discovery_sm = &mut *discovery_sm.lock().unwrap();
                        discovery_sm
                            .process_event(discovery_sm::Events::StartDiscovery)
                            .unwrap();
                    }
                    PldmEvents::Discovery(sm_event) => {
                        let discovery_sm = &mut *discovery_sm.lock().unwrap();
                        debug!("Discovery state machine state: {:?}", discovery_sm.state());
                        if discovery_sm.process_event(sm_event).is_err() {
                            error!("Error processing discovery event");
                            // Continue to process other events
                        }
                    }
                    PldmEvents::Update(sm_event) => {
                        let update_sm = &mut *update_sm.lock().unwrap();
                        debug!(
                            "Firmware update state machine state: {:?}",
                            update_sm.state()
                        );
                        if update_sm.process_event(sm_event).is_err() {
                            error!("Error processing firmware update event");
                            // Continue to process other events
                        }
                    }
                    PldmEvents::Stop => {
                        let discovery_sm = &mut *discovery_sm.lock().unwrap();
                        discovery_sm
                            .process_event(discovery_sm::Events::CancelDiscovery)
                            .unwrap();
                        running.store(false, Ordering::Relaxed);
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
        let event = update_sm::process_packet(packet);
        if let Ok(event) = event {
            return Ok(event);
        }
        error!("Unhandled packet: {}", packet);
        Err(())
    }

    pub fn get_update_sm_state(&self) -> update_sm::States {
        let update_sm = &*self.update_sm.lock().unwrap();
        (*update_sm.state()).clone()
    }

    pub fn get_device_id(&self) -> Option<FirmwareDeviceIdRecord> {
        let update_sm = &*self.update_sm.lock().unwrap();
        update_sm.context().inner_ctx.device_id.clone()
    }
}

pub struct Options<D: discovery_sm::StateMachineActions, U: update_sm::StateMachineActions> {
    // Actions for the discovery state machine that can be customized as needed
    // Otherwise, the default actions will be used
    pub discovery_sm_actions: D,

    // The TID to be assigned to the firmware device
    pub fd_tid: u8,
    // Actions for the update state machine that can be customized as needed
    pub update_sm_actions: U,
    pub pldm_fw_pkg: Option<FirmwareManifest>,
}

impl Default for Options<discovery_sm::DefaultActions, update_sm::DefaultActions> {
    fn default() -> Self {
        Self {
            discovery_sm_actions: discovery_sm::DefaultActions {},
            update_sm_actions: update_sm::DefaultActions {},
            pldm_fw_pkg: None,
            fd_tid: 0,
        }
    }
}
