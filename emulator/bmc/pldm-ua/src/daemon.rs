use crate::discovery_sm;
use crate::event_queue::EventQueue;
use crate::events::PldmEvents;
use crate::transport::{FilterType, PldmSocket, RxPacket};
use simple_logger::SimpleLogger;
use log::{debug, error, info, trace, warn};

pub struct Daemon {}

impl Daemon {
    pub async fn run<S: PldmSocket + Send + 'static>(socket: S) -> Result<(), ()> {
        debug!("Daemon is running...");
        SimpleLogger::new().init().unwrap();
        let event_queue = EventQueue::<PldmEvents>::new();
        let event_queue_clone1 = event_queue.clone();
        let event_queue_clone2 = event_queue.clone();
        let socket_clone1 = socket.clone();
        let socket_clone2 = socket.clone();
        let socket_clone3 = socket.clone();
        Daemon::connect(socket).await?;

        let _ = Daemon::rx_loop_request(socket_clone1, event_queue_clone1);
        let _ = Daemon::rx_loop_response(socket_clone2, event_queue_clone2);
        Daemon::event_loop(socket_clone3, event_queue).await?;


        Ok(())
    }

    async fn connect<S: PldmSocket>(socket: S) -> Result<(), ()> {
        debug!("Daemon is connecting...");
        socket.connect().map_err(|_| ())?;
        Ok(())
    }

    async fn rx_loop_request<S: PldmSocket>(
        socket: S,
        event_queue: EventQueue<PldmEvents>,
    ) -> Result<(), ()> {
        loop {
            match socket.receive(None, FilterType::Request).map_err(|_| ()) {
                Ok(rx_pkt) => {
                    debug!("Received request: {}", rx_pkt);
                    //let _x = socket.send(&[1,2,3,4]);
                    let ev = Self::handle_packet(&rx_pkt)?;
                    event_queue.enqueue(ev);
                }
                Err(_) => {
                    debug!("Error receiving packet");
                    event_queue.enqueue(PldmEvents::TestEvent1);
                    return Err(());
                }
            }
        }
    }

    async fn rx_loop_response<S: PldmSocket>(
        socket: S,
        event_queue: EventQueue<PldmEvents>,
    ) -> Result<(), ()> {
        loop {
            match socket.receive(None, FilterType::Response).map_err(|_| ()) {
                Ok(rx_pkt) => {
                    debug!("Received response: {}", rx_pkt);
                    //let _x = socket.send(&[1,2,3,4]);
                    let ev = Self::handle_packet(&rx_pkt)?;
                    event_queue.enqueue(ev);
                }
                Err(_) => {
                    debug!("Error receiving packet");
                    event_queue.enqueue(PldmEvents::TestEvent1);
                    return Err(());
                }
            }
        }
    }

    async fn event_loop<S: PldmSocket>(
        socket: S,
        event_queue: EventQueue<PldmEvents>,
    ) -> Result<(), ()> {
        let mut discovery_sm = discovery_sm::StateMachine::new(discovery_sm::Context::new(
            discovery_sm::DefaultActions {},
            socket,
        ));
        debug!("Daemon Event loop is running...");
        while *discovery_sm.state() != discovery_sm::States::Done {
            let ev = event_queue.dequeue();
            if let Some(ev) = ev {
                debug!("Event Loop processing event: {:?}", ev);
                match ev {
                    PldmEvents::Discovery(event) => {
                        match event {
                            discovery_sm::DiscoveryAgentEvents::Sm(event) => {
                                debug!("Processing discovery event: {:?}", event);
                                let _ = discovery_sm.process_event(event);
                            }
                            _ => {
                                debug!("Unhandled discovery event: {:?}", event);
                            }
                        }
                    }
                    _ => {
                        debug!("Unknown event received: {:?}", ev);
                    }
                }
            }


        }
        

        

        Ok(())
    }

    fn handle_packet(packet: &RxPacket) -> Result<PldmEvents, ()> {
        debug!("Handling packet: {:?}", packet);
        let event = discovery_sm::process_packet(packet);
        if event.is_ok() {
            return Ok(PldmEvents::Discovery(event.unwrap()));
        }
        Ok(PldmEvents::TestEvent1)
    }
}
