use crate::transport::PldmSocket;
use crate::event_queue::EventQueue;
use crate::events::PldmEvents;
use crate::discovery_sm;
use pldm_common::{codec::PldmCodec, protocol::base::{PldmControlCmd, PldmMsgHeader}};
use log::{debug, error, info, trace, warn};

pub struct Daemon {
}

impl Daemon {
    pub async fn run<S: PldmSocket + Send + 'static>(socket: S) -> Result<(), ()> {
        debug!("Daemon is running...");

        // Create an event queue
        let event_queue = EventQueue::<PldmEvents>::new();
        let event_queue_clone = event_queue.clone();
        let socket_clone = socket.clone();

        let f1 = Daemon::rx_loop(socket, event_queue_clone);
        let f2 = Daemon::event_loop(socket_clone, event_queue);
        
        let result = futures::join!(f1, f2);
        result.0?;
        result.1?;

        Ok(())


    }

    pub async fn rx_loop<S:PldmSocket>(socket : S, event_queue : EventQueue<PldmEvents>) -> Result<(), ()> {
        loop {
            match socket.receive(None).map_err(|_| ()) {
                Ok(rx_pkt) => {
                    debug!("Received request: {}", rx_pkt);
                    //let _x = socket.send(&[1,2,3,4]);
                    let ev = Self::handle_packet(&rx_pkt.payload.data[..rx_pkt.payload.len])?;
                    event_queue.enqueue(ev);

                    
                },
                Err(_) => {
                    debug!("Error receiving packet");
                    event_queue.enqueue(PldmEvents::TestEvent1);
                    return Err(());
                    
                }
            }
        }

    }

    pub async fn event_loop<S: PldmSocket>(socket : S, event_queue :EventQueue<PldmEvents>) -> Result<(), ()> {
        let discovery_sm = discovery_sm::StateMachine::new(
            discovery_sm::Context::new(discovery_sm::DefaultActions {}, 
                socket)
            );
        debug!("Daemon Event loop is running...");
        let ev = event_queue.dequeue();
        debug!("Event Loop processing event: {:?}", ev);



        Ok(())
    }

    pub fn handle_packet(packet : &[u8]) -> Result<PldmEvents, ()> {
        debug!("Handling packet: {:?}", packet);
        let header = PldmMsgHeader::decode(packet).map_err(|_| ( error!("Error decoding packet!")))?;
        if !header.is_hdr_ver_valid() {
            error!("Invalid header version!");
            return Err(());
        }
        
        if !header.is_valid_msg_type() {
            error!("Invalid msg type!");
            return Err(());
        }
        discovery_sm::verify_discovery_packet_event(packet)?;
        Ok(PldmEvents::TestEvent1)
    }
}

