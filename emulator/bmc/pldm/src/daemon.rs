use crate::transport::PldmSocket;
use crate::event_queue::EventQueue;
use crate::events::PldmEvents;

pub struct Daemon {
}

impl Daemon {
    pub async fn run<S: PldmSocket + Send + 'static>(socket: S) -> Result<(), ()> {
        println!("Daemon is running...");

        // Create an event queue
        let event_queue = EventQueue::<PldmEvents>::new();
        let event_queue_clone = event_queue.clone();

        let f1 = Daemon::rx_loop(socket, event_queue_clone);
        let f2 = Daemon::event_loop(event_queue);
        
        let result = futures::join!(f1, f2);
        result.0?;
        result.1?;

        Ok(())


    }

    pub async fn rx_loop<S:PldmSocket>(socket : S, event_queue : EventQueue<PldmEvents>) -> Result<(), ()> {
        loop {
            match socket.receive(None).map_err(|_| ()) {
                Ok(rx_pkt) => {
                    println!("Received request: {}", rx_pkt);
                    let _x = socket.send(rx_pkt.src, &[1,2,3,4]);
                    
                },
                Err(_) => {
                    println!("Error receiving packet");
                    event_queue.enqueue(PldmEvents::TestEvent1);
                    return Err(());
                    
                }
            }
        }

    }

    pub async fn event_loop(event_queue :EventQueue<PldmEvents>) -> Result<(), ()> {
        println!("Daemon Event loop is running...");
        let ev = event_queue.dequeue();
        println!("Event Loop processing event: {:?}", ev);



        Ok(())
    }
}

