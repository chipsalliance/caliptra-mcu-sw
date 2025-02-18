use crate::transport::PldmSocket;
use crate::event_queue::EventQueue;
use crate::events::PldmEvents;

use std::time::Duration;
use std::thread::sleep;
pub struct Daemon {
}

impl Daemon {
    pub fn run<S: PldmSocket + Send + 'static>(socket: S) -> Result<(), ()> {
        println!("Daemon is running...");

        // Create an event queue
        let event_queue = EventQueue::<PldmEvents>::new();
        let event_queue_clone = event_queue.clone();
        
        let h1 = std::thread::spawn(move || {
            Daemon::rx_loop(socket, event_queue_clone).unwrap();
        });
        

        // Spawn the event loop using std::thread
        let h = std::thread::spawn(move || {
            Daemon::event_loop(event_queue).unwrap();
        });

        // Wait for the threads to finish
        let _x = h.join();
        let _y = h1.join();
        
        Ok(())


    }

    pub fn rx_loop<S:PldmSocket>(socket : S, event_queue : EventQueue<PldmEvents>) -> Result<(), ()> {
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

        Ok(())
    }

    pub fn event_loop(event_queue :EventQueue<PldmEvents>) -> Result<(), ()> {
        println!("Daemon Event loop is running...");
        for i in 0..2 {
            let ev = event_queue.dequeue();
            println!("Event Loop processing event: {:?}", ev);
        }


        Ok(())
    }
}

