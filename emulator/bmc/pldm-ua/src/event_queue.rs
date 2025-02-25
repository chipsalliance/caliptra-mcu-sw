//use std::sync::mpsc::{self, Sender, Receiver};
use thingbuf::mpsc::{self, blocking};

/// Thread-safe event queue
pub struct EventQueue<Event: Default + Clone> {
    sender: blocking::Sender<Event>,
    receiver: Option<blocking::Receiver<Event>>,
}

impl<Event: Default + Clone> EventQueue<Event> {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::blocking::channel::<Event>(20);
        Self {
            sender: tx,
            receiver: Some(rx),
        }
    }

    pub fn enqueue(&self, event: Event) {
        if let Err(e) = self.sender.send(event) {
            eprintln!("Failed to send event: {:?}", e);
        }
    }

    pub fn dequeue(&self) -> Option<Event> {
        if let Some(receiver) = &self.receiver {
            receiver.recv()
        } else {
            None
        }
    }

    pub fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            receiver: None, // Receiver cannot be cloned
        }
    }
}

// Create a unit test for the event queue demonstrating enqueue and dequeue from multiple threads
#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;
    use crate::event_queue::EventQueue;

    // define an enum for events
    #[derive(Debug, Clone)]
    enum TestEvent {
        DataReceived(u8),
    }
    impl Default for TestEvent {
        fn default() -> Self {
            TestEvent::DataReceived(0)
        }
    }

    #[test]
    fn test_event_queue() {
        let queue = EventQueue::new();

        // Spawn a thread to enqueue events
        let queue_clone: EventQueue<TestEvent> = queue.clone();
        thread::spawn(move || {
            for i in 0..5 {
                queue_clone.enqueue(TestEvent::DataReceived(i));
                thread::sleep(Duration::from_millis(100));
            }
        });

        let queue_clone = queue.clone();
        thread::spawn(move || {
            for i in 6..8 {
                queue_clone.enqueue(TestEvent::DataReceived(i));
                thread::sleep(Duration::from_millis(100));
            }
        });

        // Dequeue events in the main thread
        for _ in 0..7 {
            if let Some(event) = queue.dequeue() {
                match event {
                    TestEvent::DataReceived(data) => println!("Received data: {}", data),
                }
            }
        }
    }
}