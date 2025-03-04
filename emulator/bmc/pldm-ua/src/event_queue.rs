// Licensed under the Apache-2.0 license
use std::sync::mpsc::{self, Receiver, Sender};

/// A thread-safe event queue that allows sending and receiving events asynchronously.
///
/// This queue uses Rust's multi-producer, single-consumer (`mpsc`) channel to enqueue and dequeue events.
/// It is designed to handle events that implement `Default` and `Clone` traits.
pub struct EventQueue<Event: Default + Clone> {
    sender: Sender<Event>,
    receiver: Option<Receiver<Event>>,
}

impl<Event: Default + Clone> Default for EventQueue<Event> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Event: Default + Clone> EventQueue<Event> {
    /// Creates a new event queue with a sender and receiver channel.
    ///
    /// # Returns
    /// A new `EventQueue` instance with an internal `mpsc` channel.
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            sender: tx,
            receiver: Some(rx),
        }
    }

    /// Enqueues an event into the queue.
    ///
    /// # Arguments
    /// * `event` - The event to be added to the queue.
    ///
    /// If sending fails (e.g., if the receiver has been dropped), an error message is printed.
    pub fn enqueue(&self, event: Event) {
        if let Err(e) = self.sender.send(event) {
            eprintln!("Failed to send event: {:?}", e);
        }
    }

    /// Dequeues an event from the queue.
    ///
    /// # Returns
    /// An `Option<Event>` containing the next event if available, or `None` if the queue is empty.
    pub fn dequeue(&self) -> Option<Event> {
        if let Some(receiver) = &self.receiver {
            receiver.recv().ok()
        } else {
            None
        }
    }
}

impl<Event: Default + Clone> Clone for EventQueue<Event> {
    /// Creates a clone of the event queue.
    ///
    /// # Returns
    /// A new `EventQueue` instance with a cloned sender.
    ///
    /// **Note:** The receiver cannot be cloned, so the new instance will not have a receiver.
    /// This means that only the original `EventQueue` instance should be used to dequeue events.
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            receiver: None, // Receiver cannot be cloned; only the original has a receiver.
        }
    }
}

// Create a unit test for the event queue demonstrating enqueue and dequeue from multiple threads
#[cfg(test)]
mod tests {
    use crate::event_queue::EventQueue;
    use std::thread;
    use std::time::Duration;

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
