// Licensed under the Apache-2.0 license

use emulator_periph::DoeMboxPeriph;
use rand::Rng;
use std::collections::VecDeque;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
enum DoeMboxState {
    Idle,
    SendData,
    ReceiveData,
    Error,
}

pub struct DoeMboxFsm {
    doe_mbox: DoeMboxPeriph,
}

impl DoeMboxFsm {
    pub fn new(doe_mbox: DoeMboxPeriph) -> Self {
        Self { doe_mbox: doe_mbox }
    }

    pub fn start(&mut self, running: Arc<AtomicBool>) -> (Receiver<Vec<u8>>, Sender<Vec<u8>>) {
        let (test_to_fsm_tx, test_to_fsm_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let (fsm_to_test_tx, fsm_to_test_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let running_clone = running.clone();
        let doe_mbox_clone = self.doe_mbox.clone();

        thread::spawn(move || {
            let mut fsm = DoeMboxStateMachine::new(doe_mbox_clone, fsm_to_test_tx);

            while running_clone.load(Ordering::Relaxed) {
                // Check for incoming messages from test
                if let Ok(message) = test_to_fsm_rx.try_recv() {
                    fsm.handle_outgoing_message(message);
                }

                // handle state transition events
                fsm.on_event();

                // Small delay to prevent busy waiting
                thread::sleep(Duration::from_millis(1));
            }
        });
        (fsm_to_test_rx, test_to_fsm_tx)
    }
}

struct DoeMboxStateMachine {
    state: DoeMboxState,
    doe_mbox: DoeMboxPeriph,
    fsm_to_test_tx: Sender<Vec<u8>>,
    pending_outgoing_message: Option<Vec<u8>>,
}

impl DoeMboxStateMachine {
    fn new(doe_mbox: DoeMboxPeriph, fsm_to_test_tx: Sender<Vec<u8>>) -> Self {
        Self {
            state: DoeMboxState::Idle,
            doe_mbox,
            fsm_to_test_tx,
            pending_outgoing_message: None,
        }
    }

    fn handle_outgoing_message(&mut self, message: Vec<u8>) {
        if self.state == DoeMboxState::Idle {
            println!("DOE_FSM: Handling outgoing message: {:?}", message);
            self.pending_outgoing_message = Some(message);
            self.state = DoeMboxState::SendData;
        }
    }

    fn on_event(&mut self) {
        match self.state {
            DoeMboxState::Idle => {
                self.handle_idle_state();
            }
            DoeMboxState::SendData => {
                self.handle_send_data_state();
            }
            DoeMboxState::ReceiveData => {
                self.handle_receive_data_state();
            }
            DoeMboxState::Error => {
                self.handle_error_state();
            }
        }
    }

    fn handle_idle_state(&mut self) {
        // Check if there is a pending outgoing message
        if self.pending_outgoing_message.is_some() {
            self.state = DoeMboxState::SendData;
        }
    }

    fn handle_send_data_state(&mut self) {
        if let Some(message) = self.pending_outgoing_message.take() {
            match self.doe_mbox.write_data(message) {
                Ok(()) => {
                    self.state = DoeMboxState::ReceiveData;
                }
                Err(_) => {
                    self.state = DoeMboxState::Error;
                }
            }
        } else {
            self.state = DoeMboxState::Idle;
        }
    }

    fn handle_receive_data_state(&mut self) {
        match self.doe_mbox.read_data() {
            Ok(Some(data)) => {
                // Process the received data
                self.fsm_to_test_tx.send(data).unwrap();
                self.state = DoeMboxState::Idle;
            }
            Ok(None) => {
                // No data received, do nothing
            }
            Err(_) => {
                // Error occurred, go to error state
                self.state = DoeMboxState::Error;
            }
        }
    }

    fn handle_error_state(&mut self) {
        // Go back to idle state to recover
        self.state = DoeMboxState::Idle;
    }
}

pub struct DoeTransportLoopbackTest {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
    test_vectors: VecDeque<Vec<u8>>,
}

impl DoeTransportLoopbackTest {
    const NUM_TEST_VECTORS: usize = 2;
    const MIN_TEST_DATA_SIZE: usize = 2 * 4; // Example minimum size of test vectors
    const MAX_TEST_DATA_SIZE: usize = 128 * 4; // Example maximum size of test vectors
    pub fn new(tx: Sender<Vec<u8>>, rx: Receiver<Vec<u8>>) -> Self {
        let mut rng = rand::thread_rng();
        let mut test_vectors = VecDeque::new();
        for _ in 0..Self::NUM_TEST_VECTORS {
            // Generate a random size (multiple of 4 bytes)
            let num_words =
                rng.gen_range((Self::MIN_TEST_DATA_SIZE / 4)..=(Self::MAX_TEST_DATA_SIZE / 4));
            let mut vector = vec![0u8; num_words * 4];
            rng.fill(vector.as_mut_slice());
            test_vectors.push_back(vector);
        }

        Self {
            tx,
            rx,
            test_vectors,
        }
    }

    pub fn run_tests(&mut self, running: Arc<AtomicBool>) {
        while running.load(Ordering::Relaxed) {
            if let Some(test_vector) = self.test_vectors.pop_front() {
                println!("Running test with vector: {}", test_vector.len());
                self.tx.send(test_vector.clone()).unwrap();

                if let Ok(response) = self.rx.recv() {
                    if response == test_vector {
                        println!("Test passed: Sent and received data match.");
                    } else {
                        println!(
                            "Test failed: Sent {:?}, but received {:?}.",
                            test_vector, response
                        );
                    }
                } else {
                    println!("Test failed: No response received from FSM.");
                }
            } else {
                // No more test vectors to process
                break;
            }
        }
    }
}

pub(crate) fn test_doe_transport_loopback(
    running: Arc<AtomicBool>,
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
) {
    thread::spawn(move || {
        let mut test = DoeTransportLoopbackTest::new(tx, rx);

        test.run_tests(running);
    });
}
