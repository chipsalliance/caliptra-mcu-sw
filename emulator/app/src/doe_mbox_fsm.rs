// Licensed under the Apache-2.0 license

use emulator_periph::DoeMboxPeriph;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;

// DOE Mailbox Register Offsets (from your RDL)
const DOE_MBOX_DLEN_OFFSET: u32 = 0x04;
const DOE_MBOX_STATUS_OFFSET: u32 = 0x08;
const DOE_MBOX_EVENT_OFFSET: u32 = 0x0C;
const DOE_MBOX_SRAM_BASE: u32 = 0x1000;

// Status register bit positions
const STATUS_DATA_READY: u32 = 1 << 0;
const STATUS_RESET_ACK: u32 = 1 << 1;
const STATUS_ERROR: u32 = 1 << 2;

// Event register bit positions
const EVENT_DATA_READY: u32 = 1 << 0;
const EVENT_RESET_REQ: u32 = 1 << 1;

#[derive(Debug, Clone, PartialEq)]
enum DoeMboxState {
    Idle,
    SendData,
    ReceiveData,
    Error,
}

pub struct DoeMboxFsm {
    state: DoeMboxState,
    doe_mbox: DoeMboxPeriph,
}

impl DoeMboxFsm {
    pub fn new(doe_mbox: DoeMboxPeriph) -> Self {
        Self {
            state: DoeMboxState::Idle,
            doe_mbox,
        }
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

pub(crate) fn test_doe_transport_loopback(
    running: Arc<AtomicBool>,
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
) {
    thread::spawn(move || {
        // Example test vector
        let test_vector = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03];
        println!("Starting loopback test with vector: {:?}", test_vector);
        // Send test vector to FSM
        tx.send(test_vector.clone()).unwrap();

        // Receive response from FSM
        if let Ok(response) = rx.recv() {
            // Compare sent and received data
            let success = response == test_vector;
            if success {
                println!("Loopback test passed: Sent and received data match.");
            } else {
                println!(
                    "Loopback test failed: Sent {:?}, but received {:?}.",
                    test_vector, response
                );
            }
        } else {
            println!("Loopback test failed: No response received from FSM.");
        }

        // Optionally stop the running flag
        running.store(false, Ordering::Relaxed);
    });
}
