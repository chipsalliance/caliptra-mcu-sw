// Licensed under the Apache-2.0 license

use emulator_periph::DoeMboxPeriph;
use mcu_testing_common::{sleep_emulator_ticks, wait_for_runtime_start, MCU_RUNNING};
use std::process::exit;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::time::Duration;

const TEST_TIMEOUT: u64 = 120;

#[derive(Debug, Clone, PartialEq)]
enum DoeMboxState {
    Idle,
    SendData,
    ReceiveData,
    WaitingResetAck,
    Error,
}

pub struct DoeMboxFsm {
    doe_mbox: DoeMboxPeriph,
}

impl DoeMboxFsm {
    pub fn new(doe_mbox: DoeMboxPeriph) -> Self {
        Self { doe_mbox }
    }

    pub fn start(&mut self) -> (Receiver<Vec<u8>>, Sender<Vec<u8>>) {
        let (test_to_fsm_tx, test_to_fsm_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let (fsm_to_test_tx, fsm_to_test_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let doe_mbox_clone = self.doe_mbox.clone();

        thread::spawn(move || {
            let mut fsm = DoeMboxStateMachine::new(doe_mbox_clone, fsm_to_test_tx);

            while MCU_RUNNING.load(Ordering::Relaxed) {
                // Check for incoming messages from test
                if let Ok(message) = test_to_fsm_rx.try_recv() {
                    fsm.handle_outgoing_message(message);
                }

                // handle state transition events
                fsm.on_event();

                // Small delay to prevent busy waiting
                sleep_emulator_ticks(1000);
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
            println!(
                "DOE_MBOX_FSM: Handling outgoing message of length {} dwords",
                message.len() / 4
            );
            self.pending_outgoing_message = Some(message);
            self.state = DoeMboxState::SendData;
        } else {
            // reset the pending message if we are not in idle state
            println!(
                "DOE_MBOX_FSM: Resetting the state before handling outgoing message of len {} dwords in state {:?}",
                message.len() / 4,
                self.state,
            );
            self.doe_mbox.request_reset();
            self.pending_outgoing_message = Some(message);
            self.state = DoeMboxState::WaitingResetAck;
        }
    }

    fn on_event(&mut self) {
        match self.state {
            DoeMboxState::Idle => {
                self.handle_idle_state();
            }
            DoeMboxState::WaitingResetAck => {
                // Handle waiting for reset acknowledgment
                if self.doe_mbox.check_reset_ack() {
                    self.state = DoeMboxState::SendData;
                } else {
                    // If reset is not acknowledged, stay in this state
                    println!("DOE_MBOX_FSM: Waiting for reset acknowledgment...");
                }
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

#[derive(Debug, Clone, PartialEq)]
pub enum DoeTestState {
    Start,
    SendData,
    ReceiveData,
    Finish,
}

pub trait DoeTransportTest {
    fn run_test(
        &mut self,
        tx: &mut Sender<Vec<u8>>,
        rx: &mut Receiver<Vec<u8>>,
        wait_for_responder: bool,
    );
    fn is_passed(&self) -> bool;
}

pub struct DoeTransportTestRunner {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
    test_vectors: Vec<Box<dyn DoeTransportTest + Send>>,
    passed: usize,
}

impl DoeTransportTestRunner {
    pub fn new(
        tx: Sender<Vec<u8>>,
        rx: Receiver<Vec<u8>>,
        tests: Vec<Box<dyn DoeTransportTest + Send>>,
    ) -> Self {
        Self {
            tx,
            rx,
            test_vectors: tests,
            passed: 0,
        }
    }

    pub fn run_tests(&mut self) {
        for (i, test) in self.test_vectors.iter_mut().enumerate() {
            test.run_test(&mut self.tx, &mut self.rx, i == 0);
            if test.is_passed() {
                self.passed += 1;
            }
        }

        if self.passed == self.test_vectors.len() {
            println!(
                "DOE_TRANSPORT_TESTS: All {}/{} tests passed successfully.",
                self.passed,
                self.test_vectors.len()
            );
            exit(0);
        } else {
            println!(
                "DOE_TRANSPORT_TESTS: Some tests failed. {}/{} tests passed.",
                self.passed,
                self.test_vectors.len()
            );
            exit(1);
        }
    }
}

pub(crate) fn run_doe_transport_tests(
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
    tests: Vec<Box<dyn DoeTransportTest + Send>>,
) {
    // Spawn a thread to handle the timeout for the test
    thread::spawn(move || {
        let timeout = Duration::from_secs(TEST_TIMEOUT);
        std::thread::sleep(timeout);
        println!(
            "DOE_TRANSPORT_TESTS Timeout after {:?} seconds",
            timeout.as_secs()
        );
        MCU_RUNNING.store(false, Ordering::Relaxed);
    });

    // Spawn a thread to run the tests
    thread::spawn(move || {
        wait_for_runtime_start();
        if !MCU_RUNNING.load(Ordering::Relaxed) {
            exit(-1);
        }
        let mut test = DoeTransportTestRunner::new(tx, rx, tests);

        test.run_tests();
        MCU_RUNNING.store(false, Ordering::Relaxed);
        println!("DOE_TRANSPORT_TESTS: All tests completed.");
    });
}
