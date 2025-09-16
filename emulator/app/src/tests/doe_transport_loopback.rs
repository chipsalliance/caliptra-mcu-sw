// Licensed under the Apache-2.0 license

use crate::doe_mbox_fsm::{DoeTestState, DoeTransportTest};
use mcu_testing_common::{sleep_emulator_ticks, MCU_RUNNING};
use rand::Rng;
const NUM_TEST_VECTORS: usize = 10;
const MIN_TEST_DATA_DWORDS: usize = 2; // minimum size of test vectors
const MAX_TEST_DATA_DWORDS: usize = 128; // maximum size of test vectors
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, Sender};

struct Test {
    test_vector: Vec<u8>,
    state: DoeTestState,
    passed: bool,
}

pub fn generate_tests() -> Vec<Box<dyn DoeTransportTest + Send>> {
    let mut rng = rand::thread_rng();
    let mut tests: Vec<Box<dyn DoeTransportTest + Send>> = Vec::new();
    for _ in 0..NUM_TEST_VECTORS {
        // Generate a random size (multiple of 4 bytes)
        let num_words = rng.gen_range((MIN_TEST_DATA_DWORDS)..=(MAX_TEST_DATA_DWORDS));
        let mut vector = vec![0u8; num_words * 4];
        rng.fill(vector.as_mut_slice());
        tests.push(Box::new(Test {
            test_vector: vector,
            state: DoeTestState::Start,
            passed: false,
        }));
    }
    tests
}

impl DoeTransportTest for Test {
    fn run_test(
        &mut self,
        tx: &mut Sender<Vec<u8>>,
        rx: &mut Receiver<Vec<u8>>,
        wait_for_responder: bool,
    ) {
        println!(
            "DOE_TRANSPORT_LOOPBACK_TEST: Running test with test vec len: {} bytes",
            self.test_vector.len()
        );

        self.state = DoeTestState::Start;

        while MCU_RUNNING.load(Ordering::Relaxed) {
            match self.state {
                DoeTestState::Start => {
                    // waits for the responder to be ready if this is the first message to send
                    if wait_for_responder {
                        println!("Waiting for responder to be ready...(10,000,000 ticks)");
                        sleep_emulator_ticks(10_000_000);
                    }
                    self.state = DoeTestState::SendData;
                }
                DoeTestState::SendData => {
                    if let Err(e) = tx.send(self.test_vector.clone()) {
                        println!(
                            "DOE_TRANSPORT_LOOPBACK_TEST: Failed to send test vector: {:?}",
                            e
                        );
                        self.passed = false;
                        self.state = DoeTestState::Finish;
                        continue;
                    }
                    self.state = DoeTestState::ReceiveData;
                    sleep_emulator_ticks(100_000);
                }
                DoeTestState::ReceiveData => {
                    match rx.try_recv() {
                        Ok(response) => {
                            if response == self.test_vector {
                                println!("DOE_TRANSPORT_LOOPBACK_TEST: Test passed: Sent and received data match.");
                                self.passed = true;
                            } else {
                                println!(
                                    "DOE_TRANSPORT_LOOPBACK_TEST: Test failed: Sent {:?}, but received {:?}.",
                                    self.test_vector, response
                                );
                                self.passed = false;
                            }
                            self.state = DoeTestState::Finish;
                        }
                        Err(std::sync::mpsc::TryRecvError::Empty) => {
                            // No data yet, stay in ReceiveData state and yield for a bit
                            sleep_emulator_ticks(100_000);
                        }
                        Err(e) => {
                            println!(
                                "DOE_TRANSPORT_LOOPBACK_TEST: Error receiving response: {:?}",
                                e
                            );
                            self.passed = false;
                            self.state = DoeTestState::Finish;
                        }
                    }
                }
                DoeTestState::Finish => {
                    break;
                }
            }
        }
    }

    fn is_passed(&self) -> bool {
        self.passed
    }
}
