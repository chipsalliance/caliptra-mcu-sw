// Licensed under the Apache-2.0 license

use crate::doe_mbox_fsm::{DoeTestState, DoeTransportTest};
use rand::Rng;
const NUM_TEST_VECTORS: usize = 2;
const MIN_TEST_DATA_SIZE: usize = 2 * 4; // Example minimum size of test vectors
const MAX_TEST_DATA_SIZE: usize = 128 * 4; // Example maximum size of test vectors
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;

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
        let num_words = rng.gen_range((MIN_TEST_DATA_SIZE / 4)..=(MAX_TEST_DATA_SIZE / 4));
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
        running: Arc<AtomicBool>,
        tx: &mut Sender<Vec<u8>>,
        rx: &mut Receiver<Vec<u8>>,
    ) {
        println!(
            "DOE_TRANSPORT_LOOPBACK_TEST: Running test with test vec len: {} thread_id {:?}",
            self.test_vector.len(),
            thread::current().id()
        );
        let mut retry = 40;
        self.state = DoeTestState::Start;
        while running.load(Ordering::Relaxed) {
            match self.state {
                DoeTestState::Start => {
                    self.state = DoeTestState::SendData;
                }
                DoeTestState::SendData => {
                    tx.send(self.test_vector.clone()).unwrap();
                    self.state = DoeTestState::ReceiveData;
                }
                DoeTestState::ReceiveData => {
                    match rx.recv_timeout(Duration::from_millis(5)) {
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
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                            // println!("DOE_TRANSPORT_LOOPBACK_TEST: Timeout waiting for response. state is now {:?}", self.state);
                            retry -= 1;
                            if retry == 0 {
                                println!("DOE_TRANSPORT_LOOPBACK_TEST: Max retries reached, failing test.");
                                self.passed = false;
                                self.state = DoeTestState::Finish;
                            } else {
                                thread::sleep(Duration::from_millis(300));
                            }
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
                    break; // Exit the loop after finishing the test
                }
            }
        }
    }

    fn is_passed(&self) -> bool {
        self.passed
    }
}
