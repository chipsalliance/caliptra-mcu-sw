// Licensed under the Apache-2.0 license

use crate::doe_mbox_fsm::{DoeTestState, DoeTransportTest};
use caliptra_mcu_testing_common::doe_util::common::DoeUtil;
use caliptra_mcu_testing_common::doe_util::protocol::DataObjectType;
use caliptra_mcu_testing_common::sleep_emulator_ticks;
use rand::Rng;
use std::sync::mpsc::{Receiver, Sender};

const NUM_TEST_VECTORS: usize = 10;
const MIN_TEST_DATA_DWORDS: usize = 1; // minimum size of test vectors
const MAX_TEST_DATA_DWORDS: usize = 250; // maximum size of test vectors

const TEST_NAME: &str = "DOE_USER_LOOPBACK_TEST";

struct Test {
    test_vector: Vec<u8>,
    test_state: DoeTestState,
    passed: bool,
    retry_count: usize,
}

pub fn generate_tests() -> Vec<Box<dyn DoeTransportTest + Send>> {
    let mut rng = rand::thread_rng();
    let random_vectors = (0..NUM_TEST_VECTORS).map(|_| {
        let num_words = rng.gen_range(MIN_TEST_DATA_DWORDS..=MAX_TEST_DATA_DWORDS);
        let mut vector = vec![0u8; num_words * 4];
        rng.fill(vector.as_mut_slice());
        vector
    });
    let boundary_vectors = [1, 2, 3, 249, 250, 1, 250, 2, 249, 1]
        .into_iter()
        .enumerate()
        .map(|(index, num_words)| {
            (0..num_words * 4)
                .map(|offset| (offset as u8).wrapping_add(index as u8))
                .collect()
        });
    let mut tests: Vec<Box<dyn DoeTransportTest + Send>> = Vec::new();
    for vector in random_vectors.chain(boundary_vectors) {
        tests.push(Box::new(Test {
            test_vector: vector,
            test_state: DoeTestState::Start,
            passed: false,
            retry_count: 40,
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
            "{}: Running test with test vector len {}",
            TEST_NAME,
            self.test_vector.len()
        );

        self.test_state = DoeTestState::Start;

        while caliptra_mcu_testing_common::is_emulator_running() {
            match self.test_state {
                DoeTestState::Start => {
                    if wait_for_responder {
                        // Wait long enough for the firmware to initialize and register the
                        // DOE loopback handler. If the message is sent before the firmware
                        // registers (waiting_rx = true), the DOE driver will drop it and no
                        // echo will ever arrive. Empirically, firmware is ready within ~13M
                        // MCU ticks; 20M provides a comfortable margin.
                        sleep_emulator_ticks(20_000_000);
                    } else {
                        sleep_emulator_ticks(100_000);
                    }
                    self.test_state = DoeTestState::SendData;
                }
                DoeTestState::SendData => {
                    if DoeUtil::send_data_object(&self.test_vector, DataObjectType::DoeSpdm, tx)
                        .is_ok()
                    {
                        self.test_state = DoeTestState::ReceiveData;
                        sleep_emulator_ticks(100_000);
                    } else {
                        println!("{}: Failed to send request", TEST_NAME);
                        self.passed = false;
                        self.test_state = DoeTestState::Finish;
                    }
                }
                DoeTestState::ReceiveData => match DoeUtil::receive_data_object(rx) {
                    Ok(response) if !response.is_empty() => {
                        if response == self.test_vector {
                            println!(
                                "{}: Received response matches expected with len {}",
                                TEST_NAME,
                                response.len()
                            );
                            self.passed = true;
                        } else {
                            println!(
                                "{}: Received response does not match expected: {:?} != {:?}",
                                TEST_NAME, response, self.test_vector
                            );
                            self.passed = false;
                        }
                        self.test_state = DoeTestState::Finish;
                    }
                    Ok(_) => {
                        if self.retry_count > 0 {
                            self.retry_count -= 1;
                            // Stay in ReceiveData state and yield for a bit
                            std::thread::sleep(std::time::Duration::from_millis(300));
                            println!(
                                "{}: No response received, retrying... ({} retries left)",
                                TEST_NAME, self.retry_count
                            );
                        } else {
                            println!(
                                "{}: No response received after retries, failing test",
                                TEST_NAME
                            );
                            self.passed = false;
                            self.test_state = DoeTestState::Finish;
                        }
                    }
                    Err(e) => {
                        println!("{}: Failed to receive response: {:?}", TEST_NAME, e);
                        self.passed = false;
                        self.test_state = DoeTestState::Finish;
                    }
                },
                DoeTestState::Finish => {
                    println!(
                        "{}: Test with data len {} {}",
                        TEST_NAME,
                        self.test_vector.len(),
                        if self.passed { "passed!" } else { "failed!" }
                    );
                    break;
                }
            }
        }
    }

    fn is_passed(&self) -> bool {
        self.passed
    }
}
