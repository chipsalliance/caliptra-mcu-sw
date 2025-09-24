// Licensed under the Apache-2.0 license

use crate::doe_mbox_fsm::{DoeTestState, DoeTransportTest};
use crate::tests::doe_util::common::DoeUtil;
use crate::tests::doe_util::protocol::*;
use mcu_testing_common::{sleep_emulator_ticks, MCU_RUNNING};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, Sender};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use zerocopy::IntoBytes;

#[derive(EnumIter, Debug)]
pub enum DoeDiscoveryTest {
    DoeDiscovery,
    Spdm,
    SecureSpdm,
}

impl std::fmt::Display for DoeDiscoveryTest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DoeDiscoveryTest::DoeDiscovery => write!(f, "DoeDiscovery"),
            DoeDiscoveryTest::Spdm => write!(f, "DoeSpdm"),
            DoeDiscoveryTest::SecureSpdm => write!(f, "DoeSecureSpdm"),
        }
    }
}

impl DoeDiscoveryTest {
    pub fn generate_tests() -> Vec<Box<dyn DoeTransportTest + Send>> {
        DoeDiscoveryTest::iter()
            .map(|test| {
                let req_msg = test.request_message();
                let resp_msg = test.response_message();
                Box::new(Test::new(&test.to_string(), req_msg, resp_msg))
                    as Box<dyn DoeTransportTest + Send>
            })
            .collect()
    }

    fn request_message(&self) -> Vec<u8> {
        let index = match self {
            DoeDiscoveryTest::DoeDiscovery => DataObjectType::DoeDiscovery as u8,
            DoeDiscoveryTest::Spdm => DataObjectType::DoeSpdm as u8,
            DoeDiscoveryTest::SecureSpdm => DataObjectType::DoeSecureSpdm as u8,
        };
        DoeDiscoveryRequest::new(index).as_bytes().to_vec()
    }

    fn response_message(&self) -> Vec<u8> {
        match self {
            DoeDiscoveryTest::DoeDiscovery => Self::build_response(
                DataObjectType::DoeDiscovery,
                DataObjectType::DoeDiscovery as u8 + 1,
            ),
            DoeDiscoveryTest::Spdm => {
                Self::build_response(DataObjectType::DoeSpdm, DataObjectType::DoeSpdm as u8 + 1)
            }
            DoeDiscoveryTest::SecureSpdm => Self::build_response(DataObjectType::DoeSecureSpdm, 0),
        }
    }

    fn build_response(obj_protocol: DataObjectType, next_index: u8) -> Vec<u8> {
        DoeDiscoveryResponse::new(obj_protocol as u8, next_index)
            .as_bytes()
            .to_vec()
    }
}

struct Test {
    name: String,
    req_msg: Vec<u8>,
    resp_msg: Vec<u8>,
    test_state: DoeTestState,
    passed: bool,
}

impl Test {
    fn new(name: &str, req_msg: Vec<u8>, resp_msg: Vec<u8>) -> Self {
        Test {
            name: name.to_string(),
            req_msg,
            resp_msg,
            test_state: DoeTestState::Start,
            passed: false,
        }
    }
}

impl DoeTransportTest for Test {
    fn run_test(
        &mut self,
        tx: &mut Sender<Vec<u8>>,
        rx: &mut Receiver<Vec<u8>>,
        wait_for_responder: bool,
    ) {
        println!("DOE_DISCOVERY_TEST: Running test: {}", self.name);

        self.test_state = DoeTestState::Start;

        while MCU_RUNNING.load(Ordering::Relaxed) {
            match self.test_state {
                DoeTestState::Start => {
                    if wait_for_responder {
                        sleep_emulator_ticks(10_000_000);
                    }
                    self.test_state = DoeTestState::SendData;
                }
                DoeTestState::SendData => {
                    if DoeUtil::send_data_object(&self.req_msg, DataObjectType::DoeDiscovery, tx)
                        .is_ok()
                    {
                        self.test_state = DoeTestState::ReceiveData;
                        sleep_emulator_ticks(100_000);
                    } else {
                        println!("DOE_DISCOVERY_TEST: Failed to send request");
                        self.passed = false;
                        self.test_state = DoeTestState::Finish;
                    }
                }
                DoeTestState::ReceiveData => match DoeUtil::receive_data_object(rx) {
                    Ok(response) if !response.is_empty() => {
                        if response == self.resp_msg {
                            println!(
                                "DOE_DISCOVERY_TEST: Received response matches expected: {:?}",
                                response
                            );
                            self.passed = true;
                        } else {
                            println!(
                                    "DOE_DISCOVERY_TEST: Received response does not match expected: {:?} != {:?}",
                                    response, self.resp_msg
                                );
                            self.passed = false;
                        }
                        self.test_state = DoeTestState::Finish;
                    }
                    Ok(_) => {
                        // Stay in ReceiveData state and yield for a bit
                        sleep_emulator_ticks(100_000);
                    }
                    Err(e) => {
                        println!("DOE_DISCOVERY_TEST: Failed to receive response: {:?}", e);
                        self.passed = false;
                        self.test_state = DoeTestState::Finish;
                    }
                },
                DoeTestState::Finish => {
                    println!(
                        "DOE_DISCOVERY_TEST: Test {} {}",
                        self.name,
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
