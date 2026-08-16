// Licensed under the Apache-2.0 license

use crate::doe_mbox_fsm::{DoeTestState, DoeTransportTest};
use caliptra_mcu_testing_common::doe_util::common::DoeUtil;
use caliptra_mcu_testing_common::doe_util::protocol::*;
use caliptra_mcu_testing_common::sleep_emulator_ticks;
use std::sync::mpsc::{Receiver, Sender};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use zerocopy::IntoBytes;

#[derive(EnumIter, Debug)]
pub enum DoeDiscoveryTest {
    DoeDiscovery,
    Spdm,
    SecureSpdm,
    OutOfRangeIndex,
    MaxIndex,
    SupportedVersion,
    UnsupportedVersion,
}

impl std::fmt::Display for DoeDiscoveryTest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DoeDiscoveryTest::DoeDiscovery => write!(f, "DoeDiscovery"),
            DoeDiscoveryTest::Spdm => write!(f, "DoeSpdm"),
            DoeDiscoveryTest::SecureSpdm => write!(f, "DoeSecureSpdm"),
            DoeDiscoveryTest::OutOfRangeIndex => write!(f, "DoeOutOfRangeIndex"),
            DoeDiscoveryTest::MaxIndex => write!(f, "DoeMaxIndex"),
            DoeDiscoveryTest::SupportedVersion => write!(f, "DoeSupportedDiscoveryVersion"),
            DoeDiscoveryTest::UnsupportedVersion => write!(f, "DoeUnsupportedDiscoveryVersion"),
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
        let (index, version) = match self {
            DoeDiscoveryTest::DoeDiscovery => (
                DataObjectType::DoeDiscovery as u8,
                DOE_DISCOVERY_VERSION_LEGACY,
            ),
            DoeDiscoveryTest::Spdm => (DataObjectType::DoeSpdm as u8, DOE_DISCOVERY_VERSION_LEGACY),
            DoeDiscoveryTest::SecureSpdm => (
                DataObjectType::DoeSecureSpdm as u8,
                DOE_DISCOVERY_VERSION_LEGACY,
            ),
            DoeDiscoveryTest::OutOfRangeIndex => (
                DataObjectType::DoeSecureSpdm as u8 + 1,
                DOE_DISCOVERY_VERSION_LEGACY,
            ),
            DoeDiscoveryTest::MaxIndex => (u8::MAX, DOE_DISCOVERY_VERSION_LEGACY),
            DoeDiscoveryTest::SupportedVersion => {
                (DataObjectType::DoeDiscovery as u8, DOE_DISCOVERY_VERSION_2)
            }
            DoeDiscoveryTest::UnsupportedVersion => (DataObjectType::DoeDiscovery as u8, 0x01),
        };
        DoeDiscoveryRequest::new_with_version(index, version)
            .as_bytes()
            .to_vec()
    }

    fn response_message(&self) -> Vec<u8> {
        match self {
            DoeDiscoveryTest::DoeDiscovery | DoeDiscoveryTest::SupportedVersion => {
                Self::build_response(
                    DataObjectType::DoeDiscovery,
                    DataObjectType::DoeDiscovery as u8 + 1,
                )
            }
            DoeDiscoveryTest::Spdm => {
                Self::build_response(DataObjectType::DoeSpdm, DataObjectType::DoeSpdm as u8 + 1)
            }
            DoeDiscoveryTest::SecureSpdm => Self::build_response(DataObjectType::DoeSecureSpdm, 0),
            DoeDiscoveryTest::OutOfRangeIndex
            | DoeDiscoveryTest::MaxIndex
            | DoeDiscoveryTest::UnsupportedVersion => Self::build_unsupported_response(),
        }
    }

    fn build_response(obj_protocol: DataObjectType, next_index: u8) -> Vec<u8> {
        DoeDiscoveryResponse::new(obj_protocol as u8, next_index)
            .as_bytes()
            .to_vec()
    }

    /// Expected response for an out-of-range index or an unsupported DOE
    /// Discovery Version: Vendor ID FFFFh with a zero protocol and next index.
    fn build_unsupported_response() -> Vec<u8> {
        DoeDiscoveryResponse::unsupported().as_bytes().to_vec()
    }
}

/// Number of polling attempts before a test case is declared failed for not
/// receiving a response. Bounding this keeps a non-responsive firmware from
/// hanging the whole test binary until the global timeout fires.
const MAX_RECEIVE_ATTEMPTS: u32 = 60;

struct Test {
    name: String,
    req_msg: Vec<u8>,
    resp_msg: Vec<u8>,
    test_state: DoeTestState,
    recv_attempts: u32,
    passed: bool,
}

impl Test {
    fn new(name: &str, req_msg: Vec<u8>, resp_msg: Vec<u8>) -> Self {
        Test {
            name: name.to_string(),
            req_msg,
            resp_msg,
            test_state: DoeTestState::Start,
            recv_attempts: 0,
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
        self.recv_attempts = 0;

        while caliptra_mcu_testing_common::is_emulator_running() {
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
                        self.recv_attempts += 1;
                        if self.recv_attempts >= MAX_RECEIVE_ATTEMPTS {
                            println!(
                                "DOE_DISCOVERY_TEST: No response received for {}, expected: {:?}",
                                self.name, self.resp_msg
                            );
                            self.passed = false;
                            self.test_state = DoeTestState::Finish;
                        } else {
                            // Stay in ReceiveData state and yield for a bit
                            sleep_emulator_ticks(100_000);
                        }
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
