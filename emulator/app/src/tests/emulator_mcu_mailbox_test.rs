//! Licensed under the Apache-2.0 license
//!
//! This module tests the MCU MBOX request/response interaction between the emulator and the device.
//! The emulator sends out different MCU MBOX requests and expects a corresponding response for those requests.

use crate::{wait_for_runtime_start, EMULATOR_RUNNING};
use emulator_mcu_mbox::mcu_mailbox_transport::{McuMailboxError, McuMailboxTransport};
use std::process::exit;
use std::sync::atomic::Ordering;
use std::thread::sleep;

#[derive(Clone)]
pub struct RequestResponseTest {
    test_messages: Vec<ExpectedMessagePair>,
    mbox: McuMailboxTransport,
}

#[derive(Clone)]
pub struct ExpectedMessagePair {
    // Important! Ensure that data are 4-byte aligned
    // Message Sent
    pub request: Vec<u8>,
    // Expected Message Response to receive
    pub response: Vec<u8>,
}

impl RequestResponseTest {
    pub fn new(mbox: McuMailboxTransport) -> Self {
        let mut test_messages: Vec<ExpectedMessagePair> = Vec::new();

        test_messages.push(ExpectedMessagePair {
            request: vec![0x01, 0x02, 0x03, 0x04],
            response: vec![0x01, 0x02, 0x03, 0x04],
        });

        test_messages.push(ExpectedMessagePair {
            request: {
                let mut req = Vec::new();
                for i in 0..64 {
                    req.push(i as u8);
                }
                req
            },
            response: {
                let mut req = Vec::new();
                for i in 0..64 {
                    req.push(i as u8);
                }
                req
            },
        });

        Self {
            test_messages,
            mbox,
        }
    }

    #[allow(clippy::result_unit_err)]
    fn test_send_receive(&mut self) -> Result<(), ()> {
        let mut cmd = 0xaaaa;
        for message_pair in &self.test_messages {
            self.mbox
                .execute(cmd, &message_pair.request)
                .map_err(|_| ())?;
            loop {
                let response_int = self.mbox.get_execute_response();
                match response_int {
                    Ok(resp) => {
                        assert_eq!(resp.data, message_pair.response);
                        break;
                    }
                    Err(e) => match e {
                        McuMailboxError::Busy => {
                            sleep(std::time::Duration::from_millis(100));
                        }
                        _ => {
                            println!("Unexpected error: {:?}", e);
                            return Err(());
                        }
                    },
                }
            }
            cmd += 0xa;
        }
        Ok(())
    }

    pub fn run(&self) {
        let transport_clone = self.mbox.clone();
        std::thread::spawn(move || {
            wait_for_runtime_start();
            if !EMULATOR_RUNNING.load(Ordering::Relaxed) {
                exit(-1);
            }
            sleep(std::time::Duration::from_secs(5));
            print!("Emulator: Running MCU MBOX Loopback Test: ",);
            let mut test = RequestResponseTest::new(transport_clone);
            if test.test_send_receive().is_err() {
                println!("Failed");
                exit(-1);
            } else {
                println!("Passed");
            }
            EMULATOR_RUNNING.store(false, Ordering::Relaxed);
        });
    }
}
