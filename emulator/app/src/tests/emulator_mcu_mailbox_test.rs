//! Licensed under the Apache-2.0 license
//!
//! This module tests the MCU MBOX request/response interaction between the emulator and the device.
//! The emulator sends out different MCU MBOX requests and expects a corresponding response for those requests.

use emulator_mcu_mbox::mcu_mailbox_transport::{
    McuMailboxError, McuMailboxResponse, McuMailboxTransport,
};
use mcu_testing_common::{wait_for_runtime_start, MCU_RUNNING};
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
    pub cmd: u32,
    pub request: Vec<u8>,
    // Expected Message Response to receive
    pub response: Vec<u8>,
}

/// Represents the current status of the MCU mailbox.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MbxCmdStatus {
    /// The command is still being processed.
    Busy,
    /// Data is available to be read.
    DataReady,
    /// The command completed successfully.
    Complete,
    /// The command failed.
    Failure,
}

impl RequestResponseTest {
    fn process_message(
        &mut self,
        cmd: u32,
        request: &[u8],
    ) -> Result<McuMailboxResponse, McuMailboxError> {
        self.mbox.execute(cmd, request)?;

        let timeout = std::time::Duration::from_secs(20);
        let start = std::time::Instant::now();
        loop {
            match self.mbox.get_execute_response() {
                Ok(resp) => return Ok(resp),
                Err(McuMailboxError::Busy) => {
                    if start.elapsed() > timeout {
                        // Print out timeout error and cmd id
                        println!(
                            "Timeout waiting for response for MCU mailbox cmd: {:#X}",
                            cmd
                        );
                        return Err(McuMailboxError::Timeout);
                    }
                    sleep(std::time::Duration::from_millis(100));
                }
                Err(e) => return Err(e),
            }
        }
    }

    pub fn new(mbox: McuMailboxTransport) -> Self {
        let test_messages: Vec<ExpectedMessagePair> = Vec::new();
        Self {
            test_messages,
            mbox,
        }
    }

    fn prep_test_messages(&mut self) {
        if cfg!(feature = "test-mcu-mbox-soc-requester-loopback") {
            println!("Running test-mcu-mbox-soc-requester-loopback test");
            // Example test messages for SOC requester loopback
            self.push(
                0x01,
                vec![0x01, 0x02, 0x03, 0x04],
                vec![0x01, 0x02, 0x03, 0x04],
            );
            self.push(
                0x02,
                (0..64).map(|i| i as u8).collect(),
                (0..64).map(|i| i as u8).collect(),
            );
        }
    }

    fn push(&mut self, cmd: u32, req_payload: Vec<u8>, resp_payload: Vec<u8>) {
        self.test_messages.push(ExpectedMessagePair {
            cmd,
            request: req_payload,
            response: resp_payload,
        });
    }

    #[allow(clippy::result_unit_err)]
    fn test_send_receive(&mut self) -> Result<(), ()> {
        self.prep_test_messages();
        let test_messages = self.test_messages.clone();
        for message_pair in &test_messages {
            let actual_response = self
                .process_message(message_pair.cmd, &message_pair.request)
                .map_err(|_| ())?;
            assert_eq!(actual_response.data, message_pair.response);
        }
        Ok(())
    }

    pub fn run(&self) {
        let transport_clone = self.mbox.clone();
        std::thread::spawn(move || {
            wait_for_runtime_start();
            if !MCU_RUNNING.load(Ordering::Relaxed) {
                exit(-1);
            }
            sleep(std::time::Duration::from_secs(5));
            println!("Emulator: MCU MBOX Test Thread Starting:");
            let mut test = RequestResponseTest::new(transport_clone);

            if test.test_send_receive().is_err() {
                println!("Failed");
                exit(-1);
            } else {
                println!("Sent {} test messages", test.test_messages.len());
                println!("Passed");
            }
            MCU_RUNNING.store(false, Ordering::Relaxed);
        });
    }
}
