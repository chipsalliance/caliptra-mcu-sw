//! Licensed under the Apache-2.0 license
//!
//! This module tests the MCU MBOX request/response interaction between the emulator and the device.
//! The emulator sends out different MCU MBOX requests and expects a corresponding response for those requests.

use crate::{wait_for_runtime_start, EMULATOR_RUNNING};
use emulator_mcu_mbox::mcu_mailbox_transport::{McuMailboxError, McuMailboxTransport};
use mcu_mbox_common::MailboxReqHeader;
#[allow(unused_imports)]
use mcu_mbox_common::{
    CommandId, FirmwareVersionReq, FirmwareVersionResp, MailboxRespHeader, McuMailboxReq,
    McuMailboxResp,
};
use std::process::exit;
use std::sync::atomic::Ordering;
use std::thread::sleep;

// Define the fake firmware version for Caliptra core, MCU RT, SoC to support testing
pub static CALIPTRA_CORE_VERSION: &str = "Caliptra_Core_v2.0.0";
pub static MCU_RT_VERSION: &str = "MCU_RT_v2.0.0";
pub static SOC_FW_VERSION: &str = "SoC_v1.0.1";

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

impl RequestResponseTest {
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
        } else if cfg!(feature = "test-mcu-mbox-usermode") {
            println!("Running test-mcu-mbox-usermode test");
            // Example test messages for usermode loopback
            self.push(
                0x03,
                vec![0x01, 0x02, 0x03, 0x04],
                vec![0x01, 0x02, 0x03, 0x04],
            );
            self.push(
                0x04,
                (0..128).map(|i| i as u8).collect(),
                (0..128).map(|i| i as u8).collect(),
            );
            // Example test payload that is not 4-byte aligned
            self.push(
                0x04,
                (0..125).map(|i| i as u8).collect(),
                (0..125).map(|i| i as u8).collect(),
            );
        } else if cfg!(feature = "test-mcu-mbox-cmds") {
            println!("Running test-mcu-mbox-cmds test");
            self.add_firmware_version_tests();
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
        for message_pair in &self.test_messages {
            self.mbox
                .execute(message_pair.cmd, &message_pair.request)
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
            // Fix: Add a delay between each test to avoid issuing another request while device is not finished send_done
            sleep(std::time::Duration::from_millis(500));
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
            println!("Emulator: MCU MBOX Test Thread Starting: ",);
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

    fn add_firmware_version_tests(&mut self) {
        // Add get_firmware_version command tests for index 0 to 2
        for idx in 0..=2 {
            let version_str = match idx {
                0 => CALIPTRA_CORE_VERSION,
                1 => MCU_RT_VERSION,
                2 => SOC_FW_VERSION,
                _ => unreachable!(),
            };

            let mut fw_version_req = McuMailboxReq::FirmwareVersion(FirmwareVersionReq {
                hdr: MailboxReqHeader::default(),
                index: idx,
            });
            let cmd = fw_version_req.cmd_code();
            fw_version_req.populate_chksum().unwrap();

            let mut fw_version_resp = McuMailboxResp::FirmwareVersion(FirmwareVersionResp {
                hdr: MailboxRespHeader::default(),
                len: version_str.len() as u32,
                version: {
                    let mut ver = [0u8; 32];
                    let bytes = version_str.as_bytes();
                    let len = bytes.len().min(ver.len());
                    ver[..len].copy_from_slice(&bytes[..len]);
                    ver
                },
            });
            fw_version_resp.populate_chksum().unwrap();

            self.push(
                cmd.0,
                fw_version_req.as_bytes().unwrap().to_vec(),
                fw_version_resp.as_bytes().unwrap().to_vec(),
            );
        }
    }
}
