//! Licensed under the Apache-2.0 license
//!
//! This module tests the MCU MBOX request/response interaction between the emulator and the device.
//! The emulator sends out different MCU MBOX requests and expects a corresponding response for those requests.

use emulator_mcu_mbox::mcu_mailbox_transport::{McuMailboxError, McuMailboxTransport};
use mcu_mbox_common::messages::{
    DeviceCapsReq, DeviceCapsResp, DeviceIdReq, DeviceIdResp, DeviceInfoReq, DeviceInfoResp,
    FirmwareVersionReq, FirmwareVersionResp, MailboxReqHeader, MailboxRespHeader,
    MailboxRespHeaderVarSize, McuMailboxReq, McuMailboxResp, DEVICE_CAPS_SIZE,
};
use mcu_testing_common::{wait_for_runtime_start, MCU_RUNNING};
use std::process::exit;
use std::sync::atomic::Ordering;
use std::thread::sleep;
use zerocopy::IntoBytes;

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
            self.add_usermode_loopback_tests();
        } else if cfg!(feature = "test-mcu-mbox-cmds") {
            println!("Running test-mcu-mbox-cmds test");
            self.add_basic_cmds_tests();
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
            println!("Emulator: MCU MBOX Test Thread Starting: ",);
            let mut test = RequestResponseTest::new(transport_clone);
            if test.test_send_receive().is_err() {
                println!("Failed");
                exit(-1);
            } else {
                // print out how many test messages were sent
                println!("Sent {} test messages", test.test_messages.len());
                println!("Passed");
            }
            MCU_RUNNING.store(false, Ordering::Relaxed);
        });
    }

    fn add_usermode_loopback_tests(&mut self) {
        // Construct 256 test messages with payload lengths from 1 to 256
        for len in 1..=256 {
            let payload: Vec<u8> = (0..len).map(|j| (j % 256) as u8).collect();
            let cmd = if len % 2 == 0 { 0x03 } else { 0x04 };
            self.push(cmd, payload.clone(), payload);
        }
        println!(
            "Added {} usermode loopback test messages",
            self.test_messages.len()
        );
    }

    fn add_basic_cmds_tests(&mut self) {
        // Add firmware version test messages
        for idx in 0..=2 {
            let version_str = match idx {
                0 => mcu_mbox_common::config::TEST_FIRMWARE_VERSIONS[0],
                1 => mcu_mbox_common::config::TEST_FIRMWARE_VERSIONS[1],
                2 => mcu_mbox_common::config::TEST_FIRMWARE_VERSIONS[2],
                _ => unreachable!(),
            };

            let mut fw_version_req = McuMailboxReq::FirmwareVersion(FirmwareVersionReq {
                hdr: MailboxReqHeader::default(),
                index: idx,
            });
            let cmd = fw_version_req.cmd_code();
            fw_version_req.populate_chksum().unwrap();

            let mut fw_version_resp = McuMailboxResp::FirmwareVersion(FirmwareVersionResp {
                hdr: MailboxRespHeaderVarSize {
                    data_len: version_str.len() as u32,
                    ..Default::default()
                },
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

        // Add device cap test message
        let mut device_caps_req = McuMailboxReq::DeviceCaps(DeviceCapsReq::default());
        let cmd = device_caps_req.cmd_code();
        device_caps_req.populate_chksum().unwrap();

        let test_capabilities = &mcu_mbox_common::config::TEST_DEVICE_CAPABILITIES;
        let mut device_caps_resp = McuMailboxResp::DeviceCaps(DeviceCapsResp {
            hdr: MailboxRespHeader::default(),
            caps: {
                let mut c = [0u8; DEVICE_CAPS_SIZE];
                c[..test_capabilities.as_bytes().len()]
                    .copy_from_slice(test_capabilities.as_bytes());
                c
            },
        });
        device_caps_resp.populate_chksum().unwrap();

        self.push(
            cmd.0,
            device_caps_req.as_bytes().unwrap().to_vec(),
            device_caps_resp.as_bytes().unwrap().to_vec(),
        );

        // Add device ID test message
        let mut device_id_req = McuMailboxReq::DeviceId(DeviceIdReq {
            hdr: MailboxReqHeader::default(),
        });
        let cmd = device_id_req.cmd_code();
        device_id_req.populate_chksum().unwrap();

        let test_device_id = &mcu_mbox_common::config::TEST_DEVICE_ID;
        let mut device_id_resp = McuMailboxResp::DeviceId(DeviceIdResp {
            hdr: MailboxRespHeader::default(),
            vendor_id: test_device_id.vendor_id,
            device_id: test_device_id.device_id,
            subsystem_vendor_id: test_device_id.subsystem_vendor_id,
            subsystem_id: test_device_id.subsystem_id,
        });
        device_id_resp.populate_chksum().unwrap();

        self.push(
            cmd.0,
            device_id_req.as_bytes().unwrap().to_vec(),
            device_id_resp.as_bytes().unwrap().to_vec(),
        );

        // Add device info test message
        let mut device_info_req = McuMailboxReq::DeviceInfo(DeviceInfoReq {
            hdr: MailboxReqHeader::default(),
            index: 0, // Only index 0 (UID) is supported in this test
        });
        let cmd = device_info_req.cmd_code();
        device_info_req.populate_chksum().unwrap();

        let test_uid = &mcu_mbox_common::config::TEST_UID;
        let mut device_info_resp = McuMailboxResp::DeviceInfo(DeviceInfoResp {
            hdr: MailboxRespHeaderVarSize {
                data_len: test_uid.len() as u32,
                ..Default::default()
            },
            data: {
                let mut u = [0u8; 32];
                let len = test_uid.len().min(u.len());
                u[..len].copy_from_slice(&test_uid[..len]);
                u
            },
        });
        device_info_resp.populate_chksum().unwrap();

        self.push(
            cmd.0,
            device_info_req.as_bytes().unwrap().to_vec(),
            device_info_resp.as_bytes().unwrap().to_vec(),
        );
    }
}
