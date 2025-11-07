// Licensed under the Apache-2.0 license

use std::net::SocketAddr;
use std::process::exit;
use std::sync::atomic::Ordering;
use std::thread::{self, sleep};

use caliptra_mailbox_client::Validator;
use caliptra_mailbox_server::ServerConfig;
use emulator_mcu_mbox::mcu_mailbox_transport::{McuMailboxError, McuMailboxTransport};
use mcu_testing_common::{wait_for_runtime_start, MCU_RUNNING};

const TEST_DEVICE_ID: u16 = 0x0010;
const TEST_VENDOR_ID: u16 = 0x1414;

pub fn run_caliptra_util_host_validator() {
    thread::spawn(|| {
        wait_for_runtime_start();
        if !MCU_RUNNING.load(Ordering::Relaxed) {
            exit(-1);
        }
        sleep(std::time::Duration::from_secs(5));
        let server_config = ServerConfig::default();
        let addr: SocketAddr = server_config.bind_addr;
        let validator =
            Validator::with_expected_values(addr, Some(TEST_DEVICE_ID), Some(TEST_VENDOR_ID));
        let result = validator.start().unwrap();
        for res in result {
            if res.passed {
                println!("Test '{}' PASSED", res.test_name);
            } else {
                println!("Test '{}' FAILED", res.test_name);
                std::process::exit(-1);
            }
        }
        MCU_RUNNING.store(false, Ordering::Relaxed);
    });
}

pub fn run_mbox_responder(mbox: McuMailboxTransport) {
    std::thread::spawn(move || {
        wait_for_runtime_start();
        if !MCU_RUNNING.load(Ordering::Relaxed) {
            exit(-1);
        }

        let server_config = ServerConfig::default();
        println!("Starting mailbox server on {}", server_config.bind_addr);

        let mut server = caliptra_mailbox_server::MailboxServer::new(server_config).unwrap();

        // Run server with a simple echo handler
        server
            .run(|raw_bytes| {
                if raw_bytes.len() < 4 {
                    println!("Command too short, echoing back");
                    // Just echo back short commands
                    return Ok(raw_bytes.to_vec());
                }
                let cmd_type =
                    u32::from_le_bytes([raw_bytes[0], raw_bytes[1], raw_bytes[2], raw_bytes[3]]);
                println!(
                    "Received command: {} bytes with id {}",
                    raw_bytes.len(),
                    cmd_type
                );

                mbox.execute(cmd_type, &raw_bytes[4..])
                    .map_err(|_| ())
                    .expect("Failed to execute mailbox command ");
                loop {
                    let response_int = mbox.get_execute_response();
                    match response_int {
                        Ok(resp) => {
                            return Ok(resp.data);
                        }
                        Err(e) => match e {
                            McuMailboxError::Busy => {
                                sleep(std::time::Duration::from_millis(100));
                            }
                            _ => {
                                println!("Unexpected error: {:?}", e);
                                exit(-1);
                            }
                        },
                    }
                }
            })
            .unwrap();
    });
}
