// Licensed under the Apache-2.0 license

use std::net::SocketAddr;
use std::process::{exit, Command};
use std::sync::atomic::Ordering;
use std::thread::{self, sleep};

use caliptra_mailbox_server::ServerConfig;
use caliptra_util_host_mailbox_test_config::{
    DeviceCapabilitiesConfig, DeviceConfig, DeviceInfoConfig, FirmwareVersionConfig, NetworkConfig,
    ServerConfig as ConfigServerConfig, TestConfig, ValidationConfig,
};
use emulator_mcu_mbox::mcu_mailbox_transport::{McuMailboxError, McuMailboxTransport};
use mcu_testing_common::{wait_for_runtime_start, MCU_RUNNING};
use tempfile::NamedTempFile;

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

        println!("Running validator using cargo xtask validator");

        // Create temporary config file with test parameters using TestConfig struct
        let test_config = TestConfig {
            device: DeviceConfig {
                device_id: TEST_DEVICE_ID,
                vendor_id: TEST_VENDOR_ID,
                subsystem_vendor_id: 0x0001,
                subsystem_id: 0x0002,
            },
            network: NetworkConfig {
                default_server_address: format!("{}:{}", addr.ip(), addr.port()),
            },
            validation: ValidationConfig {
                timeout_seconds: 30,
                retry_count: 3,
                verbose_output: false,
            },
            server: ConfigServerConfig {
                bind_address: format!("{}:{}", addr.ip(), addr.port()),
                max_connections: 10,
            },
            device_capabilities: Some(DeviceCapabilitiesConfig {
                capabilities: 0x04030201,
                max_cert_size: 134678021,
                max_csr_size: 202050057,
                device_lifecycle: 269422093,
                fips_status: 0x00000000,
            }),
            firmware_version: Some(FirmwareVersionConfig {
                rom_version: "0.0.0.0".to_string(),
                runtime_version: "0.0.0.0".to_string(),
                fips_status: 0x00000000,
                rom_firmware_id: 0,
                runtime_firmware_id: 1,
            }),
            device_info: Some(DeviceInfoConfig {
                info_index: 0,
                expected_info: String::from_utf8_lossy(&[
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
                    0xDD, 0xEE, 0xFF,
                ])
                .to_string(),
                min_info_length: 10,
                max_info_length: 64,
                fips_status: 0x00000000,
            }),
        };

        let temp_file = NamedTempFile::new().expect("Failed to create temporary file");

        test_config
            .save_to_file(temp_file.path())
            .expect("Failed to write config to temporary file");

        println!("Created temporary config file at: {:?}", temp_file.path());
        println!(
            "Config contains: device_id=0x{:04X}, vendor_id=0x{:04X}",
            TEST_DEVICE_ID, TEST_VENDOR_ID
        );

        // Run the validator using cargo xtask validator command with temporary config
        let output = Command::new("cargo")
            .arg("xtask")
            .arg("validator")
            .arg("--server")
            .arg(format!("{}:{}", addr.ip(), addr.port()))
            .arg("--config")
            .arg(temp_file.path())
            .current_dir("caliptra-util-host")
            .output()
            .expect("Failed to execute cargo xtask validator");

        // NamedTempFile will automatically clean up when dropped

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            println!("Validator output:\n{}", stdout);
            println!("✓ Caliptra util host validator PASSED");
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            println!("Validator failed:");
            println!("STDOUT:\n{}", stdout);
            println!("STDERR:\n{}", stderr);
            println!("✗ Caliptra util host validator FAILED");
            std::process::exit(-1);
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
