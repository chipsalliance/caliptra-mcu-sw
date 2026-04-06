// Licensed under the Apache-2.0 license

//! Validator for MCTP VDM client — runs the 4 supported device-info commands
//! against a VDM server and reports pass/fail.

use crate::{DynamicI3cAddress, MctpVdmSocketDriver, TestConfig, VdmClient};
use anyhow::Result;
use std::net::SocketAddr;

/// Single validation result.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub test_name: String,
    pub passed: bool,
    pub error_message: Option<String>,
}

/// MCTP VDM Validator.
pub struct Validator {
    port: u16,
    target_addr: DynamicI3cAddress,
    verbose: bool,
    config: Option<TestConfig>,
}

impl Validator {
    /// Create a validator from a test configuration.
    pub fn new(config: &TestConfig) -> Result<Self> {
        let addr: SocketAddr = config.network.default_server_address.parse()?;
        Ok(Self {
            port: addr.port(),
            target_addr: DynamicI3cAddress::from(config.network.target_i3c_address),
            verbose: config.validation.verbose_output,
            config: Some(config.clone()),
        })
    }

    /// Toggle verbose output.
    pub fn set_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Run all validation tests and return results.
    pub fn start(&self) -> Result<Vec<ValidationResult>> {
        let mut driver = MctpVdmSocketDriver::new(self.port, self.target_addr);
        let mut client = VdmClient::new(&mut driver);
        client.connect()?;

        let results = vec![
            self.validate_get_device_id(&mut client),
            self.validate_get_device_capabilities(&mut client),
            self.validate_get_firmware_version(&mut client),
            self.validate_get_device_info(&mut client),
        ];

        client.disconnect().ok();

        self.print_summary(&results);
        Ok(results)
    }

    // ------------------------------------------------------------------
    // Individual validators
    // ------------------------------------------------------------------

    fn validate_get_device_id(&self, client: &mut VdmClient) -> ValidationResult {
        let test_name = "GetDeviceId".to_string();
        match client.get_device_id() {
            Ok(resp) => {
                if self.verbose {
                    println!(
                        "  DeviceId: vendor=0x{:04X} device=0x{:04X} sub_vendor=0x{:04X} sub=0x{:04X}",
                        resp.vendor_id, resp.device_id,
                        resp.subsystem_vendor_id, resp.subsystem_id,
                    );
                }
                // If config has expected values, compare them.
                if let Some(cfg) = &self.config {
                    if resp.vendor_id != cfg.device.vendor_id
                        || resp.device_id != cfg.device.device_id
                    {
                        return ValidationResult {
                            test_name,
                            passed: false,
                            error_message: Some("Device ID mismatch".into()),
                        };
                    }
                }
                ValidationResult {
                    test_name,
                    passed: true,
                    error_message: None,
                }
            }
            Err(e) => ValidationResult {
                test_name,
                passed: false,
                error_message: Some(format!("{e:#}")),
            },
        }
    }

    fn validate_get_device_capabilities(&self, client: &mut VdmClient) -> ValidationResult {
        let test_name = "GetDeviceCapabilities".to_string();
        match client.get_device_capabilities() {
            Ok(resp) => {
                if self.verbose {
                    println!(
                        "  Capabilities: caps=0x{:08X} lifecycle={}",
                        resp.capabilities, resp.device_lifecycle,
                    );
                }
                ValidationResult {
                    test_name,
                    passed: true,
                    error_message: None,
                }
            }
            Err(e) => ValidationResult {
                test_name,
                passed: false,
                error_message: Some(format!("{e:#}")),
            },
        }
    }

    fn validate_get_firmware_version(&self, client: &mut VdmClient) -> ValidationResult {
        let test_name = "GetFirmwareVersion".to_string();
        match client.get_firmware_version(0) {
            Ok(resp) => {
                if self.verbose {
                    println!(
                        "  FirmwareVersion: {}.{}.{}.{}",
                        resp.version[0], resp.version[1], resp.version[2], resp.version[3],
                    );
                }
                ValidationResult {
                    test_name,
                    passed: true,
                    error_message: None,
                }
            }
            Err(e) => ValidationResult {
                test_name,
                passed: false,
                error_message: Some(format!("{e:#}")),
            },
        }
    }

    fn validate_get_device_info(&self, client: &mut VdmClient) -> ValidationResult {
        let test_name = "GetDeviceInfo".to_string();
        match client.get_device_info() {
            Ok(resp) => {
                if self.verbose {
                    println!("  DeviceInfo: {} bytes", resp.info_length);
                }
                ValidationResult {
                    test_name,
                    passed: true,
                    error_message: None,
                }
            }
            Err(e) => ValidationResult {
                test_name,
                passed: false,
                error_message: Some(format!("{e:#}")),
            },
        }
    }

    // ------------------------------------------------------------------

    fn print_summary(&self, results: &[ValidationResult]) {
        println!("\nValidation Summary");
        println!("==================");
        for r in results {
            let status = if r.passed { "PASS" } else { "FAIL" };
            print!("  [{status}] {}", r.test_name);
            if let Some(msg) = &r.error_message {
                print!(" — {msg}");
            }
            println!();
        }
        let passed = results.iter().filter(|r| r.passed).count();
        println!("\n  {passed}/{} tests passed", results.len());
    }
}
