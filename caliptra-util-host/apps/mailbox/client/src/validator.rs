// Licensed under the Apache-2.0 license

use crate::{MailboxClient, UdpTransportDriver};
use anyhow::Result;
use std::net::SocketAddr;

/// Hardcoded expected device responses for validation
pub const DEFAULT_EXPECTED_DEVICE_ID: u16 = 0x1234;
pub const DEFAULT_EXPECTED_VENDOR_ID: u16 = 0x5678;
pub const DEFAULT_EXPECTED_SUBSYSTEM_VENDOR_ID: u16 = 0x9ABC;
pub const DEFAULT_EXPECTED_SUBSYSTEM_ID: u16 = 0xDEF0;

/// Validation test results
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub test_name: String,
    pub passed: bool,
    pub error_message: Option<String>,
}

/// Caliptra Mailbox Validator
///
/// Provides validation testing for Caliptra device communication
pub struct Validator {
    server_addr: SocketAddr,
    verbose: bool,
    expected_device_id: Option<u16>,
    expected_vendor_id: Option<u16>,
}

impl Validator {
    /// Create a new validator instance
    pub fn new(server_addr: SocketAddr) -> Self {
        Self {
            server_addr,
            verbose: false,
            expected_device_id: Some(DEFAULT_EXPECTED_DEVICE_ID),
            expected_vendor_id: Some(DEFAULT_EXPECTED_VENDOR_ID),
        }
    }

    /// Create a validator with custom expected values
    pub fn with_expected_values(
        server_addr: SocketAddr,
        expected_device_id: Option<u16>,
        expected_vendor_id: Option<u16>,
    ) -> Self {
        Self {
            server_addr,
            verbose: false,
            expected_device_id,
            expected_vendor_id,
        }
    }

    /// Enable or disable verbose logging
    pub fn set_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Start the validation process and return results
    pub fn start(&self) -> Result<Vec<ValidationResult>> {
        if self.verbose {
            println!("Caliptra Mailbox Validator starting...");
            println!("Server: {}", self.server_addr);
        }

        // Create UDP transport driver and connect
        let mut udp_driver = UdpTransportDriver::new(self.server_addr);
        use caliptra_util_host_transport::MailboxDriver;
        udp_driver
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect UDP driver: {:?}", e))?;

        let mut client = MailboxClient::with_udp_driver(&mut udp_driver);
        let mut results = Vec::new();

        // Run GetDeviceId validation
        let device_id_result = self.validate_get_device_id(&mut client);
        results.push(device_id_result);

        // Future tests can be added here

        if self.verbose {
            self.print_summary(&results);
        }

        Ok(results)
    }
}

impl Validator {
    /// Validate GetDeviceId command
    fn validate_get_device_id(&self, client: &mut MailboxClient) -> ValidationResult {
        let test_name = "GetDeviceId".to_string();

        if self.verbose {
            println!("\n=== Validating GetDeviceId Command ===");
        }

        match client.validate_device_id(self.expected_device_id, self.expected_vendor_id) {
            Ok(_) => {
                println!("✓ GetDeviceId validation PASSED");
                ValidationResult {
                    test_name,
                    passed: true,
                    error_message: None,
                }
            }
            Err(e) => {
                eprintln!("✗ GetDeviceId validation FAILED: {}", e);
                ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(e.to_string()),
                }
            }
        }
    }

    /// Print validation summary
    fn print_summary(&self, results: &[ValidationResult]) {
        let passed = results.iter().filter(|r| r.passed).count();
        let failed = results.len() - passed;

        println!("\n=== Validation Summary ===");
        println!("Total tests: {}", results.len());
        println!("Passed: {}", passed);
        println!("Failed: {}", failed);

        if failed > 0 {
            println!("\n❌ Some validations failed!");
            for result in results {
                if !result.passed {
                    println!(
                        "  ✗ {}: {}",
                        result.test_name,
                        result.error_message.as_deref().unwrap_or("Unknown error")
                    );
                }
            }
        } else {
            println!("\n✅ All validations passed!");
        }
    }
}

/// Convenience function to run basic validation with default values
pub fn run_basic_validation(server_addr: SocketAddr) -> Result<bool> {
    let validator = Validator::new(server_addr);
    let results = validator.start()?;
    Ok(results.iter().all(|r| r.passed))
}

/// Convenience function to run validation with verbose output
pub fn run_verbose_validation(server_addr: SocketAddr) -> Result<bool> {
    let validator = Validator::new(server_addr).set_verbose(true);
    let results = validator.start()?;
    Ok(results.iter().all(|r| r.passed))
}
