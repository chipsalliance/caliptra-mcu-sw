// Licensed under the Apache-2.0 license

use crate::{MailboxClient, TestConfig, UdpTransportDriver};
use anyhow::Result;
use std::net::SocketAddr;

/// Hardcoded fallback expected device responses for validation (when config is not available)
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
    config: Option<TestConfig>,
}

impl Validator {
    /// Create a new validator instance with default values
    pub fn new(server_addr: SocketAddr) -> Self {
        Self {
            server_addr,
            verbose: false,
            expected_device_id: Some(DEFAULT_EXPECTED_DEVICE_ID),
            expected_vendor_id: Some(DEFAULT_EXPECTED_VENDOR_ID),
            config: None,
        }
    }

    /// Create a validator from a configuration file
    pub fn from_config(config: &TestConfig) -> Result<Self> {
        let server_addr: SocketAddr = config
            .network
            .default_server_address
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid server address in config: {}", e))?;

        Ok(Self {
            server_addr,
            verbose: config.validation.verbose_output,
            expected_device_id: Some(config.device.device_id),
            expected_vendor_id: Some(config.device.vendor_id),
            config: Some(config.clone()),
        })
    }

    /// Create a validator from the default configuration file
    pub fn from_default_config() -> Result<Self> {
        let config = TestConfig::load_default()?;
        Self::from_config(&config)
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
            config: None,
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

        // Run GetDeviceInfo validation
        let device_info_result = self.validate_get_device_info(&mut client);
        results.push(device_info_result);

        // Run GetDeviceCapabilities validation
        let capabilities_result = self.validate_get_device_capabilities(&mut client);
        results.push(capabilities_result);

        // Run GetFirmwareVersion validation
        let fw_version_result = self.validate_get_firmware_version(&mut client);
        results.push(fw_version_result);

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

    /// Validate GetDeviceInfo command
    fn validate_get_device_info(&self, client: &mut MailboxClient) -> ValidationResult {
        let test_name = "GetDeviceInfo".to_string();

        if self.verbose {
            println!("\n=== Validating GetDeviceInfo Command ===");
        }

        match client.get_device_info() {
            Ok(response) => {
                // Validate against config if available
                if let Some(ref config) = self.config {
                    if let Some(ref info_config) = config.device_info {
                        // Extract actual info from response (up to info_length bytes)
                        let actual_length = std::cmp::min(response.info_length as usize, response.info_data.len());
                        let actual_info = String::from_utf8_lossy(&response.info_data[..actual_length]);
                        
                        if actual_info.trim() != info_config.expected_info.trim() {
                            let error_msg = format!(
                                "Device info mismatch: expected '{}', got '{}'",
                                info_config.expected_info, actual_info.trim()
                            );
                            eprintln!("✗ GetDeviceInfo validation FAILED: {}", error_msg);
                            return ValidationResult {
                                test_name,
                                passed: false,
                                error_message: Some(error_msg),
                            };
                        }
                        
                        if self.verbose {
                            println!("  Device info: '{}' ✓", actual_info.trim());
                            println!("  Info length: {} bytes ✓", response.info_length);
                        }
                    }
                }

                println!("✓ GetDeviceInfo validation PASSED");
                ValidationResult {
                    test_name,
                    passed: true,
                    error_message: None,
                }
            }
            Err(e) => {
                eprintln!("✗ GetDeviceInfo validation FAILED: {}", e);
                ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(e.to_string()),
                }
            }
        }
    }

    /// Validate GetDeviceCapabilities command
    fn validate_get_device_capabilities(&self, client: &mut MailboxClient) -> ValidationResult {
        let test_name = "GetDeviceCapabilities".to_string();

        if self.verbose {
            println!("\n=== Validating GetDeviceCapabilities Command ===");
        }

        match client.get_device_capabilities() {
            Ok(response) => {
                // Get expected capabilities from config if available
                if let Some(ref config) = self.config {
                    if let Some(ref capabilities_config) = config.device_capabilities {
                        // Validate the response matches expected values
                        if response.capabilities != capabilities_config.capabilities {
                            let error_msg = format!(
                                "Capabilities mismatch: expected 0x{:08X}, got 0x{:08X}",
                                capabilities_config.capabilities, response.capabilities
                            );
                            eprintln!("✗ GetDeviceCapabilities validation FAILED: {}", error_msg);
                            return ValidationResult {
                                test_name,
                                passed: false,
                                error_message: Some(error_msg),
                            };
                        }
                        
                        if self.verbose {
                            println!("  Capabilities: 0x{:08X} ✓", response.capabilities);
                        }
                    }
                }

                println!("✓ GetDeviceCapabilities validation PASSED");
                ValidationResult {
                    test_name,
                    passed: true,
                    error_message: None,
                }
            }
            Err(e) => {
                eprintln!("✗ GetDeviceCapabilities validation FAILED: {}", e);
                ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(e.to_string()),
                }
            }
        }
    }

    /// Validate GetFirmwareVersion command
    fn validate_get_firmware_version(&self, client: &mut MailboxClient) -> ValidationResult {
        let test_name = "GetFirmwareVersion".to_string();

        if self.verbose {
            println!("\n=== Validating GetFirmwareVersion Command ===");
        }

        // Test both ROM (0) and Runtime (1) firmware versions
        let mut errors = Vec::new();
        
        for (fw_name, fw_id) in [("ROM", 0u32), ("Runtime", 1u32)] {
            if self.verbose {
                println!("Testing {} firmware version (id={})...", fw_name, fw_id);
            }
            
            match client.get_firmware_version(fw_id) {
                Ok(response) => {
                    // Validate against config if available
                    if let Some(ref config) = self.config {
                        if let Some(ref fw_config) = config.firmware_version {
                            let expected_version = if fw_id == 0 {
                                &fw_config.rom_version
                            } else {
                                &fw_config.runtime_version
                            };
                            
                            // Convert version array to string format: "major.minor.patch.build"
                            let response_version = format!(
                                "{}.{}.{}.{}",
                                response.version[0], response.version[1], 
                                response.version[2], response.version[3]
                            );
                            
                            if response_version != *expected_version {
                                let error_msg = format!(
                                    "{} version mismatch: expected '{}', got '{}'",
                                    fw_name, expected_version, response_version
                                );
                                eprintln!("✗ {}", error_msg);
                                errors.push(error_msg);
                                continue;
                            }
                            
                            if self.verbose {
                                println!("  {} version: '{}' ✓", fw_name, response_version);
                            }
                        }
                    }
                    
                    println!("✓ {} firmware version validation PASSED", fw_name);
                }
                Err(e) => {
                    let error_msg = format!("{} firmware version failed: {}", fw_name, e);
                    eprintln!("✗ {}", error_msg);
                    errors.push(error_msg);
                }
            }
        }

        if errors.is_empty() {
            ValidationResult {
                test_name,
                passed: true,
                error_message: None,
            }
        } else {
            ValidationResult {
                test_name,
                passed: false,
                error_message: Some(errors.join("; ")),
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
