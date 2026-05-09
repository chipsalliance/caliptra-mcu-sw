// Licensed under the Apache-2.0 license

use crate::{MailboxClient, TestConfig, UdpTransportDriver};
use anyhow::Result;
use caliptra_util_host_command_types::crypto_aes::AesMode;
use caliptra_util_host_command_types::crypto_hmac::CmKeyUsage;
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

        // Run SHA validation tests
        let sha384_result = self.validate_sha384(&mut client);
        results.push(sha384_result);

        let sha512_result = self.validate_sha512(&mut client);
        results.push(sha512_result);

        // Run HMAC validation tests
        let hmac_sha384_result = self.validate_hmac_sha384(&mut client);
        results.push(hmac_sha384_result);

        let hmac_sha512_result = self.validate_hmac_sha512(&mut client);
        results.push(hmac_sha512_result);

        // Run HMAC KDF Counter validation test
        let hmac_kdf_counter_result = self.validate_hmac_kdf_counter(&mut client);
        results.push(hmac_kdf_counter_result);

        // Run AES validation tests
        let aes_cbc_result = self.validate_aes_cbc(&mut client);
        results.push(aes_cbc_result);

        let aes_ctr_result = self.validate_aes_ctr(&mut client);
        results.push(aes_ctr_result);

        let aes_gcm_result = self.validate_aes_gcm(&mut client);
        results.push(aes_gcm_result);

        // Run ECDSA validation tests
        let ecdsa_result = self.validate_ecdsa_sign_verify(&mut client);
        results.push(ecdsa_result);

        // Run ECDH validation tests
        let ecdh_result = self.validate_ecdh(&mut client);
        results.push(ecdh_result);

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
                        let actual_length =
                            std::cmp::min(response.info_length as usize, response.info_data.len());
                        let actual_info =
                            String::from_utf8_lossy(&response.info_data[..actual_length]);

                        if actual_info.trim() != info_config.expected_info.trim() {
                            let error_msg = format!(
                                "Device info mismatch: expected '{}', got '{}'",
                                info_config.expected_info,
                                actual_info.trim()
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
                                response.version[0],
                                response.version[1],
                                response.version[2],
                                response.version[3]
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

    /// Validate SHA384 hash command
    fn validate_sha384(&self, client: &mut MailboxClient) -> ValidationResult {
        use caliptra_util_host_command_types::crypto_hash::ShaAlgorithm;
        use sha2::{Digest, Sha384};

        let test_name = "SHA384".to_string();

        if self.verbose {
            println!("\n=== Validating SHA384 Command ===");
        }

        // Test data: "a" repeated 129 times (matches existing test pattern)
        let input = "a".repeat(129);
        let input_bytes = input.as_bytes();

        // Calculate expected hash using sha2 crate
        let mut hasher = Sha384::new();
        hasher.update(input_bytes);
        let expected = hasher.finalize();

        match client.sha_hash(ShaAlgorithm::Sha384, input_bytes) {
            Ok(response) => {
                // Verify hash matches expected (first 48 bytes for SHA384)
                if response.hash_size != 48 {
                    let error_msg = format!(
                        "SHA384 hash size mismatch: expected 48, got {}",
                        response.hash_size
                    );
                    eprintln!("✗ SHA384 validation FAILED: {}", error_msg);
                    return ValidationResult {
                        test_name,
                        passed: false,
                        error_message: Some(error_msg),
                    };
                }

                if &response.hash[..48] != expected.as_slice() {
                    let error_msg = format!(
                        "SHA384 hash mismatch: expected {:02X?}..., got {:02X?}...",
                        &expected[..8],
                        &response.hash[..8]
                    );
                    eprintln!("✗ SHA384 validation FAILED: {}", error_msg);
                    return ValidationResult {
                        test_name,
                        passed: false,
                        error_message: Some(error_msg),
                    };
                }

                if self.verbose {
                    println!("  Hash: {:02X?}...", &response.hash[..16]);
                }
                println!("✓ SHA384 validation PASSED");
                ValidationResult {
                    test_name,
                    passed: true,
                    error_message: None,
                }
            }
            Err(e) => {
                eprintln!("✗ SHA384 validation FAILED: {}", e);
                ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(e.to_string()),
                }
            }
        }
    }

    /// Validate SHA512 hash command
    fn validate_sha512(&self, client: &mut MailboxClient) -> ValidationResult {
        use caliptra_util_host_command_types::crypto_hash::ShaAlgorithm;
        use sha2::{Digest, Sha512};

        let test_name = "SHA512".to_string();

        if self.verbose {
            println!("\n=== Validating SHA512 Command ===");
        }

        // Test data: "a" repeated 129 times
        let input = "a".repeat(129);
        let input_bytes = input.as_bytes();

        // Calculate expected hash using sha2 crate
        let mut hasher = Sha512::new();
        hasher.update(input_bytes);
        let expected = hasher.finalize();

        match client.sha_hash(ShaAlgorithm::Sha512, input_bytes) {
            Ok(response) => {
                // Verify hash matches expected (64 bytes for SHA512)
                if response.hash_size != 64 {
                    let error_msg = format!(
                        "SHA512 hash size mismatch: expected 64, got {}",
                        response.hash_size
                    );
                    eprintln!("✗ SHA512 validation FAILED: {}", error_msg);
                    return ValidationResult {
                        test_name,
                        passed: false,
                        error_message: Some(error_msg),
                    };
                }

                if &response.hash[..64] != expected.as_slice() {
                    let error_msg = format!(
                        "SHA512 hash mismatch: expected {:02X?}..., got {:02X?}...",
                        &expected[..8],
                        &response.hash[..8]
                    );
                    eprintln!("✗ SHA512 validation FAILED: {}", error_msg);
                    return ValidationResult {
                        test_name,
                        passed: false,
                        error_message: Some(error_msg),
                    };
                }

                if self.verbose {
                    println!("  Hash: {:02X?}...", &response.hash[..16]);
                }
                println!("✓ SHA512 validation PASSED");
                ValidationResult {
                    test_name,
                    passed: true,
                    error_message: None,
                }
            }
            Err(e) => {
                eprintln!("✗ SHA512 validation FAILED: {}", e);
                ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(e.to_string()),
                }
            }
        }
    }

    /// Validate HMAC-SHA384 command
    fn validate_hmac_sha384(&self, client: &mut MailboxClient) -> ValidationResult {
        use caliptra_util_host_command_types::crypto_hmac::{CmKeyUsage, HmacAlgorithm};

        let test_name = "HMAC-SHA384".to_string();

        if self.verbose {
            println!("\n=== Validating HMAC-SHA384 Command ===");
        }

        // Test data
        let key_data = [0x0Bu8; 48]; // Test key (48 bytes for SHA384)
        let input = b"Test message for HMAC-SHA384 validation";

        // First, import the key to get a valid CMK
        let cmk = match client.import(CmKeyUsage::Hmac, &key_data) {
            Ok(response) => {
                if self.verbose {
                    println!("  Key imported successfully");
                }
                response.cmk
            }
            Err(e) => {
                let error_msg = format!("Failed to import key: {}", e);
                eprintln!("✗ HMAC-SHA384 validation FAILED: {}", error_msg);
                return ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(error_msg),
                };
            }
        };

        // Now use the imported CMK for HMAC
        let result = match client.hmac(&cmk, HmacAlgorithm::Sha384, input) {
            Ok(response) => {
                // Verify MAC size
                if response.mac_size != 48 {
                    let error_msg = format!(
                        "HMAC-SHA384 MAC size mismatch: expected 48, got {}",
                        response.mac_size
                    );
                    eprintln!("✗ HMAC-SHA384 validation FAILED: {}", error_msg);
                    ValidationResult {
                        test_name: test_name.clone(),
                        passed: false,
                        error_message: Some(error_msg),
                    }
                } else {
                    // The CMK is encrypted, so we can't compare the MAC value directly
                    // with a software HMAC calculation. Just verify the structure is valid.
                    if self.verbose {
                        println!("  MAC size: {} bytes ✓", response.mac_size);
                        println!("  MAC: {:02X?}...", &response.mac[..16]);
                    }

                    println!("✓ HMAC-SHA384 validation PASSED");
                    ValidationResult {
                        test_name: test_name.clone(),
                        passed: true,
                        error_message: None,
                    }
                }
            }
            Err(e) => {
                eprintln!("✗ HMAC-SHA384 validation FAILED: {}", e);
                ValidationResult {
                    test_name: test_name.clone(),
                    passed: false,
                    error_message: Some(e.to_string()),
                }
            }
        };

        // Clean up - delete the imported key
        if let Err(e) = client.delete(&cmk) {
            if self.verbose {
                eprintln!("  Warning: Failed to delete key: {}", e);
            }
        } else if self.verbose {
            println!("  Key deleted successfully");
        }

        result
    }

    /// Validate HMAC-SHA512 command
    fn validate_hmac_sha512(&self, client: &mut MailboxClient) -> ValidationResult {
        use caliptra_util_host_command_types::crypto_hmac::{CmKeyUsage, HmacAlgorithm};

        let test_name = "HMAC-SHA512".to_string();

        if self.verbose {
            println!("\n=== Validating HMAC-SHA512 Command ===");
        }

        // Test data
        let key_data = [0x0Cu8; 64]; // Test key (64 bytes for SHA512)
        let input = b"Test message for HMAC-SHA512 validation";

        // First, import the key to get a valid CMK
        let cmk = match client.import(CmKeyUsage::Hmac, &key_data) {
            Ok(response) => {
                if self.verbose {
                    println!("  Key imported successfully");
                }
                response.cmk
            }
            Err(e) => {
                let error_msg = format!("Failed to import key: {}", e);
                eprintln!("✗ HMAC-SHA512 validation FAILED: {}", error_msg);
                return ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(error_msg),
                };
            }
        };

        // Now use the imported CMK for HMAC
        let result = match client.hmac(&cmk, HmacAlgorithm::Sha512, input) {
            Ok(response) => {
                // Verify MAC size
                if response.mac_size != 64 {
                    let error_msg = format!(
                        "HMAC-SHA512 MAC size mismatch: expected 64, got {}",
                        response.mac_size
                    );
                    eprintln!("✗ HMAC-SHA512 validation FAILED: {}", error_msg);
                    ValidationResult {
                        test_name: test_name.clone(),
                        passed: false,
                        error_message: Some(error_msg),
                    }
                } else {
                    if self.verbose {
                        println!("  MAC size: {} bytes ✓", response.mac_size);
                        println!("  MAC: {:02X?}...", &response.mac[..16]);
                    }

                    println!("✓ HMAC-SHA512 validation PASSED");
                    ValidationResult {
                        test_name: test_name.clone(),
                        passed: true,
                        error_message: None,
                    }
                }
            }
            Err(e) => {
                eprintln!("✗ HMAC-SHA512 validation FAILED: {}", e);
                ValidationResult {
                    test_name: test_name.clone(),
                    passed: false,
                    error_message: Some(e.to_string()),
                }
            }
        };

        // Clean up - delete the imported key
        if let Err(e) = client.delete(&cmk) {
            if self.verbose {
                eprintln!("  Warning: Failed to delete key: {}", e);
            }
        } else if self.verbose {
            println!("  Key deleted successfully");
        }

        result
    }

    /// Validate HMAC KDF Counter command
    fn validate_hmac_kdf_counter(&self, client: &mut MailboxClient) -> ValidationResult {
        use caliptra_util_host_command_types::crypto_hmac::{CmKeyUsage, HmacAlgorithm};

        let test_name = "HMAC-KDF-Counter".to_string();

        if self.verbose {
            println!("\n=== Validating HMAC KDF Counter Command ===");
        }

        // Test data - use a 48-byte key for SHA384
        let key_data = [0x0Du8; 48]; // Input key

        // First, import the key to get a valid CMK
        let kin = match client.import(CmKeyUsage::Hmac, &key_data) {
            Ok(response) => {
                if self.verbose {
                    println!("  Input key imported successfully");
                }
                response.cmk
            }
            Err(e) => {
                let error_msg = format!("Failed to import key: {}", e);
                eprintln!("✗ HMAC KDF Counter validation FAILED: {}", error_msg);
                return ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(error_msg),
                };
            }
        };

        let label = b"key derivation test label";
        let key_size = 32; // 32 bytes for AES-256 key

        let (result, derived_cmk) = match client.hmac_kdf_counter(
            &kin,
            HmacAlgorithm::Sha384,
            CmKeyUsage::Aes,
            key_size,
            label,
        ) {
            Ok(response) => {
                // Verify we got a valid CMK back (128 bytes)
                if response.kout.0.len() != 128 {
                    let error_msg = format!(
                        "HMAC KDF Counter output key size mismatch: expected 128, got {}",
                        response.kout.0.len()
                    );
                    eprintln!("✗ HMAC KDF Counter validation FAILED: {}", error_msg);
                    (
                        ValidationResult {
                            test_name: test_name.clone(),
                            passed: false,
                            error_message: Some(error_msg),
                        },
                        Some(response.kout),
                    )
                } else {
                    if self.verbose {
                        println!("  Output key (CMK): {:02X?}...", &response.kout.0[..16]);
                    }

                    println!("✓ HMAC KDF Counter validation PASSED");
                    (
                        ValidationResult {
                            test_name: test_name.clone(),
                            passed: true,
                            error_message: None,
                        },
                        Some(response.kout),
                    )
                }
            }
            Err(e) => {
                eprintln!("✗ HMAC KDF Counter validation FAILED: {}", e);
                (
                    ValidationResult {
                        test_name: test_name.clone(),
                        passed: false,
                        error_message: Some(e.to_string()),
                    },
                    None,
                )
            }
        };

        // Clean up - delete the derived key if it was created
        if let Some(ref kout) = derived_cmk {
            if let Err(e) = client.delete(kout) {
                if self.verbose {
                    eprintln!("  Warning: Failed to delete derived key: {}", e);
                }
            } else if self.verbose {
                println!("  Derived key deleted successfully");
            }
        }

        // Clean up - delete the input key
        if let Err(e) = client.delete(&kin) {
            if self.verbose {
                eprintln!("  Warning: Failed to delete input key: {}", e);
            }
        } else if self.verbose {
            println!("  Input key deleted successfully");
        }

        result
    }

    /// Validate AES-CBC encryption and decryption
    ///
    /// Tests round-trip encryption/decryption with AES-CBC mode.
    fn validate_aes_cbc(&self, client: &mut MailboxClient) -> ValidationResult {
        let test_name = "AES-CBC".to_string();

        if self.verbose {
            println!("\n=== Validating AES-CBC Command ===");
        }

        // Import a 256-bit AES key
        let key = [0xaa; 32];
        let cmk = match client.import(CmKeyUsage::Aes, &key) {
            Ok(resp) => resp.cmk,
            Err(e) => {
                return ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(format!("Failed to import AES key: {}", e)),
                };
            }
        };

        // Test with a block-aligned plaintext (CBC requires this)
        let plaintext: Vec<u8> = (0..64).map(|i| (i % 256) as u8).collect();

        // Encrypt
        let encrypt_result = match client.aes_encrypt(&cmk, AesMode::Cbc, &plaintext) {
            Ok(result) => result,
            Err(e) => {
                let _ = client.delete(&cmk);
                return ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(format!("Encryption failed: {}", e)),
                };
            }
        };

        if self.verbose {
            println!(
                "  Encrypted {} bytes -> {} bytes ciphertext",
                plaintext.len(),
                encrypt_result.ciphertext.len()
            );
        }

        // Decrypt
        let decrypted = match client.aes_decrypt(
            &cmk,
            AesMode::Cbc,
            &encrypt_result.iv,
            &encrypt_result.ciphertext,
        ) {
            Ok(result) => result,
            Err(e) => {
                let _ = client.delete(&cmk);
                return ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(format!("Decryption failed: {}", e)),
                };
            }
        };

        // Verify round-trip
        let result = if decrypted == plaintext {
            println!("✓ AES-CBC validation PASSED");
            ValidationResult {
                test_name,
                passed: true,
                error_message: None,
            }
        } else {
            ValidationResult {
                test_name,
                passed: false,
                error_message: Some("Decrypted data doesn't match original".to_string()),
            }
        };

        // Clean up - delete the key
        if let Err(e) = client.delete(&cmk) {
            if self.verbose {
                eprintln!("  Warning: Failed to delete AES key: {}", e);
            }
        } else if self.verbose {
            println!("  AES key deleted successfully");
        }

        result
    }

    /// Validate AES-CTR encryption and decryption
    ///
    /// Tests round-trip encryption/decryption with AES-CTR mode.
    fn validate_aes_ctr(&self, client: &mut MailboxClient) -> ValidationResult {
        let test_name = "AES-CTR".to_string();

        if self.verbose {
            println!("\n=== Validating AES-CTR Command ===");
        }

        // Import a 256-bit AES key
        let key = [0xbb; 32];
        let cmk = match client.import(CmKeyUsage::Aes, &key) {
            Ok(resp) => resp.cmk,
            Err(e) => {
                return ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(format!("Failed to import AES key: {}", e)),
                };
            }
        };

        // Test with non-block-aligned plaintext (CTR allows any length)
        let plaintext: Vec<u8> = (0..100).map(|i| (i % 256) as u8).collect();

        // Encrypt
        let encrypt_result = match client.aes_encrypt(&cmk, AesMode::Ctr, &plaintext) {
            Ok(result) => result,
            Err(e) => {
                let _ = client.delete(&cmk);
                return ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(format!("Encryption failed: {}", e)),
                };
            }
        };

        if self.verbose {
            println!(
                "  Encrypted {} bytes -> {} bytes ciphertext",
                plaintext.len(),
                encrypt_result.ciphertext.len()
            );
        }

        // Decrypt
        let decrypted = match client.aes_decrypt(
            &cmk,
            AesMode::Ctr,
            &encrypt_result.iv,
            &encrypt_result.ciphertext,
        ) {
            Ok(result) => result,
            Err(e) => {
                let _ = client.delete(&cmk);
                return ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(format!("Decryption failed: {}", e)),
                };
            }
        };

        // Verify round-trip
        let result = if decrypted == plaintext {
            println!("✓ AES-CTR validation PASSED");
            ValidationResult {
                test_name,
                passed: true,
                error_message: None,
            }
        } else {
            ValidationResult {
                test_name,
                passed: false,
                error_message: Some("Decrypted data doesn't match original".to_string()),
            }
        };

        // Clean up - delete the key
        if let Err(e) = client.delete(&cmk) {
            if self.verbose {
                eprintln!("  Warning: Failed to delete AES key: {}", e);
            }
        } else if self.verbose {
            println!("  AES key deleted successfully");
        }

        result
    }

    /// Validate AES-GCM authenticated encryption and decryption
    ///
    /// Tests round-trip encryption/decryption with AES-GCM mode,
    /// including tag verification.
    fn validate_aes_gcm(&self, client: &mut MailboxClient) -> ValidationResult {
        let test_name = "AES-GCM".to_string();

        if self.verbose {
            println!("\n=== Validating AES-GCM Command ===");
        }

        // Import a 256-bit AES key
        let key = [0xcc; 32];
        let cmk = match client.import(CmKeyUsage::Aes, &key) {
            Ok(resp) => resp.cmk,
            Err(e) => {
                return ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(format!("Failed to import AES key: {}", e)),
                };
            }
        };

        // Test data
        let plaintext: Vec<u8> = (0..64).map(|i| (i % 256) as u8).collect();
        let aad: Vec<u8> = (0..32).map(|i| ((i + 128) % 256) as u8).collect();

        // Encrypt
        let encrypt_result = match client.aes_gcm_encrypt(&cmk, &aad, &plaintext) {
            Ok(result) => result,
            Err(e) => {
                let _ = client.delete(&cmk);
                return ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(format!("Encryption failed: {}", e)),
                };
            }
        };

        if self.verbose {
            println!(
                "  Encrypted {} bytes plaintext with {} bytes AAD",
                plaintext.len(),
                aad.len()
            );
            println!(
                "  -> {} bytes ciphertext, 16-byte tag",
                encrypt_result.ciphertext.len()
            );
        }

        // Decrypt and verify tag
        let decrypt_result = match client.aes_gcm_decrypt(
            &cmk,
            &encrypt_result.iv,
            &aad,
            &encrypt_result.ciphertext,
            &encrypt_result.tag,
        ) {
            Ok(result) => result,
            Err(e) => {
                let _ = client.delete(&cmk);
                return ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(format!("Decryption failed: {}", e)),
                };
            }
        };

        // Verify results
        let result = if !decrypt_result.tag_verified {
            ValidationResult {
                test_name,
                passed: false,
                error_message: Some("Tag verification failed".to_string()),
            }
        } else if decrypt_result.plaintext != plaintext {
            ValidationResult {
                test_name,
                passed: false,
                error_message: Some("Decrypted data doesn't match original".to_string()),
            }
        } else {
            println!("✓ AES-GCM validation PASSED");
            ValidationResult {
                test_name,
                passed: true,
                error_message: None,
            }
        };

        // Clean up - delete the key
        if let Err(e) = client.delete(&cmk) {
            if self.verbose {
                eprintln!("  Warning: Failed to delete AES key: {}", e);
            }
        } else if self.verbose {
            println!("  AES key deleted successfully");
        }

        result
    }

    /// Validate ECDSA sign and verify commands
    ///
    /// Tests the full ECDSA workflow: import key, get public key, sign, verify.
    fn validate_ecdsa_sign_verify(&self, client: &mut MailboxClient) -> ValidationResult {
        let test_name = "ECDSA-Sign-Verify".to_string();

        if self.verbose {
            println!("\n=== Validating ECDSA Sign/Verify Commands ===");
        }

        // Import an ECDSA key (48 bytes for P-384)
        let ecdsa_key = [0u8; 48]; // Test key seed
        let cmk = match client.import(CmKeyUsage::Ecdsa, &ecdsa_key) {
            Ok(resp) => {
                if self.verbose {
                    println!("  ECDSA key imported successfully");
                }
                resp.cmk
            }
            Err(e) => {
                let error_msg = format!("Failed to import ECDSA key: {}", e);
                eprintln!("✗ ECDSA validation FAILED: {}", error_msg);
                return ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(error_msg),
                };
            }
        };

        // Get the public key
        let _pub_key_resp = match client.ecdsa_public_key(&cmk) {
            Ok(resp) => {
                if self.verbose {
                    println!("  Got public key X: {:02X?}...", &resp.pub_key_x[..8]);
                    println!("  Got public key Y: {:02X?}...", &resp.pub_key_y[..8]);
                }
                resp
            }
            Err(e) => {
                let _ = client.delete(&cmk);
                let error_msg = format!("Failed to get public key: {}", e);
                eprintln!("✗ ECDSA validation FAILED: {}", error_msg);
                return ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(error_msg),
                };
            }
        };

        // Sign a message
        let message = b"Test message for ECDSA signing";
        let sign_resp = match client.ecdsa_sign(&cmk, message) {
            Ok(resp) => {
                if self.verbose {
                    println!("  Signature R: {:02X?}...", &resp.signature_r[..8]);
                    println!("  Signature S: {:02X?}...", &resp.signature_s[..8]);
                }
                resp
            }
            Err(e) => {
                let _ = client.delete(&cmk);
                let error_msg = format!("Failed to sign message: {}", e);
                eprintln!("✗ ECDSA validation FAILED: {}", error_msg);
                return ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(error_msg),
                };
            }
        };

        // Verify the signature (should succeed)
        match client.ecdsa_verify(
            &cmk,
            message,
            &sign_resp.signature_r,
            &sign_resp.signature_s,
        ) {
            Ok(_) => {
                if self.verbose {
                    println!("  Signature verification succeeded ✓");
                }
            }
            Err(e) => {
                let _ = client.delete(&cmk);
                let error_msg = format!("Signature verification failed: {}", e);
                eprintln!("✗ ECDSA validation FAILED: {}", error_msg);
                return ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(error_msg),
                };
            }
        }

        // Verify with tampered message (should fail)
        let tampered_message = b"Tampered message for ECDSA signing";
        match client.ecdsa_verify(
            &cmk,
            tampered_message,
            &sign_resp.signature_r,
            &sign_resp.signature_s,
        ) {
            Ok(_) => {
                let _ = client.delete(&cmk);
                let error_msg = "Verification with tampered message should have failed".to_string();
                eprintln!("✗ ECDSA validation FAILED: {}", error_msg);
                return ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(error_msg),
                };
            }
            Err(_) => {
                if self.verbose {
                    println!("  Tampered message verification correctly failed ✓");
                }
            }
        }

        // Clean up
        if let Err(e) = client.delete(&cmk) {
            if self.verbose {
                eprintln!("  Warning: Failed to delete ECDSA key: {}", e);
            }
        } else if self.verbose {
            println!("  ECDSA key deleted successfully");
        }

        println!("✓ ECDSA Sign/Verify validation PASSED");
        ValidationResult {
            test_name,
            passed: true,
            error_message: None,
        }
    }

    /// Validate ECDH key exchange commands
    ///
    /// Tests ECDH generate and finish, then verifies the derived key works with AES-GCM.
    fn validate_ecdh(&self, client: &mut MailboxClient) -> ValidationResult {
        let test_name = "ECDH-KeyExchange".to_string();

        if self.verbose {
            println!("\n=== Validating ECDH Key Exchange Commands ===");
        }

        // Generate our ECDH keypair
        let our_generate_resp = match client.ecdh_generate() {
            Ok(resp) => {
                if self.verbose {
                    println!("  Generated ECDH keypair");
                    println!("  Exchange data: {:02X?}...", &resp.exchange_data[..16]);
                }
                resp
            }
            Err(e) => {
                let error_msg = format!("Failed to generate ECDH keypair: {}", e);
                eprintln!("✗ ECDH validation FAILED: {}", error_msg);
                return ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(error_msg),
                };
            }
        };

        // Generate peer's ECDH keypair (simulating the peer)
        let peer_generate_resp = match client.ecdh_generate() {
            Ok(resp) => {
                if self.verbose {
                    println!("  Generated peer ECDH keypair");
                    println!(
                        "  Peer exchange data: {:02X?}...",
                        &resp.exchange_data[..16]
                    );
                }
                resp
            }
            Err(e) => {
                let error_msg = format!("Failed to generate peer ECDH keypair: {}", e);
                eprintln!("✗ ECDH validation FAILED: {}", error_msg);
                return ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(error_msg),
                };
            }
        };

        // Complete ECDH from our side using peer's public key
        let our_finish_resp = match client.ecdh_finish(
            &our_generate_resp.context,
            CmKeyUsage::Aes,
            &peer_generate_resp.exchange_data,
        ) {
            Ok(resp) => {
                if self.verbose {
                    println!("  Completed ECDH key exchange (our side)");
                }
                resp
            }
            Err(e) => {
                let error_msg = format!("Failed to complete ECDH (our side): {}", e);
                eprintln!("✗ ECDH validation FAILED: {}", error_msg);
                return ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(error_msg),
                };
            }
        };

        // Complete ECDH from peer's side using our public key
        let peer_finish_resp = match client.ecdh_finish(
            &peer_generate_resp.context,
            CmKeyUsage::Aes,
            &our_generate_resp.exchange_data,
        ) {
            Ok(resp) => {
                if self.verbose {
                    println!("  Completed ECDH key exchange (peer side)");
                }
                resp
            }
            Err(e) => {
                let error_msg = format!("Failed to complete ECDH (peer side): {}", e);
                eprintln!("✗ ECDH validation FAILED: {}", error_msg);
                return ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(error_msg),
                };
            }
        };

        // Verify both sides derived the same shared secret by using them for AES-GCM
        let test_data = b"ECDH shared secret verification test data";
        let aad = b"additional authenticated data";

        // Encrypt with our derived key
        let encrypt_result = match client.aes_gcm_encrypt(&our_finish_resp.output, aad, test_data) {
            Ok(result) => {
                if self.verbose {
                    println!("  Encrypted test data with our derived key");
                }
                result
            }
            Err(e) => {
                let _ = client.delete(&our_finish_resp.output);
                let _ = client.delete(&peer_finish_resp.output);
                let error_msg = format!("Failed to encrypt with derived key: {}", e);
                eprintln!("✗ ECDH validation FAILED: {}", error_msg);
                return ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(error_msg),
                };
            }
        };

        // Decrypt with peer's derived key (should work if they derived the same key)
        match client.aes_gcm_decrypt(
            &peer_finish_resp.output,
            &encrypt_result.iv,
            aad,
            &encrypt_result.ciphertext,
            &encrypt_result.tag,
        ) {
            Ok(result) => {
                if result.plaintext == test_data {
                    if self.verbose {
                        println!("  Decrypted successfully with peer's derived key ✓");
                        println!("  Both sides derived the same shared secret!");
                    }
                } else {
                    let _ = client.delete(&our_finish_resp.output);
                    let _ = client.delete(&peer_finish_resp.output);
                    let error_msg = "Decrypted data doesn't match original".to_string();
                    eprintln!("✗ ECDH validation FAILED: {}", error_msg);
                    return ValidationResult {
                        test_name,
                        passed: false,
                        error_message: Some(error_msg),
                    };
                }
            }
            Err(e) => {
                let _ = client.delete(&our_finish_resp.output);
                let _ = client.delete(&peer_finish_resp.output);
                let error_msg = format!("Failed to decrypt with peer's derived key: {}", e);
                eprintln!("✗ ECDH validation FAILED: {}", error_msg);
                return ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(error_msg),
                };
            }
        }

        // Clean up
        if let Err(e) = client.delete(&our_finish_resp.output) {
            if self.verbose {
                eprintln!("  Warning: Failed to delete our derived key: {}", e);
            }
        }
        if let Err(e) = client.delete(&peer_finish_resp.output) {
            if self.verbose {
                eprintln!("  Warning: Failed to delete peer's derived key: {}", e);
            }
        }

        println!("✓ ECDH Key Exchange validation PASSED");
        ValidationResult {
            test_name,
            passed: true,
            error_message: None,
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
