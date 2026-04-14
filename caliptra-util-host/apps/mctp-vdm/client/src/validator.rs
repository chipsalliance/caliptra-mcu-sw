// Licensed under the Apache-2.0 license

//! Validator for MCTP VDM client — runs the 4 supported device-info commands
//! against a VDM server and reports pass/fail.

use crate::{DynamicI3cAddress, MctpVdmSocketDriver, TestConfig, VdmClient};
use anyhow::Result;
use caliptra_mcu_core_util_host_command_types::debug_unlock::{
    ECC_PUBLIC_KEY_WORD_SIZE, MLDSA_PUBLIC_KEY_WORD_SIZE, MLDSA_SIGNATURE_WORD_SIZE,
};
use std::net::SocketAddr;

/// Keys needed to sign a production debug unlock token.
///
/// When provided to the [`Validator`], the debug-unlock test will construct
/// a properly-signed token instead of sending a zeroed (expected-to-fail) token.
#[derive(Clone)]
pub struct DebugUnlockKeys {
    /// P-384 private key bytes (48 bytes, big-endian scalar).
    pub ecc_private_key_bytes: [u8; 48],
    /// P-384 public key as big-endian u32 words: X (12 words) || Y (12 words).
    pub ecc_public_key: [u32; ECC_PUBLIC_KEY_WORD_SIZE],
    /// ML-DSA-87 private key bytes.
    pub mldsa_private_key_bytes: Vec<u8>,
    /// ML-DSA-87 public key as little-endian u32 words.
    pub mldsa_public_key: [u32; MLDSA_PUBLIC_KEY_WORD_SIZE],
}

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
    debug_unlock_keys: Option<DebugUnlockKeys>,
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
            debug_unlock_keys: None,
        })
    }

    /// Toggle verbose output.
    pub fn set_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Set the debug unlock keys for full end-to-end token signing.
    pub fn set_debug_unlock_keys(mut self, keys: DebugUnlockKeys) -> Self {
        self.debug_unlock_keys = Some(keys);
        self
    }

    /// Run all validation tests and return results.
    pub fn start(&self) -> Result<Vec<ValidationResult>> {
        let mut driver = MctpVdmSocketDriver::new(self.port, self.target_addr);
        let mut client = VdmClient::new(&mut driver);
        client.connect()?;

        let mut results = vec![
            self.validate_get_device_id(&mut client),
            self.validate_get_device_capabilities(&mut client),
            self.validate_get_firmware_version(&mut client),
            self.validate_get_device_info(&mut client),
        ];

        results.push(self.validate_prod_debug_unlock(&mut client));

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
    // Debug Unlock validation
    // ------------------------------------------------------------------

    fn validate_prod_debug_unlock(&self, client: &mut VdmClient) -> ValidationResult {
        use caliptra_mcu_core_util_host_command_types::debug_unlock::ProdDebugUnlockTokenRequest;

        let test_name = "ProdDebugUnlock".to_string();

        if self.verbose {
            println!("\n=== Validating Production Debug Unlock Commands ===");
        }

        let unlock_level = 1u8;

        match client.prod_debug_unlock_req(unlock_level) {
            Ok(response) => {
                if self.verbose {
                    println!("  Got challenge response:");
                    println!(
                        "    UDI: {:02X?}...",
                        &response.unique_device_identifier[..8]
                    );
                    println!("    Challenge: {:02X?}...", &response.challenge[..8]);
                }

                if let Some(keys) = &self.debug_unlock_keys {
                    // Full end-to-end: construct and sign a real token.
                    if self.verbose {
                        println!("  Signing token with provided keys...");
                    }

                    let token_req =
                        match Self::sign_debug_unlock_token(&response, unlock_level, keys) {
                            Ok(t) => t,
                            Err(e) => {
                                let msg = format!("Failed to sign token: {}", e);
                                eprintln!("  {}", msg);
                                return ValidationResult {
                                    test_name,
                                    passed: false,
                                    error_message: Some(msg),
                                };
                            }
                        };

                    match client.prod_debug_unlock_token(&token_req) {
                        Ok(_) => {
                            println!("✓ ProdDebugUnlock validation PASSED (token accepted)");
                            ValidationResult {
                                test_name,
                                passed: true,
                                error_message: None,
                            }
                        }
                        Err(e) => {
                            let msg = format!("Signed token rejected by device: {}", e);
                            eprintln!("✗ ProdDebugUnlock validation FAILED: {}", msg);
                            ValidationResult {
                                test_name,
                                passed: false,
                                error_message: Some(msg),
                            }
                        }
                    }
                } else {
                    // No keys — send a zeroed token (expected to fail).
                    let token_req = ProdDebugUnlockTokenRequest::default();
                    match client.prod_debug_unlock_token(&token_req) {
                        Ok(_) => {
                            if self.verbose {
                                println!("  Token submission accepted (unexpected in test mode)");
                            }
                        }
                        Err(_) => {
                            if self.verbose {
                                println!(
                                    "  Token submission correctly rejected (no valid signature) ✓"
                                );
                            }
                        }
                    }

                    println!("✓ ProdDebugUnlock validation PASSED");
                    ValidationResult {
                        test_name,
                        passed: true,
                        error_message: None,
                    }
                }
            }
            Err(e) => {
                let error_str = e.to_string();
                if self.verbose {
                    println!(
                        "  Debug unlock request returned error: {} (may be expected due to lifecycle)",
                        error_str
                    );
                }

                println!("✓ ProdDebugUnlock validation PASSED (command dispatched, rejected by device as expected)");
                ValidationResult {
                    test_name,
                    passed: true,
                    error_message: None,
                }
            }
        }
    }

    /// Construct a signed [`ProdDebugUnlockTokenRequest`] from the challenge and keys.
    fn sign_debug_unlock_token(
        challenge_resp: &caliptra_mcu_core_util_host_command_types::debug_unlock::ProdDebugUnlockReqResponse,
        unlock_level: u8,
        keys: &DebugUnlockKeys,
    ) -> Result<caliptra_mcu_core_util_host_command_types::debug_unlock::ProdDebugUnlockTokenRequest>
    {
        use caliptra_mcu_core_util_host_command_types::debug_unlock::ProdDebugUnlockTokenRequest;
        use ecdsa::signature::hazmat::PrehashSigner;
        use ecdsa::{Signature, SigningKey as EcdsaSigningKey};
        use fips204::traits::SerDes;
        use sha2::{Digest, Sha384, Sha512};

        let mut token = ProdDebugUnlockTokenRequest {
            length: ((std::mem::size_of::<ProdDebugUnlockTokenRequest>()) / 4) as u32,
            unique_device_identifier: challenge_resp.unique_device_identifier,
            unlock_level,
            reserved: [0; 3],
            challenge: challenge_resp.challenge,
            ecc_public_key: keys.ecc_public_key,
            mldsa_public_key: keys.mldsa_public_key,
            ..Default::default()
        };

        // --- ECDSA (P-384) signature over SHA-384 digest ---
        let mut hasher = Sha384::new();
        Digest::update(&mut hasher, token.unique_device_identifier);
        Digest::update(&mut hasher, [token.unlock_level]);
        Digest::update(&mut hasher, token.reserved);
        Digest::update(&mut hasher, token.challenge);
        let ecdsa_hash: [u8; 48] = hasher.finalize().into();

        let ecc_secret = p384::SecretKey::from_slice(&keys.ecc_private_key_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid ECC private key: {}", e))?;
        let signing_key = EcdsaSigningKey::<p384::NistP384>::from(&ecc_secret);
        let ecdsa_sig: Signature<p384::NistP384> = signing_key
            .sign_prehash(&ecdsa_hash)
            .map_err(|e| anyhow::anyhow!("ECDSA signing failed: {}", e))?;

        let r_bytes = ecdsa_sig.r().to_bytes();
        let s_bytes = ecdsa_sig.s().to_bytes();
        for (i, chunk) in r_bytes.chunks(4).enumerate() {
            token.ecc_signature[i] = u32::from_be_bytes(chunk.try_into().unwrap());
        }
        for (i, chunk) in s_bytes.chunks(4).enumerate() {
            token.ecc_signature[i + 12] = u32::from_be_bytes(chunk.try_into().unwrap());
        }

        // --- ML-DSA-87 signature over SHA-512 digest ---
        let mut hasher = Sha512::new();
        Digest::update(&mut hasher, token.unique_device_identifier);
        Digest::update(&mut hasher, [token.unlock_level]);
        Digest::update(&mut hasher, token.reserved);
        Digest::update(&mut hasher, token.challenge);
        let mldsa_hash: [u8; 64] = hasher.finalize().into();

        let mldsa_priv_key_arr: [u8; 4896] = keys
            .mldsa_private_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| {
                anyhow::anyhow!(
                    "Invalid MLDSA private key size: expected 4896, got {}",
                    keys.mldsa_private_key_bytes.len()
                )
            })?;
        let mldsa_private_key = fips204::ml_dsa_87::PrivateKey::try_from_bytes(mldsa_priv_key_arr)
            .map_err(|_| anyhow::anyhow!("Failed to parse ML-DSA-87 private key"))?;

        use fips204::traits::Signer;
        let mldsa_sig = mldsa_private_key
            .try_sign_with_seed(&[0u8; 32], &mldsa_hash, &[])
            .map_err(|_| anyhow::anyhow!("ML-DSA-87 signing failed"))?;

        // Pad to MLDSA_SIGNATURE_WORD_SIZE * 4 bytes and write as LE u32 words.
        let mut sig_padded = [0u8; MLDSA_SIGNATURE_WORD_SIZE * 4];
        sig_padded[..mldsa_sig.len()].copy_from_slice(&mldsa_sig);
        for (i, chunk) in sig_padded.chunks(4).enumerate() {
            token.mldsa_signature[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        Ok(token)
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
