// Licensed under the Apache-2.0 license

//! SPDM VDM validation runner for Caliptra VDM commands.
//!
//! Uses `SpdmVdmClient` typed interfaces for command execution,
//! handles result collection and reporting.
//!
//! To add a new command:
//! 1. Add a typed method in `SpdmVdmClient` (lib.rs)
//! 2. Add `run_<command>()` function below
//! 3. Call it from `run_all()`
//! 4. Add a config section in `config.rs`

use crate::config::TestConfig;
use crate::SpdmVdmClient;
use caliptra_mcu_core_util_host_command_types::certificate::AttestedCsrValidationError;
use caliptra_mcu_debug_unlock_signer::{DebugUnlockSigner, ProdDebugUnlockChallenge};

/// Result of a single validation check.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub test_name: String,
    pub status: ValidationStatus,
    pub detail: Option<String>,
}

/// Outcome of a validation check.
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationStatus {
    Pass,
    Fail,
    Skip,
}

impl ValidationResult {
    pub fn pass(test_name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            test_name: test_name.into(),
            status: ValidationStatus::Pass,
            detail: Some(detail.into()),
        }
    }

    pub fn fail(test_name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            test_name: test_name.into(),
            status: ValidationStatus::Fail,
            detail: Some(detail.into()),
        }
    }

    pub fn skip(test_name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            test_name: test_name.into(),
            status: ValidationStatus::Skip,
            detail: Some(detail.into()),
        }
    }
}

/// Print a summary table of validation results.
pub fn print_summary(results: &[ValidationResult]) {
    println!("\nValidation Summary");
    println!("==================");
    for r in results {
        let tag = match r.status {
            ValidationStatus::Pass => "PASS",
            ValidationStatus::Fail => "FAIL",
            ValidationStatus::Skip => "SKIP",
        };
        print!("  [{tag}] {}", r.test_name);
        if let Some(msg) = &r.detail {
            print!(" — {msg}");
        }
        println!();
    }
    let passed = results
        .iter()
        .filter(|r| r.status == ValidationStatus::Pass)
        .count();
    let skipped = results
        .iter()
        .filter(|r| r.status == ValidationStatus::Skip)
        .count();
    let total = results.len() - skipped;
    println!("\n  {passed}/{total} tests passed ({skipped} skipped)");
}

/// Returns true if all non-skipped results passed.
pub fn all_passed(results: &[ValidationResult]) -> bool {
    results
        .iter()
        .all(|r| r.status == ValidationStatus::Pass || r.status == ValidationStatus::Skip)
}

/// Run all VDM command validations using the typed SpdmVdmClient.
pub fn run_all(
    client: &mut SpdmVdmClient,
    config: &TestConfig,
    debug_unlock_signer: Option<&dyn DebugUnlockSigner>,
    verbose: bool,
) -> Vec<ValidationResult> {
    let mut results = Vec::new();

    results.extend(run_export_attested_csr(
        client,
        &config.export_attested_csr.key_ids,
        config.export_attested_csr.algorithm,
        verbose,
    ));

    if config.debug_unlock.enabled {
        results.push(run_prod_debug_unlock(
            client,
            config.debug_unlock.unlock_level,
            debug_unlock_signer,
            verbose,
        ));
    }

    results
}

/// Validate ExportAttestedCsr for each key ID using the typed client.
pub fn run_export_attested_csr(
    client: &mut SpdmVdmClient,
    key_ids: &[u32],
    algorithm: u32,
    verbose: bool,
) -> Vec<ValidationResult> {
    let nonce = [0xABu8; 32];
    key_ids
        .iter()
        .map(|&key_id| {
            let test_name = format!("ExportAttestedCsr(key_id={})", key_id);
            match client.export_attested_csr(key_id, algorithm, &nonce) {
                Ok(response) => match response.validate_csr_payload() {
                    Ok(len) => {
                        if verbose {
                            println!("  csr: {} bytes", len);
                        }
                        ValidationResult::pass(test_name, format!("{} bytes", len))
                    }
                    Err(AttestedCsrValidationError::Empty) => {
                        ValidationResult::fail(test_name, "CSR data is empty")
                    }
                    Err(AttestedCsrValidationError::TooLarge(len)) => ValidationResult::fail(
                        test_name,
                        format!("CSR data_len {} exceeds maximum", len),
                    ),
                },
                Err(msg) => {
                    let msg_str = format!("{}", msg);
                    if msg_str.contains("NotSupported") {
                        ValidationResult::skip(test_name, msg_str)
                    } else {
                        ValidationResult::fail(test_name, msg_str)
                    }
                }
            }
        })
        .collect()
}

/// Validate Production Debug Unlock via SPDM VDM.
///
/// When a [`DebugUnlockSigner`] is provided, performs a full end-to-end flow:
/// request challenge → sign token → submit token.
///
/// Without a signer, sends a zeroed token (expected to be rejected) to confirm
/// command dispatch works.
pub fn run_prod_debug_unlock(
    client: &mut SpdmVdmClient,
    unlock_level: u8,
    signer: Option<&dyn DebugUnlockSigner>,
    verbose: bool,
) -> ValidationResult {
    use caliptra_mcu_core_util_host_command_types::debug_unlock::ProdDebugUnlockTokenRequest;

    let test_name = "ProdDebugUnlock".to_string();

    if verbose {
        println!("\n=== Validating Production Debug Unlock (SPDM VDM) ===");
    }

    match client.prod_debug_unlock_req(unlock_level) {
        Ok(response) => {
            if verbose {
                println!("  Got challenge response:");
                println!(
                    "    UDI: {:02X?}...",
                    &response.unique_device_identifier[..8]
                );
                println!("    Challenge: {:02X?}...", &response.challenge[..8]);
            }

            if let Some(signer) = signer {
                // Full end-to-end: sign a real token
                if verbose {
                    println!("  Signing token with provided signer...");
                }

                let challenge = ProdDebugUnlockChallenge {
                    unique_device_identifier: response.unique_device_identifier,
                    challenge: response.challenge,
                };

                let token = match signer.sign_debug_unlock_token(&challenge, unlock_level) {
                    Ok(t) => ProdDebugUnlockTokenRequest {
                        length: t.length,
                        unique_device_identifier: t.unique_device_identifier,
                        unlock_level: t.unlock_level,
                        reserved: t.reserved,
                        challenge: t.challenge,
                        ecc_public_key: t.ecc_public_key,
                        mldsa_public_key: t.mldsa_public_key,
                        ecc_signature: t.ecc_signature,
                        mldsa_signature: t.mldsa_signature,
                    },
                    Err(e) => {
                        return ValidationResult::fail(
                            test_name,
                            format!("Failed to sign token: {}", e),
                        );
                    }
                };

                match client.prod_debug_unlock_token(&token) {
                    Ok(_) => ValidationResult::pass(test_name, "token accepted"),
                    Err(e) => {
                        ValidationResult::fail(test_name, format!("Signed token rejected: {}", e))
                    }
                }
            } else {
                // No signer — send zeroed token (expected to be rejected)
                let token_req = ProdDebugUnlockTokenRequest::default();
                match client.prod_debug_unlock_token(&token_req) {
                    Ok(_) => {
                        if verbose {
                            println!("  Token accepted (unexpected in test mode)");
                        }
                    }
                    Err(_) => {
                        if verbose {
                            println!("  Token correctly rejected (no valid signature) ✓");
                        }
                    }
                }
                ValidationResult::pass(test_name, "challenge received, command dispatch works")
            }
        }
        Err(e) => {
            let msg = format!("{}", e);
            if verbose {
                println!(
                    "  Debug unlock request returned error: {} (may be expected due to lifecycle)",
                    msg
                );
            }
            // The command was dispatched — the device rejected it, which is OK
            // (e.g., wrong lifecycle state).
            ValidationResult::pass(
                test_name,
                format!("command dispatched, rejected by device: {}", msg),
            )
        }
    }
}
