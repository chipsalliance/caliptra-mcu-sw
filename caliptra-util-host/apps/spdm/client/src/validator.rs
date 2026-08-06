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
use caliptra_mcu_command_auth_challenge_signer::{CommandAuthChallengeSigner, HybridMessageSigner};
use caliptra_mcu_core_util_host_command_types::certificate::AttestedCsrValidationError;
use caliptra_mcu_core_util_host_command_types::device_ownership_transfer::{
    DotDisableRequest, DotLockRequest, DotUnlockRequest, MC_DOT_DISABLE_CANONICAL_CMD_ID,
    MC_DOT_LOCK_CANONICAL_CMD_ID, MC_DOT_UNLOCK_CANONICAL_CMD_ID,
};
use caliptra_mcu_core_util_host_command_types::fuse::MC_FE_PROG_CANONICAL_CMD_ID;
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
    fe_prog_authorizer: Option<&dyn CommandAuthChallengeSigner>,
    dot_signer: Option<&dyn HybridMessageSigner>,
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

    results.push(run_fe_prog(
        client,
        config.fe_prog.partition,
        fe_prog_authorizer,
        verbose,
    ));

    if config.dot.enabled {
        results.extend(run_dot(
            client,
            config.dot.cak.as_deref(),
            dot_signer,
            verbose,
        ));
    }

    results
}

/// Validate the native DOT state-transition commands over SPDM VDM.
///
/// The disposable test device follows one coherent sequence so every command
/// is exercised: unlocked -> locked -> unlocked -> disabled.
pub fn run_dot(
    client: &mut SpdmVdmClient,
    cak_hex: Option<&str>,
    signer: Option<&dyn HybridMessageSigner>,
    verbose: bool,
) -> Vec<ValidationResult> {
    const LOCK_NAME: &str = "DotLock";
    const CHALLENGE_NAME: &str = "DotUnlockChallenge";
    const UNLOCK_NAME: &str = "DotUnlock";
    const DISABLE_NAME: &str = "DotDisable";

    let mut results = Vec::new();
    let Some(signer) = signer else {
        results.push(ValidationResult::skip(
            LOCK_NAME,
            "no DOT LAK signer provided",
        ));
        return results;
    };
    let Some(cak_hex) = cak_hex else {
        results.push(ValidationResult::fail(
            LOCK_NAME,
            "DOT CAK is not configured",
        ));
        return results;
    };
    let cak_bytes = match hex::decode(cak_hex) {
        Ok(bytes) => bytes,
        Err(error) => {
            results.push(ValidationResult::fail(
                LOCK_NAME,
                format!("invalid DOT CAK hex: {error}"),
            ));
            return results;
        }
    };
    let cak: [u8; 48] = match cak_bytes.try_into() {
        Ok(cak) => cak,
        Err(bytes) => {
            results.push(ValidationResult::fail(
                LOCK_NAME,
                format!("DOT CAK must be 48 bytes, got {}", bytes.len()),
            ));
            return results;
        }
    };

    let keys = match signer.dot_public_keys() {
        Ok(keys) => keys,
        Err(error) => {
            results.push(ValidationResult::fail(
                LOCK_NAME,
                format!("failed to derive DOT LAK public keys: {error}"),
            ));
            return results;
        }
    };
    let lak_hash = keys.dot_lak_hash();

    let mut lock_transcript = Vec::with_capacity(100);
    lock_transcript.extend_from_slice(&MC_DOT_LOCK_CANONICAL_CMD_ID.to_be_bytes());
    lock_transcript.extend_from_slice(&cak);
    lock_transcript.extend_from_slice(&lak_hash);
    let lock_signature = match signer.sign_message(&lock_transcript) {
        Ok(signature) => signature,
        Err(error) => {
            results.push(ValidationResult::fail(
                LOCK_NAME,
                format!("failed to sign DOT_LOCK: {error}"),
            ));
            return results;
        }
    };
    let lock_request = DotLockRequest {
        cak,
        lak_ecc_pub_x: keys.ecc_pub_x,
        lak_ecc_pub_y: keys.ecc_pub_y,
        lak_mldsa_pub: keys.mldsa_pub,
        signature: lock_signature,
    };
    match client.dot_lock(&lock_request) {
        Ok(response) if response.reset_required == 1 => {
            results.push(ValidationResult::pass(LOCK_NAME, "transition committed"));
        }
        Ok(response) => {
            results.push(ValidationResult::fail(
                LOCK_NAME,
                format!("unexpected reset_required={}", response.reset_required),
            ));
            return results;
        }
        Err(error) => {
            results.push(ValidationResult::fail(LOCK_NAME, error.to_string()));
            return results;
        }
    }

    let challenge = match client.dot_unlock_challenge() {
        Ok(response) => {
            results.push(ValidationResult::pass(
                CHALLENGE_NAME,
                "48-byte challenge received",
            ));
            response.challenge
        }
        Err(error) => {
            results.push(ValidationResult::fail(CHALLENGE_NAME, error.to_string()));
            return results;
        }
    };

    let mut unlock_transcript = Vec::with_capacity(52);
    unlock_transcript.extend_from_slice(&MC_DOT_UNLOCK_CANONICAL_CMD_ID.to_be_bytes());
    unlock_transcript.extend_from_slice(&challenge);
    let unlock_signature = match signer.sign_message(&unlock_transcript) {
        Ok(signature) => signature,
        Err(error) => {
            results.push(ValidationResult::fail(
                UNLOCK_NAME,
                format!("failed to sign DOT_UNLOCK: {error}"),
            ));
            return results;
        }
    };
    let unlock_request = DotUnlockRequest {
        lak_ecc_pub_x: keys.ecc_pub_x,
        lak_ecc_pub_y: keys.ecc_pub_y,
        lak_mldsa_pub: keys.mldsa_pub,
        signature: unlock_signature,
    };
    match client.dot_unlock(&unlock_request) {
        Ok(response) if response.reset_required == 1 => {
            results.push(ValidationResult::pass(UNLOCK_NAME, "transition committed"));
        }
        Ok(response) => {
            results.push(ValidationResult::fail(
                UNLOCK_NAME,
                format!("unexpected reset_required={}", response.reset_required),
            ));
            return results;
        }
        Err(error) => {
            results.push(ValidationResult::fail(UNLOCK_NAME, error.to_string()));
            return results;
        }
    }

    let mut disable_transcript = Vec::with_capacity(52);
    disable_transcript.extend_from_slice(&MC_DOT_DISABLE_CANONICAL_CMD_ID.to_be_bytes());
    disable_transcript.extend_from_slice(&lak_hash);
    let disable_signature = match signer.sign_message(&disable_transcript) {
        Ok(signature) => signature,
        Err(error) => {
            results.push(ValidationResult::fail(
                DISABLE_NAME,
                format!("failed to sign DOT_DISABLE: {error}"),
            ));
            return results;
        }
    };
    let disable_request = DotDisableRequest {
        lak_ecc_pub_x: keys.ecc_pub_x,
        lak_ecc_pub_y: keys.ecc_pub_y,
        lak_mldsa_pub: keys.mldsa_pub,
        signature: disable_signature,
    };
    match client.dot_disable(&disable_request) {
        Ok(response) if response.reset_required == 1 => {
            results.push(ValidationResult::pass(DISABLE_NAME, "transition committed"));
        }
        Ok(response) => results.push(ValidationResult::fail(
            DISABLE_NAME,
            format!("unexpected reset_required={}", response.reset_required),
        )),
        Err(error) => results.push(ValidationResult::fail(DISABLE_NAME, error.to_string())),
    }

    if verbose {
        println!("  DOT lock/unlock/disable sequence completed over SPDM VDM");
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
                        checksum: 0,
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
                ValidationResult::fail(test_name, "no signer provided")
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
            ValidationResult::fail(test_name, format!("debug unlock request failed: {}", msg))
        }
    }
}

/// Validate Field Entropy Programming (FE_PROG) via SPDM VDM.
///
/// When a [`CommandAuthChallengeSigner`] is provided, performs the full authorized flow:
/// 1. Request an auth challenge
/// 2. Ask the authorizer to produce the MAC
/// 3. Submit FE_PROG with the MAC
///
/// Without an authorizer the test is skipped.
pub fn run_fe_prog(
    client: &mut SpdmVdmClient,
    partition: u32,
    authorizer: Option<&dyn CommandAuthChallengeSigner>,
    verbose: bool,
) -> ValidationResult {
    let test_name = format!("FeProg(partition={})", partition);

    if verbose {
        println!("\n=== Validating Field Entropy Programming (SPDM VDM) ===");
    }

    let authorizer = match authorizer {
        Some(a) => a,
        None => {
            return ValidationResult::skip(test_name, "no FE_PROG authorizer provided");
        }
    };

    // Step 1: Get authorization challenge
    let challenge_resp = match client.get_auth_challenge() {
        Ok(resp) => resp,
        Err(e) => {
            return ValidationResult::fail(
                test_name,
                format!("Failed to get auth challenge: {}", e),
            );
        }
    };

    if verbose {
        println!(
            "  Got challenge: {:02X?}...",
            &challenge_resp.challenge[..8]
        );
    }

    // Step 2: Compute the hybrid signature via the authorizer
    let cmd_id = MC_FE_PROG_CANONICAL_CMD_ID;
    let sig =
        match authorizer.authorize(cmd_id, &partition.to_le_bytes(), &challenge_resp.challenge) {
            Ok(sig) => sig,
            Err(e) => {
                return ValidationResult::fail(test_name, format!("Authorization failed: {}", e));
            }
        };

    // Public keys travel on the wire; the device re-derives its SHA-384 anchor
    // from these bytes before verifying.
    let (ecc_pub_x, ecc_pub_y, mldsa_pub) = match authorizer.public_keys() {
        Ok(keys) => keys,
        Err(e) => {
            return ValidationResult::fail(test_name, format!("public_keys() failed: {}", e));
        }
    };

    // Step 3: Submit FE_PROG. `nonce` echoes the challenge the device minted for
    // us (prod-debug-unlock idiom): the device compares this wire copy to its
    // stored one-time challenge, then rebuilds the signed transcript from it.
    match client.fe_prog(
        partition,
        &sig,
        &challenge_resp.challenge,
        &ecc_pub_x,
        &ecc_pub_y,
        &mldsa_pub,
    ) {
        Ok(_) => {
            if verbose {
                println!("  FE_PROG succeeded for partition {}", partition);
            }
            ValidationResult::pass(test_name, format!("partition {} programmed", partition))
        }
        Err(e) => {
            let msg = format!("{}", e);
            if verbose {
                println!("  FE_PROG failed: {}", msg);
            }
            ValidationResult::fail(test_name, msg)
        }
    }
}
