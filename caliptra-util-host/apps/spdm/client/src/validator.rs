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
use crate::{AuthorizedCommandData, SpdmVdmClient};
use caliptra_mcu_command_auth_challenge_signer::{CommandAuthChallengeSigner, HybridMessageSigner};
use caliptra_mcu_core_util_host_command_types::attestation::{
    formats_from_bitmap, AsymAlgo, AttestationValidationError, EvidenceFormat, PkiEntitySlot,
};
use caliptra_mcu_core_util_host_command_types::certificate::AttestedCsrValidationError;
use caliptra_mcu_core_util_host_command_types::device_ownership_transfer::{
    DotAuthorizationTrailer, DotDisableRequest, DotLockRequest, DotRotateRequest, DotUnlockRequest,
    GetDotBackupBlobRequest, DOT_FAMILY_ID, MC_DOT_DISABLE_CANONICAL_CMD_ID,
    MC_DOT_LOCK_CANONICAL_CMD_ID, MC_DOT_ROTATE_CANONICAL_CMD_ID, MC_DOT_UNLOCK_CANONICAL_CMD_ID,
    MC_GET_DOT_BACKUP_BLOB_CANONICAL_CMD_ID,
};
use caliptra_mcu_core_util_host_command_types::fuse::{
    MC_FE_PROG_CANONICAL_CMD_ID, MC_FUSE_INCREASE_CALIPTRA_MIN_SVN_CANONICAL_CMD_ID,
    MC_FUSE_LOCK_PARTITION_CANONICAL_CMD_ID, MC_FUSE_REVOKE_VENDOR_PK_HASH_CANONICAL_CMD_ID,
    MC_FUSE_REVOKE_VENDOR_PUB_KEY_CANONICAL_CMD_ID, MC_PROVISION_OWNER_PK_HASH_CANONICAL_CMD_ID,
    MC_PROVISION_VENDOR_PK_HASH_CANONICAL_CMD_ID,
};
use caliptra_mcu_core_util_host_transport::{CaliptraVdmCommand, CaliptraVdmCompletionCode};
use caliptra_mcu_debug_unlock_signer::{DebugUnlockSigner, ProdDebugUnlockChallenge};
use caliptra_mcu_mbox_common::messages::{HybridSignature, AUTH_CMD_NONCE_LEN};
use caliptra_util_host_commands::api::CaliptraApiError;

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
    command_authorizer: Option<&dyn CommandAuthChallengeSigner>,
    dot_signer: Option<&dyn HybridMessageSigner>,
    verbose: bool,
) -> Vec<ValidationResult> {
    if let Some(suite) = config.validation.fuse_suite.as_deref() {
        return run_fuse_suite(
            client,
            suite,
            command_authorizer,
            dot_signer,
            config.dot.cak.as_deref(),
            verbose,
        );
    }

    let mut results = Vec::new();

    results.extend(run_export_attested_csr(
        client,
        &config.export_attested_csr.key_ids,
        config.export_attested_csr.algorithm,
        verbose,
    ));

    match config.get_attestation.nonce_bytes() {
        Ok(nonce) => results.extend(run_get_attestation(
            client,
            config.get_attestation.algorithm,
            &nonce,
            verbose,
        )),
        Err(e) => results.push(ValidationResult::fail(
            "GetAttestation(query)",
            format!("invalid get_attestation config: {e}"),
        )),
    }

    if config.debug_unlock.enabled {
        // Signing a token needs key material the caller supplies with
        // --debug-unlock-keys-file. Without it the command can only fail, so
        // report it as skipped rather than as a device failure.
        if debug_unlock_signer.is_some() {
            results.push(run_prod_debug_unlock(
                client,
                config.debug_unlock.unlock_level,
                debug_unlock_signer,
                verbose,
            ));
        } else {
            results.push(ValidationResult::skip(
                "ProdDebugUnlock",
                "no debug unlock signer provided",
            ));
        }
    }

    if config.authorized_commands.negative_authorization_tests {
        results.extend(run_authorization_negative_tests(
            client,
            command_authorizer,
            verbose,
        ));
    }

    if config.authorized_commands.policy_rejection_tests {
        results.extend(run_fuse_policy_rejection_tests(
            client,
            command_authorizer,
            verbose,
        ));
    }

    if config.provision_vendor_pk_hash.enabled {
        results.push(run_provision_vendor_pk_hash(
            client,
            config.provision_vendor_pk_hash.slot,
            &config.provision_vendor_pk_hash.hash,
            command_authorizer,
            verbose,
        ));
    }
    if config.provision_owner_pk_hash.enabled {
        results.push(run_provision_owner_pk_hash(
            client,
            &config.provision_owner_pk_hash.hash,
            command_authorizer,
            verbose,
        ));
    }
    if config.increase_caliptra_min_svn.enabled {
        results.push(run_increase_caliptra_min_svn(
            client,
            config.increase_caliptra_min_svn.flags,
            config.increase_caliptra_min_svn.svn,
            command_authorizer,
            verbose,
        ));
    }
    if config.fe_prog.enabled {
        results.push(run_fe_prog(
            client,
            config.fe_prog.partition,
            command_authorizer,
            verbose,
        ));
    }
    if config.revoke_vendor_pub_key.enabled {
        let cfg = &config.revoke_vendor_pub_key;
        results.push(run_revoke_vendor_pub_key(
            client,
            cfg.reserved,
            cfg.vendor_pk_hash_slot,
            cfg.key_type,
            cfg.key_index,
            command_authorizer,
            verbose,
        ));
    }
    if config.revoke_vendor_pk_hash.enabled {
        let cfg = &config.revoke_vendor_pk_hash;
        results.push(run_revoke_vendor_pk_hash(
            client,
            cfg.reserved,
            cfg.vendor_pk_hash_slot,
            command_authorizer,
            verbose,
        ));
    }

    if config.dot.enabled {
        results.extend(run_dot(
            client,
            config.dot.cak.as_deref(),
            command_authorizer,
            dot_signer,
            verbose,
        ));
    }

    results
}

/// Validate authorized and native DOT commands over SPDM VDM.
///
/// The disposable test device follows one coherent sequence so every command
/// is exercised: unlocked -> locked -> unlocked -> disabled.
pub fn run_dot(
    client: &mut SpdmVdmClient,
    cak_hex: Option<&str>,
    command_authorizer: Option<&dyn CommandAuthChallengeSigner>,
    native_signer: Option<&dyn HybridMessageSigner>,
    verbose: bool,
) -> Vec<ValidationResult> {
    const STATUS_NAME: &str = "DotStatus";
    const LOCK_NAME: &str = "DotLock";
    const BACKUP_NAME: &str = "GetDotBackupBlob";
    const ROTATE_NAME: &str = "DotRotate";
    const CHALLENGE_NAME: &str = "DotUnlockChallenge";
    const UNLOCK_NAME: &str = "DotUnlock";
    const DISABLE_NAME: &str = "DotDisable";

    let mut results = Vec::new();
    let Some(command_authorizer) = command_authorizer else {
        results.push(ValidationResult::skip(
            LOCK_NAME,
            "no command authorizer provided",
        ));
        return results;
    };
    let Some(native_signer) = native_signer else {
        results.push(ValidationResult::skip(
            CHALLENGE_NAME,
            "no native DOT signer provided",
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

    match client.dot_status() {
        Ok(response) if response.status.enabled == 1 && response.status.locked == 0 => {
            results.push(ValidationResult::pass(
                STATUS_NAME,
                format!("unlocked, {} fuses burned", response.status.burned),
            ));
        }
        Ok(response) => {
            results.push(ValidationResult::fail(
                STATUS_NAME,
                format!(
                    "expected enabled unlocked state, got enabled={} locked={} burned={}",
                    response.status.enabled, response.status.locked, response.status.burned
                ),
            ));
            return results;
        }
        Err(error) => {
            results.push(ValidationResult::fail(STATUS_NAME, error.to_string()));
            return results;
        }
    }

    let keys = match native_signer.dot_public_keys() {
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

    let mut lock_payload = MC_DOT_LOCK_CANONICAL_CMD_ID.to_le_bytes().to_vec();
    lock_payload.extend_from_slice(&cak);
    lock_payload.extend_from_slice(&lak_hash);
    let lock_auth = match authorize_command(
        client,
        DOT_FAMILY_ID,
        &lock_payload,
        Some(command_authorizer),
    ) {
        Ok(authorization) => authorization,
        Err(error) => {
            results.push(ValidationResult::fail(
                LOCK_NAME,
                format!("failed to authorize DOT_LOCK: {error}"),
            ));
            return results;
        }
    };
    let lock_request = DotLockRequest {
        cak,
        lak_hash,
        authorization: DotAuthorizationTrailer {
            nonce: lock_auth.nonce,
            ecc_pub_x: lock_auth.ecc_pub_x,
            ecc_pub_y: lock_auth.ecc_pub_y,
            mldsa_pub: lock_auth.mldsa_pub,
            signature: lock_auth.sig,
        },
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

    let backup_payload = MC_GET_DOT_BACKUP_BLOB_CANONICAL_CMD_ID.to_le_bytes();
    let backup_auth = match authorize_command(
        client,
        DOT_FAMILY_ID,
        &backup_payload,
        Some(command_authorizer),
    ) {
        Ok(authorization) => authorization,
        Err(error) => {
            results.push(ValidationResult::fail(BACKUP_NAME, error));
            return results;
        }
    };
    let backup_request = GetDotBackupBlobRequest {
        authorization: DotAuthorizationTrailer {
            nonce: backup_auth.nonce,
            ecc_pub_x: backup_auth.ecc_pub_x,
            ecc_pub_y: backup_auth.ecc_pub_y,
            mldsa_pub: backup_auth.mldsa_pub,
            signature: backup_auth.sig,
        },
    };
    match client.get_dot_backup_blob(&backup_request) {
        Ok(response) if response.blob.iter().any(|byte| *byte != 0) => {
            results.push(ValidationResult::pass(
                BACKUP_NAME,
                "authenticated blob returned",
            ));
        }
        Ok(_) => {
            results.push(ValidationResult::fail(BACKUP_NAME, "empty blob returned"));
            return results;
        }
        Err(error) => {
            results.push(ValidationResult::fail(BACKUP_NAME, error.to_string()));
            return results;
        }
    }

    let min_fuse_count = 3u32;
    let mut rotate_payload = MC_DOT_ROTATE_CANONICAL_CMD_ID.to_le_bytes().to_vec();
    rotate_payload.extend_from_slice(&min_fuse_count.to_le_bytes());
    rotate_payload.extend_from_slice(&cak);
    rotate_payload.extend_from_slice(&lak_hash);
    let rotate_auth = match authorize_command(
        client,
        DOT_FAMILY_ID,
        &rotate_payload,
        Some(command_authorizer),
    ) {
        Ok(authorization) => authorization,
        Err(error) => {
            results.push(ValidationResult::fail(ROTATE_NAME, error));
            return results;
        }
    };
    let rotate_request = DotRotateRequest {
        min_fuse_count,
        cak,
        lak_hash,
        authorization: DotAuthorizationTrailer {
            nonce: rotate_auth.nonce,
            ecc_pub_x: rotate_auth.ecc_pub_x,
            ecc_pub_y: rotate_auth.ecc_pub_y,
            mldsa_pub: rotate_auth.mldsa_pub,
            signature: rotate_auth.sig,
        },
    };
    match client.dot_rotate(&rotate_request) {
        Ok(response) if response.reset_required == 1 => {
            results.push(ValidationResult::pass(ROTATE_NAME, "epoch rotated"));
        }
        Ok(response) => {
            results.push(ValidationResult::fail(
                ROTATE_NAME,
                format!("unexpected reset_required={}", response.reset_required),
            ));
            return results;
        }
        Err(error) => {
            results.push(ValidationResult::fail(ROTATE_NAME, error.to_string()));
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
    let unlock_signature = match native_signer.sign_message(&unlock_transcript) {
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

    let mut disable_payload = MC_DOT_DISABLE_CANONICAL_CMD_ID.to_le_bytes().to_vec();
    disable_payload.extend_from_slice(&lak_hash);
    let disable_auth = match authorize_command(
        client,
        DOT_FAMILY_ID,
        &disable_payload,
        Some(command_authorizer),
    ) {
        Ok(authorization) => authorization,
        Err(error) => {
            results.push(ValidationResult::fail(
                DISABLE_NAME,
                format!("failed to authorize DOT_DISABLE: {error}"),
            ));
            return results;
        }
    };
    let disable_request = DotDisableRequest {
        lak_hash,
        authorization: DotAuthorizationTrailer {
            nonce: disable_auth.nonce,
            ecc_pub_x: disable_auth.ecc_pub_x,
            ecc_pub_y: disable_auth.ecc_pub_y,
            mldsa_pub: disable_auth.mldsa_pub,
            signature: disable_auth.sig,
        },
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
        println!("  DOT authorized/native command sequence completed over SPDM VDM");
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

/// Validate GET_ATTESTATION over SPDM VDM.
///
/// The device's supported formats are compile-time selected, so this first
/// issues a discovery query and drives whatever the device advertises. That
/// keeps the test aligned with the firmware feature set instead of hardcoding
/// an expectation that breaks on a differently-configured build.
///
/// Checks performed:
/// - discovery query returns a well-formed, non-empty bitmap
/// - every advertised format returns non-empty evidence with the format echoed
/// - a format the device did not advertise is rejected rather than answered
///
/// TODO(follow-up PR): verify the returned evidence cryptographically —
/// fetch the AK certificate chain over SPDM `GET_CERTIFICATE`, then
/// (a) verify the COSE_Sign1 envelope over the OCP EAT and check the nonce
///     appears in the `eat_nonce` claim, and
/// (b) parse the PCR quote structure and verify its signature and nonce.
pub fn run_get_attestation(
    client: &mut SpdmVdmClient,
    algorithm: u32,
    nonce: &[u8; 32],
    verbose: bool,
) -> Vec<ValidationResult> {
    let mut results = Vec::new();

    let algorithm = match AsymAlgo::try_from(algorithm) {
        Ok(a) => a,
        Err(_) => {
            results.push(ValidationResult::fail(
                "GetAttestation(query)",
                format!("unknown algorithm {:#06x} in config", algorithm),
            ));
            return results;
        }
    };

    let query_name = "GetAttestation(query)";
    let bitmap = match client.get_attestation_formats() {
        Ok(response) => match response.supported_formats() {
            Ok(0) => {
                results.push(ValidationResult::fail(
                    query_name,
                    "device advertises no evidence formats",
                ));
                return results;
            }
            Ok(bitmap) => {
                if verbose {
                    println!("  supported evidence formats: {:#010x}", bitmap);
                }
                results.push(ValidationResult::pass(
                    query_name,
                    format!("bitmap {:#010x}", bitmap),
                ));
                bitmap
            }
            Err(e) => {
                results.push(ValidationResult::fail(query_name, e.to_string()));
                return results;
            }
        },
        Err(msg) => {
            let msg_str = format!("{}", msg);
            results.push(if msg_str.contains("NotSupported") {
                ValidationResult::skip(query_name, msg_str)
            } else {
                ValidationResult::fail(query_name, msg_str)
            });
            return results;
        }
    };

    for format in formats_from_bitmap(bitmap) {
        let test_name = format!("GetAttestation({}/{})", format.name(), algorithm.name());
        let result = match client.get_attestation(format, algorithm, PkiEntitySlot::Vendor, nonce) {
            Ok(response) => match response.validate_evidence_payload(format) {
                Ok(len) => {
                    if verbose {
                        println!("  {}: {} bytes of evidence", format.name(), len);
                    }
                    ValidationResult::pass(test_name, format!("{} bytes", len))
                }
                Err(e @ AttestationValidationError::Empty) => {
                    ValidationResult::fail(test_name, e.to_string())
                }
                Err(e) => ValidationResult::fail(test_name, e.to_string()),
            },
            Err(msg) => {
                let msg_str = format!("{}", msg);
                if msg_str.contains("NotSupported") {
                    // The bitmap advertises formats, not format/algorithm
                    // pairs; a device may support this format only under a
                    // different algorithm. That is conforming, so record the
                    // pair as unsupported rather than a bitmap contradiction.
                    ValidationResult::skip(
                        test_name,
                        format!("format/algorithm pair not supported: {}", msg_str),
                    )
                } else {
                    ValidationResult::fail(test_name, msg_str)
                }
            }
        };
        results.push(result);
    }

    // Negative case: a format the device did not advertise must be refused.
    if let Some(unsupported) = EvidenceFormat::ALL
        .iter()
        .copied()
        .find(|f| bitmap & f.bit() == 0)
    {
        let test_name = format!("GetAttestation(unsupported {})", unsupported.name());
        results.push(
            match client.get_attestation(unsupported, algorithm, PkiEntitySlot::Vendor, nonce) {
                Ok(_) => ValidationResult::fail(
                    test_name,
                    "device returned evidence for a format it does not advertise",
                ),
                Err(msg) => ValidationResult::pass(test_name, format!("rejected: {}", msg)),
            },
        );
    }

    results
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

struct AuthorizedCommandAuthorization {
    sig: HybridSignature,
    nonce: [u8; AUTH_CMD_NONCE_LEN],
    ecc_pub_x: [u8; 48],
    ecc_pub_y: [u8; 48],
    mldsa_pub: [u8; 2592],
}

impl AuthorizedCommandAuthorization {
    fn as_command_data(&self) -> AuthorizedCommandData<'_> {
        AuthorizedCommandData {
            sig: &self.sig,
            nonce: &self.nonce,
            ecc_pub_x: &self.ecc_pub_x,
            ecc_pub_y: &self.ecc_pub_y,
            mldsa_pub: &self.mldsa_pub,
        }
    }
}

fn authorize_command(
    client: &mut SpdmVdmClient,
    command_id: u32,
    payload: &[u8],
    authorizer: Option<&dyn CommandAuthChallengeSigner>,
) -> Result<AuthorizedCommandAuthorization, String> {
    let authorizer = authorizer.ok_or_else(|| "no command authorizer provided".to_string())?;
    let challenge = client
        .get_auth_challenge()
        .map_err(|e| format!("Failed to get auth challenge: {e}"))?;
    let sig = authorizer
        .authorize(command_id, payload, &challenge.challenge)
        .map_err(|e| format!("Authorization failed: {e}"))?;
    let (ecc_pub_x, ecc_pub_y, mldsa_pub) = authorizer
        .public_keys()
        .map_err(|e| format!("public_keys() failed: {e}"))?;
    Ok(AuthorizedCommandAuthorization {
        sig,
        nonce: challenge.challenge,
        ecc_pub_x,
        ecc_pub_y,
        mldsa_pub,
    })
}

pub fn run_provision_vendor_pk_hash(
    client: &mut SpdmVdmClient,
    slot: u32,
    hash_hex: &str,
    authorizer: Option<&dyn CommandAuthChallengeSigner>,
    _verbose: bool,
) -> ValidationResult {
    let test_name = format!("ProvisionVendorPkHash(slot={slot})");
    let hash_vec = match hex::decode(hash_hex) {
        Ok(hash) if hash.len() == 48 => hash,
        Ok(hash) => {
            return ValidationResult::fail(
                test_name,
                format!("hash must be 48 bytes, got {}", hash.len()),
            )
        }
        Err(e) => return ValidationResult::fail(test_name, format!("invalid hash hex: {e}")),
    };
    let hash: [u8; 48] = hash_vec.try_into().unwrap();
    let mut payload = Vec::with_capacity(52);
    payload.extend_from_slice(&slot.to_le_bytes());
    payload.extend_from_slice(&hash);
    let auth = match authorize_command(
        client,
        MC_PROVISION_VENDOR_PK_HASH_CANONICAL_CMD_ID,
        &payload,
        authorizer,
    ) {
        Ok(auth) => auth,
        Err(e) => return ValidationResult::fail(test_name, e),
    };
    match client.provision_vendor_pk_hash(slot, &hash, auth.as_command_data()) {
        Ok(_) => ValidationResult::pass(test_name, "hash provisioned"),
        Err(e) => ValidationResult::fail(test_name, e.to_string()),
    }
}

pub fn run_provision_owner_pk_hash(
    client: &mut SpdmVdmClient,
    hash_hex: &str,
    authorizer: Option<&dyn CommandAuthChallengeSigner>,
    _verbose: bool,
) -> ValidationResult {
    let test_name = "ProvisionOwnerPkHash";
    let hash_vec = match hex::decode(hash_hex) {
        Ok(hash) if hash.len() == 48 => hash,
        Ok(hash) => {
            return ValidationResult::fail(
                test_name,
                format!("hash must be 48 bytes, got {}", hash.len()),
            )
        }
        Err(error) => {
            return ValidationResult::fail(test_name, format!("invalid hash hex: {error}"))
        }
    };
    let hash: [u8; 48] = hash_vec.try_into().unwrap();
    let auth = match authorize_command(
        client,
        MC_PROVISION_OWNER_PK_HASH_CANONICAL_CMD_ID,
        &hash,
        authorizer,
    ) {
        Ok(auth) => auth,
        Err(error) => return ValidationResult::fail(test_name, error),
    };
    match client.provision_owner_pk_hash(
        &hash,
        &auth.sig,
        &auth.nonce,
        &auth.ecc_pub_x,
        &auth.ecc_pub_y,
        &auth.mldsa_pub,
    ) {
        Ok(_) => ValidationResult::pass(test_name, "hash provisioned"),
        Err(error) => ValidationResult::fail(test_name, error.to_string()),
    }
}

pub fn run_increase_caliptra_min_svn(
    client: &mut SpdmVdmClient,
    flags: u32,
    svn: u32,
    authorizer: Option<&dyn CommandAuthChallengeSigner>,
    _verbose: bool,
) -> ValidationResult {
    let test_name = format!("FuseIncreaseCaliptraMinSvn(svn={svn})");
    let mut payload = Vec::with_capacity(8);
    payload.extend_from_slice(&flags.to_le_bytes());
    payload.extend_from_slice(&svn.to_le_bytes());
    let auth = match authorize_command(
        client,
        MC_FUSE_INCREASE_CALIPTRA_MIN_SVN_CANONICAL_CMD_ID,
        &payload,
        authorizer,
    ) {
        Ok(auth) => auth,
        Err(e) => return ValidationResult::fail(test_name, e),
    };
    match client.fuse_increase_caliptra_min_svn(flags, svn, auth.as_command_data()) {
        Ok(_) => ValidationResult::pass(test_name, "minimum SVN updated"),
        Err(e) => ValidationResult::fail(test_name, e.to_string()),
    }
}

pub fn run_revoke_vendor_pub_key(
    client: &mut SpdmVdmClient,
    reserved: u32,
    slot: u32,
    key_type: u32,
    key_index: u32,
    authorizer: Option<&dyn CommandAuthChallengeSigner>,
    _verbose: bool,
) -> ValidationResult {
    let test_name =
        format!("FuseRevokeVendorPubKey(slot={slot},type={key_type},index={key_index})");
    let mut payload = Vec::with_capacity(16);
    for value in [reserved, slot, key_type, key_index] {
        payload.extend_from_slice(&value.to_le_bytes());
    }
    let auth = match authorize_command(
        client,
        MC_FUSE_REVOKE_VENDOR_PUB_KEY_CANONICAL_CMD_ID,
        &payload,
        authorizer,
    ) {
        Ok(auth) => auth,
        Err(e) => return ValidationResult::fail(test_name, e),
    };
    match client.fuse_revoke_vendor_pub_key(
        reserved,
        slot,
        key_type,
        key_index,
        auth.as_command_data(),
    ) {
        Ok(_) => ValidationResult::pass(test_name, "key revoked"),
        Err(e) => ValidationResult::fail(test_name, e.to_string()),
    }
}

pub fn run_revoke_vendor_pk_hash(
    client: &mut SpdmVdmClient,
    reserved: u32,
    slot: u32,
    authorizer: Option<&dyn CommandAuthChallengeSigner>,
    _verbose: bool,
) -> ValidationResult {
    let test_name = format!("FuseRevokeVendorPkHash(slot={slot})");
    let mut payload = Vec::with_capacity(8);
    payload.extend_from_slice(&reserved.to_le_bytes());
    payload.extend_from_slice(&slot.to_le_bytes());
    let auth = match authorize_command(
        client,
        MC_FUSE_REVOKE_VENDOR_PK_HASH_CANONICAL_CMD_ID,
        &payload,
        authorizer,
    ) {
        Ok(auth) => auth,
        Err(e) => return ValidationResult::fail(test_name, e),
    };
    match client.fuse_revoke_vendor_pk_hash(reserved, slot, auth.as_command_data()) {
        Ok(_) => ValidationResult::pass(test_name, "PK-hash slot revoked"),
        Err(e) => ValidationResult::fail(test_name, e.to_string()),
    }
}

#[derive(Debug)]
enum AuthorizedCommandError {
    Preparation(String),
    Command(CaliptraApiError),
}

fn signed_provision_vendor_pk_hash(
    client: &mut SpdmVdmClient,
    slot: u32,
    hash: &[u8; 48],
    authorizer: &dyn CommandAuthChallengeSigner,
) -> Result<(), AuthorizedCommandError> {
    let mut payload = Vec::with_capacity(52);
    payload.extend_from_slice(&slot.to_le_bytes());
    payload.extend_from_slice(hash);
    let auth = authorize_command(
        client,
        MC_PROVISION_VENDOR_PK_HASH_CANONICAL_CMD_ID,
        &payload,
        Some(authorizer),
    )
    .map_err(AuthorizedCommandError::Preparation)?;
    client
        .provision_vendor_pk_hash(slot, hash, auth.as_command_data())
        .map(|_| ())
        .map_err(AuthorizedCommandError::Command)
}

fn signed_provision_owner_pk_hash(
    client: &mut SpdmVdmClient,
    hash: &[u8; 48],
    authorizer: &dyn CommandAuthChallengeSigner,
) -> Result<(), AuthorizedCommandError> {
    let auth = authorize_command(
        client,
        MC_PROVISION_OWNER_PK_HASH_CANONICAL_CMD_ID,
        hash,
        Some(authorizer),
    )
    .map_err(AuthorizedCommandError::Preparation)?;
    client
        .provision_owner_pk_hash(
            hash,
            &auth.sig,
            &auth.nonce,
            &auth.ecc_pub_x,
            &auth.ecc_pub_y,
            &auth.mldsa_pub,
        )
        .map(|_| ())
        .map_err(AuthorizedCommandError::Command)
}

fn signed_increase_caliptra_min_svn(
    client: &mut SpdmVdmClient,
    flags: u32,
    svn: u32,
    authorizer: &dyn CommandAuthChallengeSigner,
) -> Result<(), AuthorizedCommandError> {
    let mut payload = Vec::with_capacity(8);
    payload.extend_from_slice(&flags.to_le_bytes());
    payload.extend_from_slice(&svn.to_le_bytes());
    let auth = authorize_command(
        client,
        MC_FUSE_INCREASE_CALIPTRA_MIN_SVN_CANONICAL_CMD_ID,
        &payload,
        Some(authorizer),
    )
    .map_err(AuthorizedCommandError::Preparation)?;
    client
        .fuse_increase_caliptra_min_svn(flags, svn, auth.as_command_data())
        .map(|_| ())
        .map_err(AuthorizedCommandError::Command)
}

fn signed_revoke_vendor_pub_key(
    client: &mut SpdmVdmClient,
    reserved: u32,
    slot: u32,
    key_type: u32,
    key_index: u32,
    authorizer: &dyn CommandAuthChallengeSigner,
) -> Result<(), AuthorizedCommandError> {
    let mut payload = Vec::with_capacity(16);
    for field in [reserved, slot, key_type, key_index] {
        payload.extend_from_slice(&field.to_le_bytes());
    }
    let auth = authorize_command(
        client,
        MC_FUSE_REVOKE_VENDOR_PUB_KEY_CANONICAL_CMD_ID,
        &payload,
        Some(authorizer),
    )
    .map_err(AuthorizedCommandError::Preparation)?;
    client
        .fuse_revoke_vendor_pub_key(reserved, slot, key_type, key_index, auth.as_command_data())
        .map(|_| ())
        .map_err(AuthorizedCommandError::Command)
}

fn signed_revoke_vendor_pk_hash(
    client: &mut SpdmVdmClient,
    reserved: u32,
    slot: u32,
    authorizer: &dyn CommandAuthChallengeSigner,
) -> Result<(), AuthorizedCommandError> {
    let mut payload = Vec::with_capacity(8);
    payload.extend_from_slice(&reserved.to_le_bytes());
    payload.extend_from_slice(&slot.to_le_bytes());
    let auth = authorize_command(
        client,
        MC_FUSE_REVOKE_VENDOR_PK_HASH_CANONICAL_CMD_ID,
        &payload,
        Some(authorizer),
    )
    .map_err(AuthorizedCommandError::Preparation)?;
    client
        .fuse_revoke_vendor_pk_hash(reserved, slot, auth.as_command_data())
        .map(|_| ())
        .map_err(AuthorizedCommandError::Command)
}

fn signed_fuse_lock_partition(
    client: &mut SpdmVdmClient,
    partition: u32,
    authorizer: &dyn CommandAuthChallengeSigner,
) -> Result<(), AuthorizedCommandError> {
    let payload = partition.to_le_bytes();
    let auth = authorize_command(
        client,
        MC_FUSE_LOCK_PARTITION_CANONICAL_CMD_ID,
        &payload,
        Some(authorizer),
    )
    .map_err(AuthorizedCommandError::Preparation)?;
    client
        .fuse_lock_partition(
            partition,
            &auth.sig,
            &auth.nonce,
            &auth.ecc_pub_x,
            &auth.ecc_pub_y,
            &auth.mldsa_pub,
        )
        .map(|_| ())
        .map_err(AuthorizedCommandError::Command)
}

fn expect_success(test_name: &str, result: Result<(), AuthorizedCommandError>) -> ValidationResult {
    match result {
        Ok(()) => ValidationResult::pass(test_name, "accepted"),
        Err(error) => ValidationResult::fail(test_name, format!("{error:?}")),
    }
}

fn expect_completion(
    test_name: &str,
    result: Result<(), AuthorizedCommandError>,
    expected: CaliptraVdmCompletionCode,
) -> ValidationResult {
    match result {
        Err(AuthorizedCommandError::Command(CaliptraApiError::DeviceError(code)))
            if code == expected as u8 =>
        {
            ValidationResult::pass(test_name, format!("completion code {code:#04x}"))
        }
        Err(AuthorizedCommandError::Command(CaliptraApiError::DeviceError(code))) => {
            ValidationResult::fail(
                test_name,
                format!("expected {:#04x}, got {code:#04x}", expected as u8),
            )
        }
        Err(AuthorizedCommandError::Preparation(error)) => {
            ValidationResult::fail(test_name, format!("authorization setup failed: {error}"))
        }
        Err(AuthorizedCommandError::Command(error)) => {
            ValidationResult::fail(test_name, format!("non-device command failure: {error}"))
        }
        Ok(()) => ValidationResult::fail(test_name, "request was unexpectedly accepted"),
    }
}

fn expect_api_completion<T>(
    test_name: &str,
    result: Result<T, CaliptraApiError>,
    expected: CaliptraVdmCompletionCode,
) -> ValidationResult {
    match result {
        Err(CaliptraApiError::DeviceError(code)) if code == expected as u8 => {
            ValidationResult::pass(test_name, format!("completion code {code:#04x}"))
        }
        Err(CaliptraApiError::DeviceError(code)) => ValidationResult::fail(
            test_name,
            format!("expected {:#04x}, got {code:#04x}", expected as u8),
        ),
        Err(error) => {
            ValidationResult::fail(test_name, format!("non-device command failure: {error}"))
        }
        Ok(_) => ValidationResult::fail(test_name, "request was unexpectedly accepted"),
    }
}

fn run_fe_prog_tamper_test<F>(
    client: &mut SpdmVdmClient,
    authorizer: &dyn CommandAuthChallengeSigner,
    test_name: &str,
    signed_partition: u32,
    submitted_partition: u32,
    mutate: F,
) -> ValidationResult
where
    F: FnOnce(&mut AuthorizedCommandAuthorization),
{
    let payload = signed_partition.to_le_bytes();
    let mut auth = match authorize_command(
        client,
        MC_FE_PROG_CANONICAL_CMD_ID,
        &payload,
        Some(authorizer),
    ) {
        Ok(auth) => auth,
        Err(error) => return ValidationResult::fail(test_name, error),
    };
    mutate(&mut auth);
    expect_api_completion(
        test_name,
        client.fe_prog(
            submitted_partition,
            &auth.sig,
            &auth.nonce,
            &auth.ecc_pub_x,
            &auth.ecc_pub_y,
            &auth.mldsa_pub,
        ),
        CaliptraVdmCompletionCode::AccessDenied,
    )
}

fn run_raw_malformed_request_tests(client: &mut SpdmVdmClient) -> Vec<ValidationResult> {
    let signature_len = core::mem::size_of::<HybridSignature>();
    let mut exact = vec![1, CaliptraVdmCommand::AuthorizedCommand as u8];
    exact.extend_from_slice(&MC_PROVISION_VENDOR_PK_HASH_CANONICAL_CMD_ID.to_le_bytes());
    exact.extend_from_slice(&1u32.to_le_bytes());
    exact.extend_from_slice(&[0xA5; 48]);
    exact.resize(exact.len() + signature_len, 0);

    let missing_signature = exact[..exact.len() - signature_len].to_vec();
    let truncated = exact[..exact.len() - 1].to_vec();
    let mut oversized = exact;
    oversized.push(0);

    [
        (
            "AuthorizedCommand rejects missing signature",
            missing_signature,
        ),
        ("AuthorizedCommand rejects truncated request", truncated),
        ("AuthorizedCommand rejects oversized request", oversized),
    ]
    .into_iter()
    .map(|(name, request)| {
        let mut response = [0u8; 16];
        match client.send_raw_vdm(&request, &mut response) {
            Ok(3)
                if response[..3]
                    == [
                        1,
                        CaliptraVdmCommand::AuthorizedCommand as u8,
                        CaliptraVdmCompletionCode::InvalidPayloadSize as u8,
                    ] =>
            {
                ValidationResult::pass(name, "responder returned InvalidPayloadSize")
            }
            Ok(len) => ValidationResult::fail(
                name,
                format!("unexpected raw response {:02x?}", &response[..len]),
            ),
            Err(error) => ValidationResult::fail(name, format!("transport failure: {error:?}")),
        }
    })
    .collect()
}

pub fn run_fuse_policy_rejection_tests(
    client: &mut SpdmVdmClient,
    authorizer: Option<&dyn CommandAuthChallengeSigner>,
    _verbose: bool,
) -> Vec<ValidationResult> {
    let Some(authorizer) = authorizer else {
        return vec![ValidationResult::skip(
            "Authorized fuse policy rejections",
            "no command authorizer provided",
        )];
    };
    vec![
        expect_completion(
            "ProvisionVendorPkHash rejects invalid slot",
            signed_provision_vendor_pk_hash(client, 16, &[0xA5; 48], authorizer),
            CaliptraVdmCompletionCode::OperationFailed,
        ),
        expect_completion(
            "FuseIncreaseCaliptraMinSvn rejects nonzero reserved flags",
            signed_increase_caliptra_min_svn(client, 1, 1, authorizer),
            CaliptraVdmCompletionCode::InvalidParameter,
        ),
        expect_completion(
            "FuseIncreaseCaliptraMinSvn rejects zero SVN",
            signed_increase_caliptra_min_svn(client, 0, 0, authorizer),
            CaliptraVdmCompletionCode::InvalidParameter,
        ),
        expect_completion(
            "FuseRevokeVendorPubKey rejects nonzero reserved field",
            signed_revoke_vendor_pub_key(client, 1, 1, 0, 0, authorizer),
            CaliptraVdmCompletionCode::InvalidParameter,
        ),
        expect_completion(
            "FuseRevokeVendorPubKey rejects current-boot key",
            signed_revoke_vendor_pub_key(client, 0, 0, 0, 0, authorizer),
            CaliptraVdmCompletionCode::InvalidParameter,
        ),
        expect_completion(
            "FuseRevokeVendorPkHash rejects nonzero reserved field",
            signed_revoke_vendor_pk_hash(client, 1, 1, authorizer),
            CaliptraVdmCompletionCode::InvalidParameter,
        ),
        expect_completion(
            "FuseRevokeVendorPkHash rejects current-boot slot",
            signed_revoke_vendor_pk_hash(client, 0, 0, authorizer),
            CaliptraVdmCompletionCode::InvalidParameter,
        ),
    ]
}

fn run_fuse_suite(
    client: &mut SpdmVdmClient,
    suite: &str,
    authorizer: Option<&dyn CommandAuthChallengeSigner>,
    dot_signer: Option<&dyn HybridMessageSigner>,
    dot_cak: Option<&str>,
    verbose: bool,
) -> Vec<ValidationResult> {
    let Some(authorizer) = authorizer else {
        return vec![ValidationResult::fail(
            suite,
            "no command authorizer provided",
        )];
    };
    let hash = [0xA5; 48];
    let other_hash = [0x5A; 48];
    let mut results = Vec::new();

    results.extend(match suite {
        "dot" => run_dot(client, dot_cak, Some(authorizer), dot_signer, verbose),
        "authorization" => {
            let mut results = run_raw_malformed_request_tests(client);
            results.extend(run_authorization_negative_tests(
                client,
                Some(authorizer),
                verbose,
            ));
            results
        }
        "provision-vendor-pk-hash" => vec![
            expect_completion(
                "PVPK invalid slot",
                signed_provision_vendor_pk_hash(client, 16, &hash, authorizer),
                CaliptraVdmCompletionCode::OperationFailed,
            ),
            expect_success(
                "PVPK programs and reads back slot",
                signed_provision_vendor_pk_hash(client, 1, &hash, authorizer),
            ),
            expect_success(
                "PVPK same hash is idempotent",
                signed_provision_vendor_pk_hash(client, 1, &hash, authorizer),
            ),
            expect_completion(
                "PVPK conflicting hash rejected",
                signed_provision_vendor_pk_hash(client, 1, &other_hash, authorizer),
                CaliptraVdmCompletionCode::OperationFailed,
            ),
        ],
        "provision-owner-pk-hash" => vec![
            expect_completion(
                "POPK rejects zero hash",
                signed_provision_owner_pk_hash(client, &[0; 48], authorizer),
                CaliptraVdmCompletionCode::InvalidParameter,
            ),
            expect_success(
                "POPK programs and reads back hash",
                signed_provision_owner_pk_hash(client, &hash, authorizer),
            ),
            expect_success(
                "POPK same hash is idempotent",
                signed_provision_owner_pk_hash(client, &hash, authorizer),
            ),
            expect_completion(
                "POPK conflicting hash rejected",
                signed_provision_owner_pk_hash(client, &other_hash, authorizer),
                CaliptraVdmCompletionCode::InvalidParameter,
            ),
        ],
        "increase-min-svn" => vec![
            expect_completion(
                "MCMS rejects nonzero reserved flags",
                signed_increase_caliptra_min_svn(client, 1, 5, authorizer),
                CaliptraVdmCompletionCode::InvalidParameter,
            ),
            expect_completion(
                "MCMS rejects zero SVN",
                signed_increase_caliptra_min_svn(client, 0, 0, authorizer),
                CaliptraVdmCompletionCode::InvalidParameter,
            ),
            expect_completion(
                "MCMS rejects SVN above encoding bound",
                signed_increase_caliptra_min_svn(client, 0, 129, authorizer),
                CaliptraVdmCompletionCode::InvalidParameter,
            ),
            expect_completion(
                "MCMS rejects SVN above running firmware",
                signed_increase_caliptra_min_svn(client, 0, 8, authorizer),
                CaliptraVdmCompletionCode::InvalidParameter,
            ),
            expect_success(
                "MCMS increases minimum SVN",
                signed_increase_caliptra_min_svn(client, 0, 5, authorizer),
            ),
            expect_success(
                "MCMS equal SVN is idempotent",
                signed_increase_caliptra_min_svn(client, 0, 5, authorizer),
            ),
            expect_completion(
                "MCMS rejects decrease",
                signed_increase_caliptra_min_svn(client, 0, 4, authorizer),
                CaliptraVdmCompletionCode::InvalidParameter,
            ),
        ],
        "fuse-lock-partition" => vec![
            expect_completion(
                "IFPK rejects invalid partition",
                signed_fuse_lock_partition(client, u32::MAX, authorizer),
                CaliptraVdmCompletionCode::InvalidParameter,
            ),
            expect_success(
                "IFPK locks partition",
                signed_fuse_lock_partition(client, 0x0E, authorizer),
            ),
            expect_success(
                "IFPK same partition is idempotent",
                signed_fuse_lock_partition(client, 0x0E, authorizer),
            ),
        ],
        "revoke-vendor-pub-key" => vec![
            expect_completion(
                "MRVK rejects nonzero reserved field",
                signed_revoke_vendor_pub_key(client, 1, 1, 0, 0, authorizer),
                CaliptraVdmCompletionCode::InvalidParameter,
            ),
            expect_completion(
                "MRVK rejects unprovisioned slot",
                signed_revoke_vendor_pub_key(client, 0, 1, 0, 0, authorizer),
                CaliptraVdmCompletionCode::InvalidParameter,
            ),
            expect_success(
                "MRVK prerequisite slot provisioning",
                signed_provision_vendor_pk_hash(client, 1, &hash, authorizer),
            ),
            expect_completion(
                "MRVK rejects invalid key type",
                signed_revoke_vendor_pub_key(client, 0, 1, 99, 0, authorizer),
                CaliptraVdmCompletionCode::InvalidParameter,
            ),
            expect_completion(
                "MRVK rejects invalid key index",
                signed_revoke_vendor_pub_key(client, 0, 1, 0, 4, authorizer),
                CaliptraVdmCompletionCode::OperationFailed,
            ),
            expect_completion(
                "MRVK rejects current-boot key",
                signed_revoke_vendor_pub_key(client, 0, 0, 0, 0, authorizer),
                CaliptraVdmCompletionCode::InvalidParameter,
            ),
            expect_success(
                "MRVK revokes inactive key",
                signed_revoke_vendor_pub_key(client, 0, 1, 0, 0, authorizer),
            ),
            expect_completion(
                "MRVK rejects last algorithm key",
                signed_revoke_vendor_pub_key(client, 0, 1, 0, 3, authorizer),
                CaliptraVdmCompletionCode::OperationFailed,
            ),
        ],
        "revoke-vendor-pk-hash" => vec![
            expect_completion(
                "RVKH rejects nonzero reserved field",
                signed_revoke_vendor_pk_hash(client, 1, 1, authorizer),
                CaliptraVdmCompletionCode::InvalidParameter,
            ),
            expect_completion(
                "RVKH rejects unprovisioned slot",
                signed_revoke_vendor_pk_hash(client, 0, 1, authorizer),
                CaliptraVdmCompletionCode::OperationFailed,
            ),
            expect_completion(
                "RVKH rejects current-boot slot",
                signed_revoke_vendor_pk_hash(client, 0, 0, authorizer),
                CaliptraVdmCompletionCode::InvalidParameter,
            ),
            expect_success(
                "RVKH prerequisite slot provisioning",
                signed_provision_vendor_pk_hash(client, 1, &hash, authorizer),
            ),
            expect_success(
                "RVKH revokes inactive slot",
                signed_revoke_vendor_pk_hash(client, 0, 1, authorizer),
            ),
            expect_success(
                "RVKH repeated revocation is idempotent",
                signed_revoke_vendor_pk_hash(client, 0, 1, authorizer),
            ),
        ],
        _ => vec![ValidationResult::fail(
            "Authorized fuse suite",
            format!("unknown suite {suite:?}"),
        )],
    });
    results
}

pub fn run_authorization_negative_tests(
    client: &mut SpdmVdmClient,
    authorizer: Option<&dyn CommandAuthChallengeSigner>,
    _verbose: bool,
) -> Vec<ValidationResult> {
    let Some(authorizer) = authorizer else {
        return vec![ValidationResult::skip(
            "AuthorizedCommand negative authorization",
            "no command authorizer provided",
        )];
    };
    let partition = 0u32;
    let payload = partition.to_le_bytes();
    let mut results = Vec::new();

    let challenge = match client.get_auth_challenge() {
        Ok(challenge) => challenge,
        Err(e) => {
            return vec![ValidationResult::fail(
                "AuthorizedCommand bad signature",
                e.to_string(),
            )]
        }
    };
    let valid =
        match authorizer.authorize(MC_FE_PROG_CANONICAL_CMD_ID, &payload, &challenge.challenge) {
            Ok(auth) => auth,
            Err(e) => {
                return vec![ValidationResult::fail(
                    "AuthorizedCommand bad signature",
                    e.to_string(),
                )]
            }
        };
    let (ecc_pub_x, ecc_pub_y, mldsa_pub) = match authorizer.public_keys() {
        Ok(keys) => keys,
        Err(e) => {
            return vec![ValidationResult::fail(
                "AuthorizedCommand public keys",
                e.to_string(),
            )]
        }
    };
    results.push(expect_api_completion(
        "AuthorizedCommand bad signature",
        client.fe_prog(
            partition,
            &HybridSignature::default(),
            &challenge.challenge,
            &ecc_pub_x,
            &ecc_pub_y,
            &mldsa_pub,
        ),
        CaliptraVdmCompletionCode::AccessDenied,
    ));
    results.push(expect_api_completion(
        "AuthorizedCommand reused challenge",
        client.fe_prog(
            partition,
            &valid,
            &challenge.challenge,
            &ecc_pub_x,
            &ecc_pub_y,
            &mldsa_pub,
        ),
        CaliptraVdmCompletionCode::AccessDenied,
    ));

    let wrong_sig = match authorize_command(
        client,
        MC_PROVISION_VENDOR_PK_HASH_CANONICAL_CMD_ID,
        &payload,
        Some(authorizer),
    ) {
        Ok(auth) => auth,
        Err(e) => {
            results.push(ValidationResult::fail(
                "AuthorizedCommand wrong-command signature",
                e,
            ));
            return results;
        }
    };
    results.push(expect_api_completion(
        "AuthorizedCommand wrong-command signature",
        client.fe_prog(
            partition,
            &wrong_sig.sig,
            &wrong_sig.nonce,
            &wrong_sig.ecc_pub_x,
            &wrong_sig.ecc_pub_y,
            &wrong_sig.mldsa_pub,
        ),
        CaliptraVdmCompletionCode::AccessDenied,
    ));
    results.push(run_fe_prog_tamper_test(
        client,
        authorizer,
        "AuthorizedCommand rejects tampered payload",
        0,
        1,
        |_| {},
    ));
    results.push(run_fe_prog_tamper_test(
        client,
        authorizer,
        "AuthorizedCommand rejects unanchored public key",
        0,
        0,
        |auth| auth.ecc_pub_x[0] ^= 1,
    ));
    results.push(run_fe_prog_tamper_test(
        client,
        authorizer,
        "AuthorizedCommand rejects tampered ECC signature",
        0,
        0,
        |auth| auth.sig.ecc_sig_r[0] ^= 1,
    ));
    results.push(run_fe_prog_tamper_test(
        client,
        authorizer,
        "AuthorizedCommand rejects tampered ML-DSA signature",
        0,
        0,
        |auth| auth.sig.mldsa_sig[0] ^= 1,
    ));
    results
}

/// Validate Field Entropy Programming (FE_PROG) via SPDM VDM.
///
/// When a [`CommandAuthChallengeSigner`] is provided, performs the full authorized flow:
/// 1. Request an auth challenge
/// 2. Ask the authorizer to produce the hybrid signature
/// 3. Submit FE_PROG with the signature
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
            Ok(auth) => auth,
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
