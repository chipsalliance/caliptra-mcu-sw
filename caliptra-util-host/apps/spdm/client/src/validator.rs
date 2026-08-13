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
use caliptra_mcu_command_auth_challenge_signer::CommandAuthChallengeSigner;
use caliptra_mcu_core_util_host_command_types::certificate::AttestedCsrValidationError;
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

const IMPLEMENTED_AUTHORIZED_SUBCOMMANDS: u32 =
    (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7);

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
    verbose: bool,
) -> Vec<ValidationResult> {
    if let Some(suite) = config.validation.fuse_suite.as_deref() {
        return run_fuse_suite(client, suite, command_authorizer, verbose);
    }

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

struct AuthorizedCommandAuthorization {
    sig: HybridSignature,
    nonce: [u8; AUTH_CMD_NONCE_LEN],
    ecc_pub_x: [u8; 48],
    ecc_pub_y: [u8; 48],
    mldsa_pub: [u8; 2592],
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
    match client.provision_vendor_pk_hash(
        slot,
        &hash,
        &auth.sig,
        &auth.nonce,
        &auth.ecc_pub_x,
        &auth.ecc_pub_y,
        &auth.mldsa_pub,
    ) {
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
    match client.fuse_increase_caliptra_min_svn(
        flags,
        svn,
        &auth.sig,
        &auth.nonce,
        &auth.ecc_pub_x,
        &auth.ecc_pub_y,
        &auth.mldsa_pub,
    ) {
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
        &auth.sig,
        &auth.nonce,
        &auth.ecc_pub_x,
        &auth.ecc_pub_y,
        &auth.mldsa_pub,
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
    match client.fuse_revoke_vendor_pk_hash(
        reserved,
        slot,
        &auth.sig,
        &auth.nonce,
        &auth.ecc_pub_x,
        &auth.ecc_pub_y,
        &auth.mldsa_pub,
    ) {
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
        .provision_vendor_pk_hash(
            slot,
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
        .fuse_increase_caliptra_min_svn(
            flags,
            svn,
            &auth.sig,
            &auth.nonce,
            &auth.ecc_pub_x,
            &auth.ecc_pub_y,
            &auth.mldsa_pub,
        )
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
        .fuse_revoke_vendor_pub_key(
            reserved,
            slot,
            key_type,
            key_index,
            &auth.sig,
            &auth.nonce,
            &auth.ecc_pub_x,
            &auth.ecc_pub_y,
            &auth.mldsa_pub,
        )
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
        .fuse_revoke_vendor_pk_hash(
            reserved,
            slot,
            &auth.sig,
            &auth.nonce,
            &auth.ecc_pub_x,
            &auth.ecc_pub_y,
            &auth.mldsa_pub,
        )
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

fn run_authorized_subcommand_capability_test(client: &mut SpdmVdmClient) -> ValidationResult {
    match client.get_device_capabilities() {
        Ok(capabilities) => {
            let advertised = capabilities.authorized_subcommand_capabilities();
            if advertised & IMPLEMENTED_AUTHORIZED_SUBCOMMANDS == IMPLEMENTED_AUTHORIZED_SUBCOMMANDS
            {
                ValidationResult::pass(
                    "Authorized fuse capability advertisement",
                    format!("authorized_subcommands={advertised:#010x}"),
                )
            } else {
                ValidationResult::fail(
                    "Authorized fuse capability advertisement",
                    format!(
                        "expected bits {IMPLEMENTED_AUTHORIZED_SUBCOMMANDS:#010x}, got {advertised:#010x}"
                    ),
                )
            }
        }
        Err(error) => ValidationResult::fail(
            "Authorized fuse capability advertisement",
            format!("GetDeviceCapabilities failed: {error}"),
        ),
    }
}

fn run_fuse_suite(
    client: &mut SpdmVdmClient,
    suite: &str,
    authorizer: Option<&dyn CommandAuthChallengeSigner>,
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
    let mut results = vec![run_authorized_subcommand_capability_test(client)];

    results.extend(match suite {
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
