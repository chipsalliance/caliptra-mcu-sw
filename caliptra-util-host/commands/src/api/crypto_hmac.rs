// Licensed under the Apache-2.0 license

//! Cryptographic HMAC API functions
//!
//! High-level functions for HMAC and HMAC-based KDF operations.
//!
//! HMAC operations:
//! - `caliptra_cmd_hmac` - Compute HMAC-SHA384/SHA512 over data
//!
//! KDF operations:
//! - `caliptra_cmd_hmac_kdf_counter` - Derive a key using HMAC-based KDF in counter mode

use crate::api::{CaliptraApiError, CaliptraResult};
use caliptra_util_host_command_types::crypto_hmac::{
    CmKeyUsage, Cmk, HmacAlgorithm, HmacKdfCounterRequest, HmacKdfCounterResponse, HmacRequest,
    HmacResponse,
};
use caliptra_util_host_command_types::CaliptraCommandId;
use caliptra_util_host_session::CaliptraSession;

/// Compute an HMAC over data
///
/// This computes HMAC-SHA384 or HMAC-SHA512 over the provided data using
/// the specified key.
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
/// - `cmk`: Cryptographic mailbox key (encrypted key handle)
/// - `algorithm`: HMAC algorithm (SHA384 or SHA512)
/// - `data`: Data to compute HMAC over
///
/// # Returns
///
/// - `Ok(HmacResponse)` containing the MAC result
/// - `Err(CaliptraApiError)` on failure
///
/// # Example
///
/// ```ignore
/// let resp = caliptra_cmd_hmac(&mut session, &key, HmacAlgorithm::Sha384, b"message")?;
/// let mac = &resp.mac[..resp.mac_size as usize];
/// println!("HMAC: {:02x?}", mac);
/// ```
pub fn caliptra_cmd_hmac(
    session: &mut CaliptraSession,
    cmk: &Cmk,
    algorithm: HmacAlgorithm,
    data: &[u8],
) -> CaliptraResult<HmacResponse> {
    let request = HmacRequest::new(cmk, algorithm, data);
    session
        .execute_command_with_id(CaliptraCommandId::Hmac, &request)
        .map_err(|_| CaliptraApiError::SessionError("HMAC command execution failed"))
}

/// Derive a key using HMAC-based KDF in counter mode
///
/// This derives a new key from an input key using HMAC-based KDF as specified
/// in NIST SP 800-108. The derived key is returned as an encrypted CMK.
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
/// - `kin`: Input key (encrypted CMK)
/// - `algorithm`: HMAC algorithm to use (SHA384 or SHA512)
/// - `key_usage`: Intended usage for the derived key
/// - `key_size`: Size of the derived key in bytes (32 for AES/MLDSA, 48 for ECDSA/SHA384-HMAC, 64 for SHA512-HMAC)
/// - `label`: Context-specific label for key derivation
///
/// # Returns
///
/// - `Ok(HmacKdfCounterResponse)` containing the derived key (encrypted CMK)
/// - `Err(CaliptraApiError)` on failure
///
/// # Example
///
/// ```ignore
/// let resp = caliptra_cmd_hmac_kdf_counter(
///     &mut session,
///     &master_key,
///     HmacAlgorithm::Sha384,
///     CmKeyUsage::Aes,
///     32,  // 256-bit key = 32 bytes
///     b"encryption key",
/// )?;
/// let derived_key = resp.kout;
/// ```
pub fn caliptra_cmd_hmac_kdf_counter(
    session: &mut CaliptraSession,
    kin: &Cmk,
    algorithm: HmacAlgorithm,
    key_usage: CmKeyUsage,
    key_size: u32,
    label: &[u8],
) -> CaliptraResult<HmacKdfCounterResponse> {
    let request = HmacKdfCounterRequest::new(kin, algorithm, key_usage, key_size, label);
    session
        .execute_command_with_id(CaliptraCommandId::HmacKdfCounter, &request)
        .map_err(|_| CaliptraApiError::SessionError("HMAC KDF counter command execution failed"))
}
