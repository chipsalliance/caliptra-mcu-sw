// Licensed under the Apache-2.0 license

//! Cryptographic Import API function
//!
//! High-level function for importing raw keys to get encrypted CMK handles.
//!
//! Import operations:
//! - `caliptra_cmd_import` - Import a raw key and get an encrypted CMK

use crate::api::{CaliptraApiError, CaliptraResult};
use caliptra_util_host_command_types::crypto_hmac::CmKeyUsage;
use caliptra_util_host_command_types::crypto_import::{ImportRequest, ImportResponse};
use caliptra_util_host_command_types::CaliptraCommandId;
use caliptra_util_host_session::CaliptraSession;

/// Import a raw key and get an encrypted CMK handle
///
/// This imports a raw key into the cryptographic mailbox and returns an
/// encrypted CMK (Cryptographic Mailbox Key) that can be used for HMAC,
/// HKDF, and other cryptographic operations.
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
/// - `key_usage`: Intended usage for the key (Hmac, Aes, etc.)
/// - `key`: Raw key data (up to 64 bytes)
///
/// # Returns
///
/// - `Ok(ImportResponse)` containing the encrypted CMK
/// - `Err(CaliptraApiError)` on failure
///
/// # Example
///
/// ```ignore
/// // Import a key for HMAC operations
/// let key_data = [0x01u8; 32]; // 256-bit key
/// let resp = caliptra_cmd_import(&mut session, CmKeyUsage::Hmac, &key_data)?;
/// let cmk = resp.cmk; // Use this CMK for HMAC operations
/// ```
pub fn caliptra_cmd_import(
    session: &mut CaliptraSession,
    key_usage: CmKeyUsage,
    key: &[u8],
) -> CaliptraResult<ImportResponse> {
    let request = ImportRequest::new(key_usage, key);
    session
        .execute_command_with_id(CaliptraCommandId::Import, &request)
        .map_err(|_| CaliptraApiError::SessionError("Import command execution failed"))
}
