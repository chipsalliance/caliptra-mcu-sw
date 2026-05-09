// Licensed under the Apache-2.0 license

//! Cryptographic hash API functions
//!
//! High-level functions for SHA hash operations (SHA384, SHA512).
//!
//! SHA operations use a three-phase pattern:
//! 1. `caliptra_cmd_sha_init` - Initialize hash context with optional initial data
//! 2. `caliptra_cmd_sha_update` - Add more data to the hash (can be called multiple times)
//! 3. `caliptra_cmd_sha_final` - Finalize and get the hash result
//!
//! For convenience, `caliptra_cmd_sha_hash` performs all three steps in one call.

use crate::api::{CaliptraApiError, CaliptraResult};
use caliptra_util_host_command_types::crypto_hash::{
    ShaAlgorithm, ShaFinalRequest, ShaFinalResponse, ShaInitRequest, ShaInitResponse,
    ShaUpdateRequest, ShaUpdateResponse, SHA_CONTEXT_SIZE,
};
use caliptra_util_host_command_types::CaliptraCommandId;
use caliptra_util_host_session::CaliptraSession;

/// Initialize a SHA hash operation
///
/// This starts a new hash context with the specified algorithm and optional initial data.
/// The returned context must be passed to subsequent update or final operations.
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
/// - `algorithm`: Hash algorithm (SHA384 or SHA512)
/// - `data`: Initial data to hash (can be empty)
///
/// # Returns
///
/// - `Ok(ShaInitResponse)` containing the hash context
/// - `Err(CaliptraApiError)` on failure
///
/// # Example
///
/// ```ignore
/// let init_resp = caliptra_cmd_sha_init(&mut session, ShaAlgorithm::Sha384, b"initial data")?;
/// // Use init_resp.context for subsequent operations
/// ```
pub fn caliptra_cmd_sha_init(
    session: &mut CaliptraSession,
    algorithm: ShaAlgorithm,
    data: &[u8],
) -> CaliptraResult<ShaInitResponse> {
    let request = ShaInitRequest::new(algorithm, data);
    session
        .execute_command_with_id(CaliptraCommandId::HashInit, &request)
        .map_err(|_| CaliptraApiError::SessionError("SHA init command execution failed"))
}

/// Update a SHA hash operation with additional data
///
/// This adds more data to an existing hash context. Can be called multiple times
/// to hash data in chunks.
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
/// - `context`: Hash context from previous init or update operation
/// - `data`: Additional data to hash
///
/// # Returns
///
/// - `Ok(ShaUpdateResponse)` containing the updated hash context
/// - `Err(CaliptraApiError)` on failure
///
/// # Example
///
/// ```ignore
/// let update_resp = caliptra_cmd_sha_update(&mut session, &init_resp.context, b"more data")?;
/// // Use update_resp.context for subsequent operations
/// ```
pub fn caliptra_cmd_sha_update(
    session: &mut CaliptraSession,
    context: &[u8; SHA_CONTEXT_SIZE],
    data: &[u8],
) -> CaliptraResult<ShaUpdateResponse> {
    let request = ShaUpdateRequest::new(context, data);
    session
        .execute_command_with_id(CaliptraCommandId::HashUpdate, &request)
        .map_err(|_| CaliptraApiError::SessionError("SHA update command execution failed"))
}

/// Finalize a SHA hash operation and get the result
///
/// This completes the hash operation and returns the final hash value.
/// Optionally, additional data can be included in the final call.
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
/// - `context`: Hash context from previous init or update operation
/// - `data`: Optional final data to include in the hash (can be empty)
///
/// # Returns
///
/// - `Ok(ShaFinalResponse)` containing the hash result
/// - `Err(CaliptraApiError)` on failure
///
/// # Example
///
/// ```ignore
/// let final_resp = caliptra_cmd_sha_final(&mut session, &context, &[])?;
/// let hash = &final_resp.hash[..final_resp.hash_size as usize];
/// ```
pub fn caliptra_cmd_sha_final(
    session: &mut CaliptraSession,
    context: &[u8; SHA_CONTEXT_SIZE],
    data: &[u8],
) -> CaliptraResult<ShaFinalResponse> {
    let request = if data.is_empty() {
        ShaFinalRequest::new(context)
    } else {
        ShaFinalRequest::new_with_data(context, data)
    };
    session
        .execute_command_with_id(CaliptraCommandId::HashFinalize, &request)
        .map_err(|_| CaliptraApiError::SessionError("SHA final command execution failed"))
}

/// Compute a SHA hash in one operation
///
/// This is a convenience function that performs init and final in a single call.
/// Use this for hashing data that fits in a single request.
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
/// - `algorithm`: Hash algorithm (SHA384 or SHA512)
/// - `data`: Data to hash
///
/// # Returns
///
/// - `Ok(ShaFinalResponse)` containing the hash result
/// - `Err(CaliptraApiError)` on failure
///
/// # Example
///
/// ```ignore
/// let resp = caliptra_cmd_sha_hash(&mut session, ShaAlgorithm::Sha384, b"hello world")?;
/// let hash = &resp.hash[..resp.hash_size as usize];
/// println!("SHA384: {:02x?}", hash);
/// ```
pub fn caliptra_cmd_sha_hash(
    session: &mut CaliptraSession,
    algorithm: ShaAlgorithm,
    data: &[u8],
) -> CaliptraResult<ShaFinalResponse> {
    // Initialize with all the data
    let init_resp = caliptra_cmd_sha_init(session, algorithm, data)?;

    // Finalize immediately (no additional data)
    caliptra_cmd_sha_final(session, &init_resp.context, &[])
}
