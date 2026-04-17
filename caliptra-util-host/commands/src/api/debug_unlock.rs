// Licensed under the Apache-2.0 license

//! Production Debug Unlock API functions
//!
//! High-level functions for production authentication debug unlock operations.
//!
//! - `caliptra_cmd_prod_debug_unlock_req` - Request a debug unlock challenge
//! - `caliptra_cmd_prod_debug_unlock_token` - Submit a debug unlock token

use crate::api::{CaliptraApiError, CaliptraResult};
use caliptra_mcu_core_util_host_command_types::debug_unlock::{
    ProdDebugUnlockReqRequest, ProdDebugUnlockReqResponse, ProdDebugUnlockTokenRequest,
    ProdDebugUnlockTokenResponse,
};
use caliptra_mcu_core_util_host_command_types::CaliptraCommandId;
use caliptra_util_host_session::CaliptraSession;

/// Request a production debug unlock challenge
///
/// Sends a debug unlock request to the device and receives a challenge
/// containing the unique device identifier and a random challenge value.
/// The challenge must be signed and submitted via `caliptra_cmd_prod_debug_unlock_token`.
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
/// - `unlock_level`: The debug unlock level requested
///
/// # Returns
///
/// - `Ok(ProdDebugUnlockReqResponse)` containing the device identifier and challenge
/// - `Err(CaliptraApiError)` on failure
pub fn caliptra_cmd_prod_debug_unlock_req(
    session: &mut CaliptraSession,
    unlock_level: u8,
) -> CaliptraResult<ProdDebugUnlockReqResponse> {
    let request = ProdDebugUnlockReqRequest::new(unlock_level);
    session
        .execute_command_with_id(CaliptraCommandId::ProdDebugUnlockReq, &request)
        .map_err(|_| {
            CaliptraApiError::SessionError(
                "Production debug unlock request command execution failed",
            )
        })
}

/// Submit a production debug unlock token
///
/// Submits a signed token containing the challenge response, ECC and ML-DSA
/// public keys and signatures to complete the debug unlock flow.
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
/// - `request`: The fully populated debug unlock token request
///
/// # Returns
///
/// - `Ok(ProdDebugUnlockTokenResponse)` on successful unlock
/// - `Err(CaliptraApiError)` on failure
pub fn caliptra_cmd_prod_debug_unlock_token(
    session: &mut CaliptraSession,
    request: &ProdDebugUnlockTokenRequest,
) -> CaliptraResult<ProdDebugUnlockTokenResponse> {
    session
        .execute_command_with_id(CaliptraCommandId::ProdDebugUnlockToken, request)
        .map_err(|_| {
            CaliptraApiError::SessionError("Production debug unlock token command execution failed")
        })
}
