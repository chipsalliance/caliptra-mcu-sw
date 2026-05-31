// Licensed under the Apache-2.0 license

//! Fuse and Authorized Command API functions
//!
//! High-level functions for authorized command operations including
//! field entropy programming (FE_PROG).
//!
//! ## Authorization Flow
//!
//! Authorized commands follow a challenge-response pattern:
//! 1. Call `caliptra_cmd_get_auth_challenge` to obtain a 32-byte nonce
//! 2. Compute HMAC-SHA384 over `cmd_id(BE) || cmd_body || challenge`
//! 3. Call the authorized command (e.g., `caliptra_cmd_fe_prog`) which
//!    internally appends the MAC to the request

use crate::api::{CaliptraApiError, CaliptraResult};
use caliptra_mcu_core_util_host_command_types::fuse::{
    FeProgRequest, FeProgResponse, GetAuthCmdChallengeRequest, GetAuthCmdChallengeResponse,
};
use caliptra_mcu_core_util_host_command_types::CaliptraCommandId;
use caliptra_util_host_session::CaliptraSession;

/// Request an authorization challenge nonce.
///
/// Returns a 32-byte random challenge that must be included in the HMAC
/// computation for the next authorized command. The challenge is single-use:
/// it is consumed by the device after one authorized command.
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
///
/// # Returns
///
/// - `Ok(GetAuthCmdChallengeResponse)` containing the 32-byte challenge
/// - `Err(CaliptraApiError)` on failure
pub fn caliptra_cmd_get_auth_challenge(
    session: &mut CaliptraSession,
) -> CaliptraResult<GetAuthCmdChallengeResponse> {
    let request = GetAuthCmdChallengeRequest::default();
    session
        .execute_command_with_id(CaliptraCommandId::GetAuthCmdChallenge, &request)
        .map_err(|_| CaliptraApiError::SessionError("Get auth command challenge execution failed"))
}

/// Program field entropy for an OTP partition.
///
/// This is an authorized command. The caller must first obtain a challenge
/// via `caliptra_cmd_get_auth_challenge`, then pass it here. The transport
/// layer handles HMAC computation and MAC appending.
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
/// - `request`: The FE_PROG request containing the partition to program
///
/// # Returns
///
/// - `Ok(FeProgResponse)` on success
/// - `Err(CaliptraApiError)` on failure
pub fn caliptra_cmd_fe_prog(
    session: &mut CaliptraSession,
    request: &FeProgRequest,
) -> CaliptraResult<FeProgResponse> {
    session
        .execute_command_with_id(CaliptraCommandId::FeProg, request)
        .map_err(|_| CaliptraApiError::SessionError("FE_PROG command execution failed"))
}
