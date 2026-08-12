// Licensed under the Apache-2.0 license

//! Fuse and Authorized Command API functions
//!
//! High-level functions for challenge-authorized fuse operations.
//!
//! ## Authorization Flow
//!
//! Authorized commands follow a challenge-response pattern:
//! 1. Call `caliptra_cmd_get_auth_challenge` to obtain a one-use 48-byte nonce
//! 2. Sign `cmd_id(BE) || cmd_body || challenge` with ECC P-384 and ML-DSA-87
//! 3. Append the hybrid signature to the authorized command request

use crate::api::{CaliptraApiError, CaliptraResult};
use caliptra_mcu_core_util_host_command_types::fuse::{
    FeProgRequest, FeProgResponse, FuseIncreaseCaliptraMinSvnRequest,
    FuseIncreaseCaliptraMinSvnResponse, FuseRevokeVendorPkHashRequest,
    FuseRevokeVendorPkHashResponse, FuseRevokeVendorPubKeyRequest, FuseRevokeVendorPubKeyResponse,
    GetAuthCmdChallengeRequest, GetAuthCmdChallengeResponse, ProvisionVendorPkHashRequest,
    ProvisionVendorPkHashResponse,
};
use caliptra_mcu_core_util_host_command_types::CaliptraCommandId;
use caliptra_util_host_session::{CaliptraSession, SessionError};

fn map_session_error(error: SessionError, context: &'static str) -> CaliptraApiError {
    match error {
        SessionError::DeviceError(code) => CaliptraApiError::DeviceError(code),
        _ => CaliptraApiError::SessionError(context),
    }
}

/// Request an authorization challenge nonce.
///
/// Returns a 48-byte random challenge that must be included in the signed
/// pre-image for the next authorized command. The challenge is single-use:
/// it is consumed by the device after one authorized command.
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
///
/// # Returns
///
/// - `Ok(GetAuthCmdChallengeResponse)` containing the 48-byte challenge
/// - `Err(CaliptraApiError)` on failure
pub fn caliptra_cmd_get_auth_challenge(
    session: &mut CaliptraSession,
) -> CaliptraResult<GetAuthCmdChallengeResponse> {
    let request = GetAuthCmdChallengeRequest::default();
    session
        .execute_command_with_id(CaliptraCommandId::GetAuthCmdChallenge, &request)
        .map_err(|error| map_session_error(error, "Get auth command challenge execution failed"))
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
        .map_err(|error| map_session_error(error, "FE_PROG command execution failed"))
}

macro_rules! authorized_fuse_api {
    ($fn_name:ident, $request:ty, $response:ty, $command:ident, $error:literal) => {
        pub fn $fn_name(
            session: &mut CaliptraSession,
            request: &$request,
        ) -> CaliptraResult<$response> {
            session
                .execute_command_with_id(CaliptraCommandId::$command, request)
                .map_err(|error| map_session_error(error, $error))
        }
    };
}

authorized_fuse_api!(
    caliptra_cmd_provision_vendor_pk_hash,
    ProvisionVendorPkHashRequest,
    ProvisionVendorPkHashResponse,
    ProvisionVendorPkHash,
    "ProvisionVendorPkHash command execution failed"
);
authorized_fuse_api!(
    caliptra_cmd_fuse_increase_caliptra_min_svn,
    FuseIncreaseCaliptraMinSvnRequest,
    FuseIncreaseCaliptraMinSvnResponse,
    FuseIncreaseCaliptraMinSvn,
    "FuseIncreaseCaliptraMinSvn command execution failed"
);
authorized_fuse_api!(
    caliptra_cmd_fuse_revoke_vendor_pub_key,
    FuseRevokeVendorPubKeyRequest,
    FuseRevokeVendorPubKeyResponse,
    FuseRevokeVendorPubKey,
    "FuseRevokeVendorPubKey command execution failed"
);
authorized_fuse_api!(
    caliptra_cmd_fuse_revoke_vendor_pk_hash,
    FuseRevokeVendorPkHashRequest,
    FuseRevokeVendorPkHashResponse,
    FuseRevokeVendorPkHash,
    "FuseRevokeVendorPkHash command execution failed"
);
