// Licensed under the Apache-2.0 license

//! Device Ownership Transfer API functions.

use crate::api::{CaliptraApiError, CaliptraResult};
use caliptra_mcu_core_util_host_command_types::device_ownership_transfer::{
    DotChallengeResponse, DotDisableRequest, DotLockRequest, DotOverrideChallengeRequest,
    DotOverrideRequest, DotRecoveryRequest, DotRotateRequest, DotStatusRequest, DotStatusResponse,
    DotTransitionResponse, DotUnlockChallengeRequest, DotUnlockRequest, GetDotBackupBlobRequest,
    GetDotBackupBlobResponse,
};
use caliptra_mcu_core_util_host_command_types::CaliptraCommandId;
use caliptra_util_host_session::{CaliptraSession, SessionError};

fn map_session_error(error: SessionError, context: &'static str) -> CaliptraApiError {
    match error {
        SessionError::DeviceError(code) => CaliptraApiError::DeviceError(code),
        _ => CaliptraApiError::SessionError(context),
    }
}

pub fn caliptra_cmd_dot_lock(
    session: &mut CaliptraSession,
    request: &DotLockRequest,
) -> CaliptraResult<DotTransitionResponse> {
    session
        .execute_command_with_id(CaliptraCommandId::DotLock, request)
        .map_err(|error| map_session_error(error, "DOT_LOCK command execution failed"))
}

pub fn caliptra_cmd_dot_disable(
    session: &mut CaliptraSession,
    request: &DotDisableRequest,
) -> CaliptraResult<DotTransitionResponse> {
    session
        .execute_command_with_id(CaliptraCommandId::DotDisable, request)
        .map_err(|error| map_session_error(error, "DOT_DISABLE command execution failed"))
}

pub fn caliptra_cmd_dot_rotate(
    session: &mut CaliptraSession,
    request: &DotRotateRequest,
) -> CaliptraResult<DotTransitionResponse> {
    session
        .execute_command_with_id(CaliptraCommandId::DotRotate, request)
        .map_err(|error| map_session_error(error, "DOT_ROTATE command execution failed"))
}

pub fn caliptra_cmd_dot_unlock_challenge(
    session: &mut CaliptraSession,
) -> CaliptraResult<DotChallengeResponse> {
    session
        .execute_command_with_id(
            CaliptraCommandId::DotUnlockChallenge,
            &DotUnlockChallengeRequest,
        )
        .map_err(|error| map_session_error(error, "DOT_UNLOCK_CHALLENGE command execution failed"))
}

pub fn caliptra_cmd_dot_unlock(
    session: &mut CaliptraSession,
    request: &DotUnlockRequest,
) -> CaliptraResult<DotTransitionResponse> {
    session
        .execute_command_with_id(CaliptraCommandId::DotUnlock, request)
        .map_err(|error| map_session_error(error, "DOT_UNLOCK command execution failed"))
}

pub fn caliptra_cmd_get_dot_backup_blob(
    session: &mut CaliptraSession,
    request: &GetDotBackupBlobRequest,
) -> CaliptraResult<GetDotBackupBlobResponse> {
    session
        .execute_command_with_id(CaliptraCommandId::GetDotBackupBlob, request)
        .map_err(|error| map_session_error(error, "GET_DOT_BACKUP_BLOB execution failed"))
}

pub fn caliptra_cmd_dot_status(session: &mut CaliptraSession) -> CaliptraResult<DotStatusResponse> {
    session
        .execute_command_with_id(CaliptraCommandId::DotStatus, &DotStatusRequest)
        .map_err(|error| map_session_error(error, "DOT_STATUS command execution failed"))
}

pub fn caliptra_cmd_dot_recovery(
    session: &mut CaliptraSession,
    request: &DotRecoveryRequest,
) -> CaliptraResult<DotTransitionResponse> {
    session
        .execute_command_with_id(CaliptraCommandId::DotRecovery, request)
        .map_err(|error| map_session_error(error, "DOT_RECOVERY command execution failed"))
}

pub fn caliptra_cmd_dot_override_challenge(
    session: &mut CaliptraSession,
    request: &DotOverrideChallengeRequest,
) -> CaliptraResult<DotChallengeResponse> {
    session
        .execute_command_with_id(CaliptraCommandId::DotOverrideChallenge, request)
        .map_err(|error| map_session_error(error, "DOT_OVERRIDE_CHALLENGE execution failed"))
}

pub fn caliptra_cmd_dot_override(
    session: &mut CaliptraSession,
    request: &DotOverrideRequest,
) -> CaliptraResult<DotTransitionResponse> {
    session
        .execute_command_with_id(CaliptraCommandId::DotOverride, request)
        .map_err(|error| map_session_error(error, "DOT_OVERRIDE command execution failed"))
}
