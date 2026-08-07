// Licensed under the Apache-2.0 license

//! Device Ownership Transfer API functions.

use crate::api::{CaliptraApiError, CaliptraResult};
use caliptra_mcu_core_util_host_command_types::device_ownership_transfer::{
    DotDisableRequest, DotLockRequest, DotTransitionResponse, DotUnlockChallengeRequest,
    DotUnlockChallengeResponse, DotUnlockRequest, GetDotBackupBlobRequest,
    GetDotBackupBlobResponse,
};
use caliptra_mcu_core_util_host_command_types::CaliptraCommandId;
use caliptra_util_host_session::CaliptraSession;

pub fn caliptra_cmd_dot_lock(
    session: &mut CaliptraSession,
    request: &DotLockRequest,
) -> CaliptraResult<DotTransitionResponse> {
    session
        .execute_command_with_id(CaliptraCommandId::DotLock, request)
        .map_err(|_| CaliptraApiError::SessionError("DOT_LOCK command execution failed"))
}

pub fn caliptra_cmd_dot_disable(
    session: &mut CaliptraSession,
    request: &DotDisableRequest,
) -> CaliptraResult<DotTransitionResponse> {
    session
        .execute_command_with_id(CaliptraCommandId::DotDisable, request)
        .map_err(|_| CaliptraApiError::SessionError("DOT_DISABLE command execution failed"))
}

pub fn caliptra_cmd_dot_unlock_challenge(
    session: &mut CaliptraSession,
) -> CaliptraResult<DotUnlockChallengeResponse> {
    session
        .execute_command_with_id(
            CaliptraCommandId::DotUnlockChallenge,
            &DotUnlockChallengeRequest,
        )
        .map_err(|_| {
            CaliptraApiError::SessionError("DOT_UNLOCK_CHALLENGE command execution failed")
        })
}

pub fn caliptra_cmd_dot_unlock(
    session: &mut CaliptraSession,
    request: &DotUnlockRequest,
) -> CaliptraResult<DotTransitionResponse> {
    session
        .execute_command_with_id(CaliptraCommandId::DotUnlock, request)
        .map_err(|_| CaliptraApiError::SessionError("DOT_UNLOCK command execution failed"))
}

pub fn caliptra_cmd_get_dot_backup_blob(
    session: &mut CaliptraSession,
) -> CaliptraResult<GetDotBackupBlobResponse> {
    session
        .execute_command_with_id(
            CaliptraCommandId::GetDotBackupBlob,
            &GetDotBackupBlobRequest,
        )
        .map_err(|_| CaliptraApiError::SessionError("GET_DOT_BACKUP_BLOB command execution failed"))
}
