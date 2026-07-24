// Licensed under the Apache-2.0 license

//! Device Ownership Transfer command APIs.

use super::{CaliptraApiError, CaliptraResult, CommandSession};
use caliptra_mcu_core_util_host_command_types::{
    CaliptraCommandId, GetDotBackupBlobRequest, GetDotBackupBlobResponse,
};

/// Retrieve the current DOT_BLOB for platform/BMC backup.
pub fn caliptra_cmd_get_dot_backup_blob<S>(
    session: &mut S,
) -> CaliptraResult<GetDotBackupBlobResponse>
where
    S: CommandSession,
{
    let request = GetDotBackupBlobRequest {};
    session
        .execute_command_with_id(CaliptraCommandId::GetDotBackupBlob, &request)
        .map_err(|_| CaliptraApiError::SessionError("GetDotBackupBlob command execution failed"))
}
