// Licensed under the Apache-2.0 license

//! GET_DOT_BACKUP_BLOB (0x13): returns the current DOT_BLOB bytes.

use caliptra_mcu_spdm_traits::SpdmPalAlloc;

use crate::iana::ocp::caliptra_vdm::{CaliptraVdmCmdResult, CaliptraVdmCommands};
use caliptra_mcu_spdm_codec::vendor_defined::iana::ocp::caliptra::CaliptraCompletionCode;

/// Fixed DOT_BLOB size authenticated by the ROM DOT flow.
pub(crate) const DOT_BLOB_SIZE: usize = 168;

pub(crate) async fn handle<H, A>(
    cmds: &H,
    req: &[u8],
    scratch: &A,
    out: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraVdmCommands,
    A: SpdmPalAlloc,
{
    if let Err(code) = super::require_empty(req) {
        return CaliptraVdmCmdResult::Error(code);
    }

    let data = match super::write_success(out) {
        Ok(data) => data,
        Err(code) => return CaliptraVdmCmdResult::Error(code),
    };
    if data.len() < DOT_BLOB_SIZE {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
    }

    match cmds
        .get_dot_backup_blob(scratch, &mut data[..DOT_BLOB_SIZE])
        .await
    {
        Ok(bytes_written) if bytes_written == DOT_BLOB_SIZE => {
            CaliptraVdmCmdResult::Response(1 + DOT_BLOB_SIZE)
        }
        Ok(_) => CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidLength),
        Err(code) => CaliptraVdmCmdResult::Error(code),
    }
}
