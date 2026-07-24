// Licensed under the Apache-2.0 license

//! DEVICE_OWNERSHIP_TRANSFER (0x11): dispatches DOT subcommands.

use caliptra_mcu_spdm_traits::SpdmPalAlloc;

use crate::iana::ocp::caliptra_vdm::{CaliptraVdmAuthorization, CaliptraVdmCmdResult};
use caliptra_mcu_spdm_codec::vendor_defined::iana::ocp::caliptra::CaliptraCompletionCode;

/// MC_GET_DOT_BACKUP_BLOB sub-command (`MDOT`).
pub const GET_DOT_BACKUP_BLOB_CMD_ID: u32 = 0x4D44_4F54;
/// Fixed DOT_BLOB size authenticated by the ROM DOT flow.
pub(crate) const DOT_BLOB_SIZE: usize = 168;

pub(crate) async fn handle<H, A>(
    cmds: &H,
    req: &[u8],
    scratch: &A,
    out: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraVdmAuthorization,
    A: SpdmPalAlloc,
{
    let Some(sub_cmd_bytes) = req.get(..4) else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    };
    let sub_cmd = u32::from_le_bytes([
        sub_cmd_bytes[0],
        sub_cmd_bytes[1],
        sub_cmd_bytes[2],
        sub_cmd_bytes[3],
    ]);
    let payload = &req[4..];

    match sub_cmd {
        GET_DOT_BACKUP_BLOB_CMD_ID => handle_get_dot_backup_blob(cmds, payload, scratch, out).await,
        _ => CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidParameter),
    }
}

async fn handle_get_dot_backup_blob<H, A>(
    cmds: &H,
    req: &[u8],
    scratch: &A,
    out: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraVdmAuthorization,
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
