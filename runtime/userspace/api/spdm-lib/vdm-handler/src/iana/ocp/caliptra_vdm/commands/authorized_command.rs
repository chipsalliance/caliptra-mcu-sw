// Licensed under the Apache-2.0 license

//! AUTHORIZED_COMMAND (0x12): dispatches authorization subcommands.

use caliptra_mcu_spdm_traits::SpdmPalAlloc;

use crate::iana::ocp::caliptra_vdm::CaliptraVdmAuthorization;
use caliptra_mcu_spdm_codec::vendor_defined::iana::ocp::caliptra::{
    CaliptraCompletionCode, CaliptraVdmCmdResult,
};

/// MC_GET_AUTH_CMD_CHALLENGE sub-command (`MACC`).
pub const GET_AUTH_CHALLENGE_CMD_ID: u32 = 0x4D41_4343;

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
        GET_AUTH_CHALLENGE_CMD_ID => handle_get_auth_challenge(cmds, payload, scratch, out).await,
        _ => handle_authorized_cmd(cmds, sub_cmd, payload, scratch, out).await,
    }
}

async fn handle_get_auth_challenge<H, A>(
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

    let Some((completion_code, challenge_buf)) = out.split_first_mut() else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
    };

    match cmds.get_auth_challenge(scratch, challenge_buf).await {
        Ok(bytes_written) => {
            *completion_code = CaliptraCompletionCode::Success as u8;
            CaliptraVdmCmdResult::Response(1 + bytes_written)
        }
        Err(code) => CaliptraVdmCmdResult::Error(code),
    }
}

async fn handle_authorized_cmd<H, A>(
    cmds: &H,
    sub_cmd: u32,
    payload: &[u8],
    scratch: &A,
    out: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraVdmAuthorization,
    A: SpdmPalAlloc,
{
    let Some((completion_code, resp_payload)) = out.split_first_mut() else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
    };

    match cmds
        .execute_authorized_command(sub_cmd, payload, scratch, resp_payload)
        .await
    {
        Ok(bytes_written) => {
            *completion_code = CaliptraCompletionCode::Success as u8;
            CaliptraVdmCmdResult::Response(1 + bytes_written)
        }
        Err(code) => CaliptraVdmCmdResult::Error(code),
    }
}
