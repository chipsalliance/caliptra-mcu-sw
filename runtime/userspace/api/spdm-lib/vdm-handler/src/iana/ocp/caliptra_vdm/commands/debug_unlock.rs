// Licensed under the Apache-2.0 license

//! Production debug unlock VDM commands.

use caliptra_mcu_spdm_traits::SpdmPalAlloc;

use crate::iana::ocp::caliptra_vdm::{
    CaliptraCompletionCode, CaliptraVdmCmdResult, CaliptraVdmCommands,
};

pub(crate) async fn handle_request_debug_unlock<H, A>(
    cmds: &H,
    req: &[u8],
    scratch: &A,
    out: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraVdmCommands,
    A: SpdmPalAlloc,
{
    const REQUEST_LENGTH_DWORDS: u32 = 2;
    const RESPONSE_LENGTH_DWORDS: u32 = 21;

    let &[length_0, length_1, length_2, length_3, unlock_level, _, _, _] = req else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    };
    let length = u32::from_le_bytes([length_0, length_1, length_2, length_3]);
    if length != REQUEST_LENGTH_DWORDS {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    }

    let data = match super::write_success(out) {
        Ok(data) => data,
        Err(code) => return CaliptraVdmCmdResult::Error(code),
    };
    let Some((length_out, challenge_out)) = data.split_at_mut_checked(core::mem::size_of::<u32>())
    else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
    };

    match cmds
        .request_debug_unlock(unlock_level, scratch, challenge_out)
        .await
    {
        Ok(n) => {
            length_out.copy_from_slice(&RESPONSE_LENGTH_DWORDS.to_le_bytes());
            CaliptraVdmCmdResult::Response(1 + length_out.len() + n)
        }
        Err(code) => CaliptraVdmCmdResult::Error(code),
    }
}

pub(crate) async fn handle_authorize_debug_unlock_token<H, A>(
    cmds: &H,
    req: &[u8],
    scratch: &A,
    out: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraVdmCommands,
    A: SpdmPalAlloc,
{
    match cmds.authorize_debug_unlock_token(req, scratch).await {
        Ok(()) => match super::write_success(out) {
            Ok(_) => CaliptraVdmCmdResult::Response(1),
            Err(code) => CaliptraVdmCmdResult::Error(code),
        },
        Err(code) => CaliptraVdmCmdResult::Error(code),
    }
}
