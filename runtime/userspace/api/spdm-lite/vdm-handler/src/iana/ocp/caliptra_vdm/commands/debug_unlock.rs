// Licensed under the Apache-2.0 license

//! Production debug unlock VDM commands.

use mcu_spdm_lite_traits::SpdmPalAlloc;

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
    // Decode only the required unlock-level byte. Missing data is an invalid
    // payload; extra bytes are ignored by the command handler.
    let Some(&unlock_level) = req.first() else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    };
    let data = match super::write_success(out) {
        Ok(data) => data,
        Err(code) => return CaliptraVdmCmdResult::Error(code),
    };
    match cmds.request_debug_unlock(unlock_level, scratch, data).await {
        Ok(n) => CaliptraVdmCmdResult::Response(1 + n),
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
