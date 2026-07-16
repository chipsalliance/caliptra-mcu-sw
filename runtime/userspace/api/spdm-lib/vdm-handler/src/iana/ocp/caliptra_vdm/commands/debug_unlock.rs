// Licensed under the Apache-2.0 license

//! Production debug unlock VDM commands.

use caliptra_mcu_common_commands::{
    CaliptraCmdHandler, DebugUnlockChallenge, DEBUG_UNLOCK_CHALLENGE_SIZE,
    DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE,
};
use caliptra_mcu_spdm_traits::SpdmPalAlloc;

use crate::iana::ocp::caliptra_vdm::{CaliptraCompletionCode, CaliptraVdmCmdResult};

pub(crate) async fn handle_request_debug_unlock<H, A>(
    cmds: &H,
    req: &[u8],
    scratch: &A,
    out: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraCmdHandler,
    A: SpdmPalAlloc,
{
    let &[unlock_level] = req else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    };

    let data = match super::write_success(out) {
        Ok(data) => data,
        Err(code) => return CaliptraVdmCmdResult::Error(code),
    };
    let needed = DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE + DEBUG_UNLOCK_CHALLENGE_SIZE;
    if data.len() < needed {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
    }

    let mut challenge = DebugUnlockChallenge::default();
    match cmds
        .request_debug_unlock(scratch, unlock_level, &mut challenge)
        .await
    {
        Ok(()) => {
            data[..DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE]
                .copy_from_slice(&challenge.unique_device_identifier);
            data[DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE..needed].copy_from_slice(&challenge.challenge);
            CaliptraVdmCmdResult::Response(1 + needed)
        }
        Err(code) => CaliptraVdmCmdResult::Error(super::map_common_completion(code)),
    }
}

pub(crate) async fn handle_authorize_debug_unlock_token<H, A>(
    cmds: &H,
    req: &[u8],
    scratch: &A,
    out: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraCmdHandler,
    A: SpdmPalAlloc,
{
    match cmds.authorize_debug_unlock_token(scratch, req).await {
        Ok(()) => match super::write_success(out) {
            Ok(_) => CaliptraVdmCmdResult::Response(1),
            Err(code) => CaliptraVdmCmdResult::Error(code),
        },
        Err(code) => CaliptraVdmCmdResult::Error(super::map_common_completion(code)),
    }
}
