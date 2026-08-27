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
    const REQUEST_LENGTH_DWORDS: u32 = 2;
    let Ok(&[length_0, length_1, length_2, length_3, unlock_level, _, _, _]) =
        <&[u8; 8]>::try_from(req)
    else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    };
    if u32::from_le_bytes([length_0, length_1, length_2, length_3]) != REQUEST_LENGTH_DWORDS {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    }

    let data = match super::write_success(out) {
        Ok(data) => data,
        Err(code) => return CaliptraVdmCmdResult::Error(code),
    };
    const RESPONSE_LENGTH_DWORDS: u32 = 21;
    const LENGTH_SIZE: usize = core::mem::size_of::<u32>();
    let needed = LENGTH_SIZE + DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE + DEBUG_UNLOCK_CHALLENGE_SIZE;
    if data.len() < needed {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
    }

    let mut challenge = DebugUnlockChallenge::default();
    match cmds
        .request_debug_unlock(scratch, unlock_level, &mut challenge)
        .await
    {
        Ok(()) => {
            data[..LENGTH_SIZE].copy_from_slice(&RESPONSE_LENGTH_DWORDS.to_le_bytes());
            data[LENGTH_SIZE..LENGTH_SIZE + DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE]
                .copy_from_slice(&challenge.unique_device_identifier);
            data[LENGTH_SIZE + DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE..needed]
                .copy_from_slice(&challenge.challenge);
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
