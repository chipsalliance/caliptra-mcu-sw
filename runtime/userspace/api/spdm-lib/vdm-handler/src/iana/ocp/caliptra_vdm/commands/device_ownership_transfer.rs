// Licensed under the Apache-2.0 license

use caliptra_mcu_common_commands::CaliptraCmdHandler;
use caliptra_mcu_mbox_common::messages::{CommandId, DotDisablePayload, DotLockPayload};
use caliptra_mcu_spdm_codec::vendor_defined::iana::ocp::caliptra::{
    CaliptraCompletionCode, CaliptraVdmCmdResult,
};
use caliptra_mcu_spdm_traits::SpdmPalAlloc;
use zerocopy::FromBytes;

pub const DOT_LOCK_CMD_ID: u32 = CommandId::MC_DOT_LOCK.0;
pub const DOT_DISABLE_CMD_ID: u32 = CommandId::MC_DOT_DISABLE.0;
pub const DOT_UNLOCK_CHALLENGE_CMD_ID: u32 = CommandId::MC_DOT_UNLOCK_CHALLENGE.0;

pub(crate) async fn handle<H, A>(
    commands: &H,
    request: &[u8],
    scratch: &A,
    output: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraCmdHandler,
    A: SpdmPalAlloc,
{
    let Some(subcommand) = request.get(..4) else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    };
    let subcommand =
        u32::from_le_bytes([subcommand[0], subcommand[1], subcommand[2], subcommand[3]]);

    match subcommand {
        DOT_LOCK_CMD_ID => handle_dot_lock(commands, &request[4..], scratch, output).await,
        DOT_DISABLE_CMD_ID => handle_dot_disable(commands, &request[4..], scratch, output).await,
        DOT_UNLOCK_CHALLENGE_CMD_ID => {
            handle_dot_unlock_challenge(commands, &request[4..], scratch, output).await
        }
        _ => CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidParameter),
    }
}

async fn handle_dot_unlock_challenge<H, A>(
    commands: &H,
    request: &[u8],
    scratch: &A,
    output: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraCmdHandler,
    A: SpdmPalAlloc,
{
    if !request.is_empty() {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    }
    let Some((completion, challenge_out)) = output.split_first_mut() else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
    };
    if challenge_out.len() < caliptra_mcu_mbox_common::messages::AUTH_CMD_NONCE_LEN {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
    }

    match commands.dot_unlock_challenge(scratch).await {
        Ok(challenge) => {
            *completion = CaliptraCompletionCode::Success as u8;
            challenge_out[..challenge.len()].copy_from_slice(&challenge);
            CaliptraVdmCmdResult::Response(1 + challenge.len())
        }
        Err(error) => CaliptraVdmCmdResult::Error(super::map_common_completion(error)),
    }
}

async fn handle_dot_disable<H, A>(
    commands: &H,
    request: &[u8],
    scratch: &A,
    output: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraCmdHandler,
    A: SpdmPalAlloc,
{
    let Ok(request) = DotDisablePayload::ref_from_bytes(request) else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    };
    if output.is_empty() {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
    }

    match commands.dot_disable(scratch, request).await {
        Ok(()) => {
            output[0] = CaliptraCompletionCode::Success as u8;
            CaliptraVdmCmdResult::Response(1)
        }
        Err(error) => CaliptraVdmCmdResult::Error(super::map_common_completion(error)),
    }
}

async fn handle_dot_lock<H, A>(
    commands: &H,
    request: &[u8],
    scratch: &A,
    output: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraCmdHandler,
    A: SpdmPalAlloc,
{
    let Ok(request) = DotLockPayload::ref_from_bytes(request) else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    };
    if output.is_empty() {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
    }

    match commands.dot_lock(scratch, request).await {
        Ok(()) => {
            output[0] = CaliptraCompletionCode::Success as u8;
            CaliptraVdmCmdResult::Response(1)
        }
        Err(error) => CaliptraVdmCmdResult::Error(super::map_common_completion(error)),
    }
}
