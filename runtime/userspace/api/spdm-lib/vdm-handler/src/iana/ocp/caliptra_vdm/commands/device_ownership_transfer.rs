// Licensed under the Apache-2.0 license

use caliptra_mcu_common_commands::CaliptraCmdHandler;
use caliptra_mcu_mbox_common::messages::{
    CommandId, DotOverrideChallengePayload, DotOverridePayload, DotStatus, DotUnlockPayload,
};
use caliptra_mcu_spdm_codec::vendor_defined::iana::ocp::caliptra::{
    CaliptraCompletionCode, CaliptraVdmCmdResult,
};
use caliptra_mcu_spdm_traits::SpdmPalAlloc;
use zerocopy::{FromBytes, IntoBytes};

pub const DOT_LOCK_CMD_ID: u32 = CommandId::MC_DOT_LOCK.0;
pub const DOT_DISABLE_CMD_ID: u32 = CommandId::MC_DOT_DISABLE.0;
pub const DOT_ROTATE_CMD_ID: u32 = CommandId::MC_DOT_ROTATE.0;
pub const DOT_RECOVERY_CMD_ID: u32 = CommandId::MC_DOT_RECOVERY.0;
pub const DOT_STATUS_CMD_ID: u32 = CommandId::MC_DOT_STATUS.0;
pub const DOT_UNLOCK_CHALLENGE_CMD_ID: u32 = CommandId::MC_DOT_UNLOCK_CHALLENGE.0;
pub const DOT_UNLOCK_CMD_ID: u32 = CommandId::MC_DOT_UNLOCK.0;
pub const GET_DOT_BACKUP_BLOB_CMD_ID: u32 = CommandId::MC_GET_DOT_BACKUP_BLOB.0;
pub const DOT_OVERRIDE_CHALLENGE_CMD_ID: u32 = CommandId::MC_DOT_OVERRIDE_CHALLENGE.0;
pub const DOT_OVERRIDE_CMD_ID: u32 = CommandId::MC_DOT_OVERRIDE.0;

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

    // Protected commands must arrive as AuthorizedCommand(0x12) -> family
    // 0x11. Rejecting them on this native 0x11 path prevents authorization
    // bypass while keeping status, recovery, unlock, and override native.
    match subcommand {
        DOT_LOCK_CMD_ID | DOT_DISABLE_CMD_ID | DOT_ROTATE_CMD_ID | GET_DOT_BACKUP_BLOB_CMD_ID => {
            CaliptraVdmCmdResult::Error(CaliptraCompletionCode::AccessDenied)
        }
        DOT_UNLOCK_CHALLENGE_CMD_ID => {
            handle_dot_unlock_challenge(commands, &request[4..], scratch, output).await
        }
        DOT_STATUS_CMD_ID => handle_dot_status(commands, &request[4..], output).await,
        DOT_RECOVERY_CMD_ID => handle_dot_recovery(commands, &request[4..], scratch, output).await,
        DOT_OVERRIDE_CHALLENGE_CMD_ID => {
            handle_dot_override_challenge(commands, &request[4..], scratch, output).await
        }
        DOT_OVERRIDE_CMD_ID => handle_dot_override(commands, &request[4..], scratch, output).await,
        DOT_UNLOCK_CMD_ID => handle_dot_unlock(commands, &request[4..], scratch, output).await,
        _ => CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidParameter),
    }
}

async fn handle_dot_override<H, A>(
    commands: &H,
    request: &[u8],
    scratch: &A,
    output: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraCmdHandler,
    A: SpdmPalAlloc,
{
    let Ok(request) = DotOverridePayload::ref_from_bytes(request) else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    };
    if output.is_empty() {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
    }
    match commands.dot_override(scratch, request).await {
        Ok(()) => {
            output[0] = CaliptraCompletionCode::Success as u8;
            CaliptraVdmCmdResult::Response(1)
        }
        Err(error) => CaliptraVdmCmdResult::Error(super::map_common_completion(error)),
    }
}

async fn handle_dot_override_challenge<H, A>(
    commands: &H,
    request: &[u8],
    scratch: &A,
    output: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraCmdHandler,
    A: SpdmPalAlloc,
{
    let Ok(request) = DotOverrideChallengePayload::ref_from_bytes(request) else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    };
    let Some((completion, challenge_out)) = output.split_first_mut() else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
    };
    let Some(challenge_out) =
        challenge_out.get_mut(..caliptra_mcu_mbox_common::messages::AUTH_CMD_NONCE_LEN)
    else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
    };
    match commands.dot_override_challenge(scratch, request).await {
        Ok(challenge) => {
            *completion = CaliptraCompletionCode::Success as u8;
            challenge_out.copy_from_slice(&challenge);
            CaliptraVdmCmdResult::Response(1 + challenge_out.len())
        }
        Err(error) => CaliptraVdmCmdResult::Error(super::map_common_completion(error)),
    }
}

async fn handle_dot_recovery<H, A>(
    commands: &H,
    request: &[u8],
    scratch: &A,
    output: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraCmdHandler,
    A: SpdmPalAlloc,
{
    let Ok(blob) = <&[u8; caliptra_mcu_mbox_common::messages::DOT_BLOB_SIZE]>::try_from(request)
    else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    };
    if output.is_empty() {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
    }
    match commands.dot_recovery(scratch, blob).await {
        Ok(()) => {
            output[0] = CaliptraCompletionCode::Success as u8;
            CaliptraVdmCmdResult::Response(1)
        }
        Err(error) => CaliptraVdmCmdResult::Error(super::map_common_completion(error)),
    }
}

async fn handle_dot_status<H>(
    commands: &H,
    request: &[u8],
    output: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraCmdHandler,
{
    if !request.is_empty() {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    }
    let Some((completion, status_out)) = output.split_first_mut() else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
    };
    let Some(status_out) = status_out.get_mut(..core::mem::size_of::<DotStatus>()) else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
    };
    let mut status = DotStatus::default();
    match commands.dot_status(&mut status).await {
        Ok(()) => {
            *completion = CaliptraCompletionCode::Success as u8;
            status_out.copy_from_slice(status.as_bytes());
            CaliptraVdmCmdResult::Response(1 + status_out.len())
        }
        Err(error) => CaliptraVdmCmdResult::Error(super::map_common_completion(error)),
    }
}

async fn handle_dot_unlock<H, A>(
    commands: &H,
    request: &[u8],
    scratch: &A,
    output: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraCmdHandler,
    A: SpdmPalAlloc,
{
    let Ok(request) = DotUnlockPayload::ref_from_bytes(request) else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    };
    if output.is_empty() {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
    }

    match commands.dot_unlock(scratch, request).await {
        Ok(()) => {
            output[0] = CaliptraCompletionCode::Success as u8;
            CaliptraVdmCmdResult::Response(1)
        }
        Err(error) => CaliptraVdmCmdResult::Error(super::map_common_completion(error)),
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
