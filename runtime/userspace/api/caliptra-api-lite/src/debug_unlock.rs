// Licensed under the Apache-2.0 license

//! Production Debug Unlock mailbox commands.

use mcu_error::codes::{INTERNAL_BUG, OUT_OF_MEMORY};
use mcu_error::McuResult;

use crate::wire::{
    calc_checksum, mbox_execute, CMD_PRODUCTION_AUTH_DEBUG_UNLOCK_REQ,
    CMD_PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN, MBOX_RESP_HEADER_SIZE,
};
use crate::ApiAlloc;

const REQ_LEN: usize = 12;
const RSP_LEN: usize = MBOX_RESP_HEADER_SIZE + 4 + DEBUG_UNLOCK_CHALLENGE_LEN;

/// Response data length: `unique_device_identifier(32) | challenge(48)`.
pub const DEBUG_UNLOCK_CHALLENGE_LEN: usize = 32 + 48;

/// Mailbox command ID for `PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN`.
pub const PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_CMD: u32 = CMD_PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN;

/// Response buffer length for `PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN`.
pub const PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_RSP_LEN: usize = MBOX_RESP_HEADER_SIZE;

/// Request a production Debug Unlock challenge.
///
/// On success, writes `unique_device_identifier(32) | challenge(48)` into
/// `out` and returns [`DEBUG_UNLOCK_CHALLENGE_LEN`].
#[inline(never)]
pub async fn request_debug_unlock_challenge<A: ApiAlloc>(
    alloc: &A,
    unlock_level: u8,
    out: &mut [u8],
) -> McuResult<usize> {
    if out.len() < DEBUG_UNLOCK_CHALLENGE_LEN {
        return Err(OUT_OF_MEMORY);
    }

    // Request layout: `chksum(4) | length_dwords(4) | unlock_level(1) | reserved(3)`.
    let mut req = alloc.alloc(REQ_LEN)?;
    req.fill(0);
    req[4..8].copy_from_slice(&2u32.to_le_bytes());
    req[8] = unlock_level;
    let checksum = calc_checksum(CMD_PRODUCTION_AUTH_DEBUG_UNLOCK_REQ, &req[4..]);
    req[..4].copy_from_slice(&checksum.to_le_bytes());

    let mut rsp = alloc.alloc(RSP_LEN)?;
    let rsp_len = mbox_execute(CMD_PRODUCTION_AUTH_DEBUG_UNLOCK_REQ, &req, &mut rsp).await?;
    if rsp_len != RSP_LEN {
        return Err(INTERNAL_BUG);
    }

    let challenge = rsp
        .get(MBOX_RESP_HEADER_SIZE + 4..RSP_LEN)
        .ok_or(INTERNAL_BUG)?;
    out[..DEBUG_UNLOCK_CHALLENGE_LEN].copy_from_slice(challenge);
    Ok(DEBUG_UNLOCK_CHALLENGE_LEN)
}
