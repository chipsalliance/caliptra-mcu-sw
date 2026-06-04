// Licensed under the Apache-2.0 license

//! `CM_ECDH_GENERATE` and `CM_ECDH_FINISH` mailbox commands.
//!
//! These commands perform an ECDH key exchange through Caliptra:
//!
//! 1. [`ecdh_generate`] — generates our ephemeral key pair, returning
//!    an encrypted context and our public exchange data.
//! 2. [`ecdh_finish`] — feeds in the peer's exchange data and the
//!    context, producing a [`Cmk`] handle to the shared secret.

use core::mem::size_of;
use mcu_error::codes::{INTERNAL_BUG, INVARIANT};
use mcu_error::McuResult;
use zerocopy::{little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::types::{CmKeyUsage, Cmk, CMK_SIZE};
use crate::wire::{
    mbox_execute, populate_checksum, CMD_CM_ECDH_FINISH, CMD_CM_ECDH_GENERATE,
    MBOX_RESP_HEADER_SIZE,
};
use crate::ApiAlloc;

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

/// Size of the encrypted ECDH context returned by `ecdh_generate`.
pub const CMB_ECDH_ENCRYPTED_CONTEXT_SIZE: usize = 76;

/// Maximum size of ECDH exchange data (P-384: 48 × 2 = 96 bytes).
pub const CMB_ECDH_EXCHANGE_DATA_MAX_SIZE: usize = 96;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Generate request is just the checksum (no additional fields).
const GENERATE_REQ_SIZE: usize = 4;

/// Generate response: `chksum(4) + fips(4) + context(76) + exchange_data(96)`.
const GENERATE_RSP_SIZE: usize =
    MBOX_RESP_HEADER_SIZE + CMB_ECDH_ENCRYPTED_CONTEXT_SIZE + CMB_ECDH_EXCHANGE_DATA_MAX_SIZE;

/// Finish request prefix: `chksum(4) + context(76) + key_usage(4)`, then
/// `incoming_exchange_data(96)`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct EcdhFinishReqPrefix {
    chksum: U32,
    context: [u8; CMB_ECDH_ENCRYPTED_CONTEXT_SIZE],
    key_usage: U32,
}

const _: () = assert!(size_of::<EcdhFinishReqPrefix>() == 4 + 76 + 4);

const FINISH_REQ_SIZE: usize = size_of::<EcdhFinishReqPrefix>() + CMB_ECDH_EXCHANGE_DATA_MAX_SIZE;

/// Finish response: `chksum(4) + fips(4) + cmk(128)`.
const FINISH_RSP_SIZE: usize = MBOX_RESP_HEADER_SIZE + CMK_SIZE;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate an ephemeral ECDH key pair.
///
/// Writes the encrypted context (needed for [`ecdh_finish`]) and our
/// public exchange data (to be sent to the peer in KEY_EXCHANGE_RSP).
#[inline(never)]
pub async fn ecdh_generate<A: ApiAlloc>(
    alloc: &A,
    context: &mut [u8],
    exchange_data: &mut [u8],
) -> McuResult<()> {
    if context.len() != CMB_ECDH_ENCRYPTED_CONTEXT_SIZE
        || exchange_data.len() != CMB_ECDH_EXCHANGE_DATA_MAX_SIZE
    {
        return Err(INVARIANT);
    }
    let mut req = alloc.alloc(GENERATE_REQ_SIZE)?;
    req.fill(0);
    populate_checksum(CMD_CM_ECDH_GENERATE, &mut req)?;

    let mut rsp = alloc.alloc(GENERATE_RSP_SIZE)?;
    let rsp_len = mbox_execute(CMD_CM_ECDH_GENERATE, &req, &mut rsp).await?;
    if rsp_len < GENERATE_RSP_SIZE {
        return Err(INTERNAL_BUG);
    }

    let ctx_start = MBOX_RESP_HEADER_SIZE;
    let ctx_end = ctx_start + CMB_ECDH_ENCRYPTED_CONTEXT_SIZE;
    let xd_end = ctx_end + CMB_ECDH_EXCHANGE_DATA_MAX_SIZE;

    context.copy_from_slice(&rsp[ctx_start..ctx_end]);
    exchange_data.copy_from_slice(&rsp[ctx_end..xd_end]);
    Ok(())
}

/// Complete the ECDH exchange, producing a CMK handle to the shared
/// secret.
///
/// * `context` — encrypted context from [`ecdh_generate`].
/// * `key_usage` — intended use of the derived key (typically `Hmac`
///   for SPDM key schedule).
/// * `peer_exchange_data` — the peer's public exchange data from
///   KEY_EXCHANGE request.
#[inline(never)]
pub async fn ecdh_finish<A: ApiAlloc>(
    alloc: &A,
    context: &[u8],
    key_usage: CmKeyUsage,
    peer_exchange_data: &[u8],
) -> McuResult<Cmk> {
    if context.len() != CMB_ECDH_ENCRYPTED_CONTEXT_SIZE
        || peer_exchange_data.len() != CMB_ECDH_EXCHANGE_DATA_MAX_SIZE
    {
        return Err(INVARIANT);
    }
    let mut req = alloc.alloc(FINISH_REQ_SIZE)?;
    req.fill(0);
    let prefix_len = size_of::<EcdhFinishReqPrefix>();
    let pfx = EcdhFinishReqPrefix::mut_from_bytes(&mut req[..prefix_len]).map_err(|_| INVARIANT)?;
    pfx.context.copy_from_slice(context);
    pfx.key_usage = U32::new(key_usage as u32);
    req[prefix_len..prefix_len + CMB_ECDH_EXCHANGE_DATA_MAX_SIZE]
        .copy_from_slice(peer_exchange_data);
    populate_checksum(CMD_CM_ECDH_FINISH, &mut req)?;

    let mut rsp = alloc.alloc(FINISH_RSP_SIZE)?;
    let rsp_len = mbox_execute(CMD_CM_ECDH_FINISH, &req, &mut rsp).await?;
    if rsp_len < FINISH_RSP_SIZE {
        return Err(INTERNAL_BUG);
    }

    let mut cmk = Cmk::default();
    cmk.0
        .copy_from_slice(&rsp[MBOX_RESP_HEADER_SIZE..FINISH_RSP_SIZE]);
    Ok(cmk)
}
