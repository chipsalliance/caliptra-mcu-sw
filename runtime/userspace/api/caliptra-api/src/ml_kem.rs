// Licensed under the Apache-2.0 license

//! `CM_MLKEM_KEY_GEN`, `CM_MLKEM_ENCAPSULATE` and `CM_MLKEM_DECAPSULATE` mailbox commands.
//!
//! These commands perform an ML-KEM key exchange through Caliptra:
//!
//! 1. [`mlkem_key_gen`] — generates an ML-KEM-1024 encapsulation key from a seed CMK.
//! 2. [`mlkem_encapsulate`] — performs encapsulation against the encapsulation key,
//!    producing ciphertext and a shared secret CMK.
//! 3. [`mlkem_decapsulate`] — performs decapsulation using the seed and ciphertext,
//!    recovering the shared secret CMK.

use core::mem::size_of;
use mcu_error::codes::{INTERNAL_BUG, INVARIANT};
use mcu_error::McuResult;
use zerocopy::{little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::types::{CmKeyUsage, Cmk, CMK_SIZE};
use crate::wire::{
    mbox_execute, populate_checksum, CMD_CM_MLKEM_DECAPSULATE, CMD_CM_MLKEM_ENCAPSULATE,
    CMD_CM_MLKEM_KEY_GEN, MBOX_RESP_HEADER_SIZE,
};
use crate::ApiAlloc;

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

/// Size of the ML-KEM-1024 encapsulation key.
pub const CMB_MLKEM_ENCAPS_KEY_SIZE: usize = 1568;

/// Size of the ML-KEM-1024 ciphertext.
pub const CMB_MLKEM_CIPHERTEXT_SIZE: usize = 1568;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Key generation request: `chksum(4) + cmk(128)`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct MlKemKeyGenReq {
    chksum: U32,
    cmk: Cmk,
}

const _: () = assert!(size_of::<MlKemKeyGenReq>() == 4 + CMK_SIZE);

const KEY_GEN_REQ_SIZE: usize = size_of::<MlKemKeyGenReq>();

/// Key generation response: `chksum(4) + fips(4) + encaps_key(1568)`.
const KEY_GEN_RSP_SIZE: usize = MBOX_RESP_HEADER_SIZE + CMB_MLKEM_ENCAPS_KEY_SIZE;

/// Encapsulate request prefix: `chksum(4) + key_usage(4)`, then
/// `encaps_key(1568)`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct MlKemEncapsulateReqPrefix {
    chksum: U32,
    key_usage: U32,
}

const _: () = assert!(size_of::<MlKemEncapsulateReqPrefix>() == 4 + 4);

const ENCAPSULATE_REQ_SIZE: usize =
    size_of::<MlKemEncapsulateReqPrefix>() + CMB_MLKEM_ENCAPS_KEY_SIZE;

/// Encapsulate response: `chksum(4) + fips(4) + ciphertext(1568) + cmk(128)`.
const ENCAPSULATE_RSP_SIZE: usize = MBOX_RESP_HEADER_SIZE + CMB_MLKEM_CIPHERTEXT_SIZE + CMK_SIZE;

/// Decapsulate request prefix: `chksum(4) + key_usage(4) + cmk(128)`, then
/// `ciphertext(1568)`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct MlKemDecapsulateReqPrefix {
    chksum: U32,
    key_usage: U32,
    cmk: Cmk,
}

const _: () = assert!(size_of::<MlKemDecapsulateReqPrefix>() == 4 + 4 + CMK_SIZE);

const DECAPSULATE_REQ_SIZE: usize =
    size_of::<MlKemDecapsulateReqPrefix>() + CMB_MLKEM_CIPHERTEXT_SIZE;

/// Decapsulate response: `chksum(4) + fips(4) + cmk(128)`.
const DECAPSULATE_RSP_SIZE: usize = MBOX_RESP_HEADER_SIZE + CMK_SIZE;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate an ML-KEM-1024 encapsulation key from a seed CMK.
///
/// Writes the encapsulation key (to be sent to the peer for encapsulation).
///
/// * `seed_cmk` — CMK containing ML-KEM seed (seed_d || seed_z, 64 bytes).
/// * `encaps_key` — Output buffer for the 1568-byte encapsulation key.
#[inline(never)]
pub async fn mlkem_key_gen<A: ApiAlloc>(
    alloc: &A,
    seed_cmk: &Cmk,
    encaps_key: &mut [u8],
) -> McuResult<()> {
    if encaps_key.len() != CMB_MLKEM_ENCAPS_KEY_SIZE {
        return Err(INVARIANT);
    }

    let mut req = alloc.alloc(KEY_GEN_REQ_SIZE)?;
    req.fill(0);
    let req_struct =
        MlKemKeyGenReq::mut_from_bytes(&mut req[..KEY_GEN_REQ_SIZE]).map_err(|_| INVARIANT)?;
    req_struct.cmk = *seed_cmk;
    populate_checksum(CMD_CM_MLKEM_KEY_GEN, &mut req)?;

    let mut rsp = alloc.alloc(KEY_GEN_RSP_SIZE)?;
    let rsp_len = mbox_execute(CMD_CM_MLKEM_KEY_GEN, &req, &mut rsp).await?;
    if rsp_len < KEY_GEN_RSP_SIZE {
        return Err(INTERNAL_BUG);
    }

    *encaps_key
        .first_chunk_mut::<CMB_MLKEM_ENCAPS_KEY_SIZE>()
        .ok_or(INVARIANT)? = *rsp
        .get(MBOX_RESP_HEADER_SIZE..)
        .and_then(|s| s.first_chunk::<CMB_MLKEM_ENCAPS_KEY_SIZE>())
        .ok_or(INTERNAL_BUG)?;
    Ok(())
}

/// Perform ML-KEM-1024 encapsulation, producing ciphertext and a shared secret.
///
/// * `key_usage` — intended use of the shared secret CMK (e.g., `Hmac` for
///   SPDM key schedule).
/// * `encaps_key` — the peer's ML-KEM-1024 encapsulation key (1568 bytes).
/// * `ciphertext` — output buffer for the 1568-byte ciphertext (to be sent to
///   the peer).
///
/// Returns a CMK handle to the shared secret.
#[inline(never)]
pub async fn mlkem_encapsulate<A: ApiAlloc>(
    alloc: &A,
    key_usage: CmKeyUsage,
    encaps_key: &[u8],
    ciphertext: &mut [u8],
) -> McuResult<Cmk> {
    if encaps_key.len() != CMB_MLKEM_ENCAPS_KEY_SIZE
        || ciphertext.len() != CMB_MLKEM_CIPHERTEXT_SIZE
    {
        return Err(INVARIANT);
    }

    let mut req = alloc.alloc(ENCAPSULATE_REQ_SIZE)?;
    req.fill(0);
    let prefix_len = size_of::<MlKemEncapsulateReqPrefix>();
    let pfx =
        MlKemEncapsulateReqPrefix::mut_from_bytes(&mut req[..prefix_len]).map_err(|_| INVARIANT)?;
    pfx.key_usage = U32::new(key_usage as u32);
    *req.get_mut(prefix_len..)
        .and_then(|s| s.first_chunk_mut::<CMB_MLKEM_ENCAPS_KEY_SIZE>())
        .ok_or(INVARIANT)? = *encaps_key
        .first_chunk::<CMB_MLKEM_ENCAPS_KEY_SIZE>()
        .ok_or(INVARIANT)?;
    populate_checksum(CMD_CM_MLKEM_ENCAPSULATE, &mut req)?;

    let mut rsp = alloc.alloc(ENCAPSULATE_RSP_SIZE)?;
    let rsp_len = mbox_execute(CMD_CM_MLKEM_ENCAPSULATE, &req, &mut rsp).await?;
    if rsp_len < ENCAPSULATE_RSP_SIZE {
        return Err(INTERNAL_BUG);
    }

    let ct_start = MBOX_RESP_HEADER_SIZE;
    let ct_end = ct_start + CMB_MLKEM_CIPHERTEXT_SIZE;

    *ciphertext
        .first_chunk_mut::<CMB_MLKEM_CIPHERTEXT_SIZE>()
        .ok_or(INVARIANT)? = *rsp
        .get(ct_start..)
        .and_then(|s| s.first_chunk::<CMB_MLKEM_CIPHERTEXT_SIZE>())
        .ok_or(INTERNAL_BUG)?;

    let cmk = Cmk(*rsp
        .get(ct_end..)
        .and_then(|s| s.first_chunk::<CMK_SIZE>())
        .ok_or(INTERNAL_BUG)?);
    Ok(cmk)
}

/// Perform ML-KEM-1024 decapsulation, recovering the shared secret.
///
/// * `key_usage` — intended use of the shared secret CMK (e.g., `Hmac` for
///   SPDM key schedule).
/// * `seed_cmk` — CMK containing ML-KEM seed (seed_d || seed_z, 64 bytes).
/// * `ciphertext` — the 1568-byte ciphertext from the peer.
///
/// Returns a CMK handle to the shared secret.
#[inline(never)]
pub async fn mlkem_decapsulate<A: ApiAlloc>(
    alloc: &A,
    key_usage: CmKeyUsage,
    seed_cmk: &Cmk,
    ciphertext: &[u8],
) -> McuResult<Cmk> {
    if ciphertext.len() != CMB_MLKEM_CIPHERTEXT_SIZE {
        return Err(INVARIANT);
    }

    let mut req = alloc.alloc(DECAPSULATE_REQ_SIZE)?;
    req.fill(0);
    let prefix_len = size_of::<MlKemDecapsulateReqPrefix>();
    let pfx =
        MlKemDecapsulateReqPrefix::mut_from_bytes(&mut req[..prefix_len]).map_err(|_| INVARIANT)?;
    pfx.key_usage = U32::new(key_usage as u32);
    pfx.cmk = *seed_cmk;
    *req.get_mut(prefix_len..)
        .and_then(|s| s.first_chunk_mut::<CMB_MLKEM_CIPHERTEXT_SIZE>())
        .ok_or(INVARIANT)? = *ciphertext
        .first_chunk::<CMB_MLKEM_CIPHERTEXT_SIZE>()
        .ok_or(INVARIANT)?;
    populate_checksum(CMD_CM_MLKEM_DECAPSULATE, &mut req)?;

    let mut rsp = alloc.alloc(DECAPSULATE_RSP_SIZE)?;
    let rsp_len = mbox_execute(CMD_CM_MLKEM_DECAPSULATE, &req, &mut rsp).await?;
    if rsp_len < DECAPSULATE_RSP_SIZE {
        return Err(INTERNAL_BUG);
    }

    let cmk = Cmk(*rsp
        .get(MBOX_RESP_HEADER_SIZE..)
        .and_then(|s| s.first_chunk::<CMK_SIZE>())
        .ok_or(INTERNAL_BUG)?);
    Ok(cmk)
}
