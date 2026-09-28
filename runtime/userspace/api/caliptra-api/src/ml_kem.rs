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

use caliptra_api::mailbox::{
    CmMlkemDecapsulateReq, CmMlkemDecapsulateResp, CmMlkemEncapsulateReq, CmMlkemEncapsulateResp,
    CmMlkemKeyGenReq,
};
pub use caliptra_api::mailbox::{MLKEM1024_CIPHERTEXT_SIZE, MLKEM1024_ENCAPS_KEY_SIZE};
use core::mem::size_of;
use mcu_error::codes::{INTERNAL_BUG, INVARIANT};
use mcu_error::McuResult;
use zerocopy::FromBytes;

use crate::types::{CmKeyUsage, Cmk, CMK_SIZE};
use crate::wire::{
    mbox_execute, populate_checksum, CMD_CM_MLKEM_DECAPSULATE, CMD_CM_MLKEM_ENCAPSULATE,
    CMD_CM_MLKEM_KEY_GEN, MBOX_RESP_HEADER_SIZE,
};
use crate::ApiAlloc;

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

const KEY_GEN_REQ_SIZE: usize = size_of::<CmMlkemKeyGenReq>();

const KEY_GEN_RSP_SIZE: usize = MBOX_RESP_HEADER_SIZE + MLKEM1024_ENCAPS_KEY_SIZE;

const ENCAPSULATE_REQ_SIZE: usize = size_of::<CmMlkemEncapsulateReq>();

const ENCAPSULATE_RSP_SIZE: usize = size_of::<CmMlkemEncapsulateResp>();

const DECAPSULATE_REQ_SIZE: usize = size_of::<CmMlkemDecapsulateReq>();

const DECAPSULATE_RSP_SIZE: usize = size_of::<CmMlkemDecapsulateResp>();

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
    if encaps_key.len() != MLKEM1024_ENCAPS_KEY_SIZE {
        return Err(INVARIANT);
    }

    let mut req = alloc.alloc(KEY_GEN_REQ_SIZE)?;
    req.fill(0);
    let req_struct =
        CmMlkemKeyGenReq::mut_from_bytes(&mut req[..KEY_GEN_REQ_SIZE]).map_err(|_| INVARIANT)?;
    req_struct.cmk = (*seed_cmk).into();
    populate_checksum(CMD_CM_MLKEM_KEY_GEN, &mut req)?;

    let mut rsp = alloc.alloc(KEY_GEN_RSP_SIZE)?;
    let rsp_len = mbox_execute(CMD_CM_MLKEM_KEY_GEN, &req, &mut rsp).await?;
    if rsp_len < KEY_GEN_RSP_SIZE {
        return Err(INTERNAL_BUG);
    }

    *encaps_key
        .first_chunk_mut::<MLKEM1024_ENCAPS_KEY_SIZE>()
        .ok_or(INVARIANT)? = *rsp
        .get(MBOX_RESP_HEADER_SIZE..)
        .and_then(|s| s.first_chunk::<MLKEM1024_ENCAPS_KEY_SIZE>())
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
    if encaps_key.len() != MLKEM1024_ENCAPS_KEY_SIZE
        || ciphertext.len() != MLKEM1024_CIPHERTEXT_SIZE
    {
        return Err(INVARIANT);
    }

    let mut req_buf = alloc.alloc(ENCAPSULATE_REQ_SIZE)?;
    req_buf.fill(0);
    let req = CmMlkemEncapsulateReq::mut_from_bytes(&mut req_buf).map_err(|_| INVARIANT)?;
    req.key_usage = key_usage as u32;
    if encaps_key.len() != req.encaps_key.len() {
        return Err(INTERNAL_BUG);
    }
    req.encaps_key.copy_from_slice(encaps_key);
    populate_checksum(CMD_CM_MLKEM_ENCAPSULATE, &mut req_buf)?;

    let mut rsp_buf = alloc.alloc(ENCAPSULATE_RSP_SIZE)?;
    let rsp_len = mbox_execute(CMD_CM_MLKEM_ENCAPSULATE, &req_buf, &mut rsp_buf).await?;
    if rsp_len < ENCAPSULATE_RSP_SIZE {
        return Err(INTERNAL_BUG);
    }
    let rsp = CmMlkemEncapsulateResp::mut_from_bytes(&mut rsp_buf).map_err(|_| INTERNAL_BUG)?;

    ciphertext
        .first_chunk_mut::<MLKEM1024_CIPHERTEXT_SIZE>()
        .map(|s| s.copy_from_slice(&rsp.ciphertext))
        .ok_or(INVARIANT)?;

    Ok((&rsp.shared_key).into())
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
    if ciphertext.len() != MLKEM1024_CIPHERTEXT_SIZE {
        return Err(INVARIANT);
    }

    let mut req_buf = alloc.alloc(DECAPSULATE_REQ_SIZE)?;
    req_buf.fill(0);
    let req = CmMlkemDecapsulateReq::mut_from_bytes(&mut req_buf).map_err(|_| INTERNAL_BUG)?;
    req.key_usage = key_usage as u32;
    req.cmk = (*seed_cmk).into();
    if ciphertext.len() != req.ciphertext.len() {
        return Err(INTERNAL_BUG);
    }
    req.ciphertext.copy_from_slice(ciphertext);
    populate_checksum(CMD_CM_MLKEM_DECAPSULATE, &mut req_buf)?;

    let mut rsp = alloc.alloc(DECAPSULATE_RSP_SIZE)?;
    let rsp_len = mbox_execute(CMD_CM_MLKEM_DECAPSULATE, &req_buf, &mut rsp).await?;
    if rsp_len < DECAPSULATE_RSP_SIZE {
        return Err(INTERNAL_BUG);
    }

    let cmk = Cmk(*rsp
        .get(MBOX_RESP_HEADER_SIZE..)
        .and_then(|s| s.first_chunk::<CMK_SIZE>())
        .ok_or(INTERNAL_BUG)?);
    Ok(cmk)
}
