// Licensed under the Apache-2.0 license

//! SPDM-specific AES-256-GCM encrypt / decrypt via Caliptra CM
//! mailbox commands.
//!
//! Exposes two one-shot functions:
//!
//! * [`spdm_aes_gcm_encrypt`] — init + (update)* + final, producing
//!   ciphertext and a 16-byte authentication tag.
//! * [`spdm_aes_gcm_decrypt`] — init + (update)* + final with tag
//!   verification, producing plaintext.
//!
//! The SPDM init variants (`CM_AES_GCM_SPDM_ENCRYPT_INIT` /
//! `CM_AES_GCM_SPDM_DECRYPT_INIT`) derive key + IV from the CMK
//! handle, SPDM version, and sequence number — matching the
//! SPDM secured-message key schedule.

use core::mem::size_of;
use mcu_error::codes::{INTERNAL_BUG, INVARIANT};
use mcu_error::McuResult;
use zerocopy::{little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::types::{Cmk, CMK_SIZE};
use crate::wire::{
    mbox_execute, pad4, populate_checksum, CMD_CM_AES_GCM_DECRYPT_FINAL,
    CMD_CM_AES_GCM_DECRYPT_UPDATE, CMD_CM_AES_GCM_ENCRYPT_FINAL, CMD_CM_AES_GCM_ENCRYPT_UPDATE,
    CMD_CM_AES_GCM_SPDM_DECRYPT_INIT, CMD_CM_AES_GCM_SPDM_ENCRYPT_INIT, MAX_CMB_DATA_SIZE,
    MBOX_RESP_HEADER_SIZE,
};
use crate::ApiAlloc;

// ---------------------------------------------------------------------------
// Public constants / types
// ---------------------------------------------------------------------------

pub type Aes256GcmTag = [u8; 16];

/// Encrypted AES-GCM context size returned by Caliptra.
pub const AES_GCM_CTX_SIZE: usize = 128;

/// Opaque AES-GCM context returned by SPDM encrypt/decrypt init.
pub type AesGcmCtx<'a, A> = <A as ApiAlloc>::Buf<'a>;

/// Maximum output bytes per update/final (plaintext or ciphertext +
/// possible 16-byte expansion).
const MAX_OUTPUT_SIZE: usize = MAX_CMB_DATA_SIZE + 16;

// ---------------------------------------------------------------------------
// Wire types — SPDM Init (encrypt & decrypt share the same layout)
// ---------------------------------------------------------------------------

/// SPDM encrypt/decrypt init request prefix:
/// `chksum(4) + spdm_flags(4) + spdm_counter(8) + cmk(128) +
/// aad_size(4)`, then `aad[variable]`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct SpdmInitReqPrefix {
    chksum: U32,
    spdm_flags: U32,
    spdm_counter: [u8; 8],
    cmk: [u8; CMK_SIZE],
    aad_size: U32,
}

const _: () = assert!(size_of::<SpdmInitReqPrefix>() == 4 + 4 + 8 + CMK_SIZE + 4);

/// SPDM init response: `chksum(4) + fips(4) + context(128)`.
const SPDM_INIT_RSP_SIZE: usize = MBOX_RESP_HEADER_SIZE + AES_GCM_CTX_SIZE;

// ---------------------------------------------------------------------------
// Wire types — Encrypt Update / Final
// ---------------------------------------------------------------------------

/// Encrypt update / final request prefix:
/// `chksum(4) + context(128) + plaintext_size(4)`, then
/// `plaintext[variable]`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct EncryptDataReqPrefix {
    chksum: U32,
    context: [u8; AES_GCM_CTX_SIZE],
    plaintext_size: U32,
}

const _: () = assert!(size_of::<EncryptDataReqPrefix>() == 4 + AES_GCM_CTX_SIZE + 4);

/// Encrypt update response header:
/// `chksum(4) + fips(4) + context(128) + ciphertext_size(4)`.
const ENCRYPT_UPDATE_RSP_HDR: usize = MBOX_RESP_HEADER_SIZE + AES_GCM_CTX_SIZE + 4;
const ENCRYPT_UPDATE_RSP_MAX: usize = ENCRYPT_UPDATE_RSP_HDR + MAX_OUTPUT_SIZE;

/// Encrypt final response header:
/// `chksum(4) + fips(4) + tag(16) + ciphertext_size(4)`.
const ENCRYPT_FINAL_RSP_HDR: usize = MBOX_RESP_HEADER_SIZE + 16 + 4;
const ENCRYPT_FINAL_RSP_MAX: usize = ENCRYPT_FINAL_RSP_HDR + MAX_OUTPUT_SIZE;

// ---------------------------------------------------------------------------
// Wire types — Decrypt Update / Final
// ---------------------------------------------------------------------------

/// Decrypt update request prefix:
/// `chksum(4) + context(128) + ciphertext_size(4)`, then
/// `ciphertext[variable]`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct DecryptDataReqPrefix {
    chksum: U32,
    context: [u8; AES_GCM_CTX_SIZE],
    ciphertext_size: U32,
}

const _: () = assert!(size_of::<DecryptDataReqPrefix>() == 4 + AES_GCM_CTX_SIZE + 4);

/// Decrypt update response header:
/// `chksum(4) + fips(4) + context(128) + plaintext_size(4)`.
const DECRYPT_UPDATE_RSP_HDR: usize = MBOX_RESP_HEADER_SIZE + AES_GCM_CTX_SIZE + 4;
const DECRYPT_UPDATE_RSP_MAX: usize = DECRYPT_UPDATE_RSP_HDR + MAX_OUTPUT_SIZE;

/// Decrypt final request prefix:
/// `chksum(4) + context(128) + tag_len(4) + tag(16) +
/// ciphertext_size(4)`, then `ciphertext[variable]`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct DecryptFinalReqPrefix {
    chksum: U32,
    context: [u8; AES_GCM_CTX_SIZE],
    tag_len: U32,
    tag: [u8; 16],
    ciphertext_size: U32,
}

const _: () = assert!(size_of::<DecryptFinalReqPrefix>() == 4 + AES_GCM_CTX_SIZE + 4 + 16 + 4);

/// Decrypt final response header:
/// `chksum(4) + fips(4) + tag_verified(4) + plaintext_size(4)`.
const DECRYPT_FINAL_RSP_HDR: usize = MBOX_RESP_HEADER_SIZE + 4 + 4;
const DECRYPT_FINAL_RSP_MAX: usize = DECRYPT_FINAL_RSP_HDR + MAX_OUTPUT_SIZE;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Execute SPDM AES-GCM init (encrypt or decrypt variant).
///
/// Returns the 128-byte encrypted context on success.
async fn spdm_init<'a, A: ApiAlloc>(
    alloc: &'a A,
    cmd: u32,
    cmk: &Cmk,
    spdm_version: u8,
    seq_number: &[u8; 8],
    aad: &[u8],
) -> McuResult<AesGcmCtx<'a, A>> {
    if aad.len() > MAX_CMB_DATA_SIZE {
        return Err(INVARIANT);
    }
    let prefix_len = size_of::<SpdmInitReqPrefix>();
    let wire_len = pad4(prefix_len + aad.len());

    let mut req = alloc.alloc(wire_len)?;
    req.fill(0);
    let pfx = SpdmInitReqPrefix::mut_from_bytes(&mut req[..prefix_len]).map_err(|_| INVARIANT)?;
    // spdm_flags: version in low byte, big-endian seq flag in bit 8
    // For SPDM secured messages the counter is always little-endian,
    // so flag bit 8 = 0.
    pfx.spdm_flags = U32::new(spdm_version as u32);
    pfx.spdm_counter.copy_from_slice(seq_number);
    pfx.cmk.copy_from_slice(&cmk.0);
    pfx.aad_size = U32::new(aad.len() as u32);
    req[prefix_len..prefix_len + aad.len()].copy_from_slice(aad);
    populate_checksum(cmd, &mut req)?;

    let mut rsp = alloc.alloc(SPDM_INIT_RSP_SIZE)?;
    let rsp_len = mbox_execute(cmd, &req, &mut rsp).await?;
    if rsp_len < SPDM_INIT_RSP_SIZE {
        return Err(INTERNAL_BUG);
    }

    let mut ctx = alloc.alloc(AES_GCM_CTX_SIZE)?;
    ctx.copy_from_slice(&rsp[MBOX_RESP_HEADER_SIZE..SPDM_INIT_RSP_SIZE]);
    Ok(ctx)
}

/// Start SPDM AES-256-GCM encryption for one secured message fragment.
pub async fn spdm_aes_gcm_encrypt_init<'a, A: ApiAlloc>(
    alloc: &'a A,
    cmk: &Cmk,
    spdm_version: u8,
    seq_number: &[u8; 8],
    aad: &[u8],
) -> McuResult<AesGcmCtx<'a, A>> {
    spdm_init(
        alloc,
        CMD_CM_AES_GCM_SPDM_ENCRYPT_INIT,
        cmk,
        spdm_version,
        seq_number,
        aad,
    )
    .await
}

/// Start SPDM AES-256-GCM decryption for one secured message fragment.
pub async fn spdm_aes_gcm_decrypt_init<'a, A: ApiAlloc>(
    alloc: &'a A,
    cmk: &Cmk,
    spdm_version: u8,
    seq_number: &[u8; 8],
    aad: &[u8],
) -> McuResult<AesGcmCtx<'a, A>> {
    spdm_init(
        alloc,
        CMD_CM_AES_GCM_SPDM_DECRYPT_INIT,
        cmk,
        spdm_version,
        seq_number,
        aad,
    )
    .await
}

/// Encrypt one chunk (update, not final). Returns bytes written to
/// `out` and the updated context.
pub async fn spdm_aes_gcm_encrypt_update<'a, A: ApiAlloc>(
    alloc: &'a A,
    ctx: &[u8],
    chunk: &[u8],
    out: &mut [u8],
) -> McuResult<(usize, AesGcmCtx<'a, A>)> {
    if ctx.len() != AES_GCM_CTX_SIZE || chunk.len() > MAX_CMB_DATA_SIZE {
        return Err(INVARIANT);
    }
    let prefix_len = size_of::<EncryptDataReqPrefix>();
    let wire_len = pad4(prefix_len + chunk.len());

    let mut req = alloc.alloc(wire_len)?;
    req.fill(0);
    let pfx =
        EncryptDataReqPrefix::mut_from_bytes(&mut req[..prefix_len]).map_err(|_| INVARIANT)?;
    pfx.context.copy_from_slice(ctx);
    pfx.plaintext_size = U32::new(chunk.len() as u32);
    req[prefix_len..prefix_len + chunk.len()].copy_from_slice(chunk);
    populate_checksum(CMD_CM_AES_GCM_ENCRYPT_UPDATE, &mut req)?;

    let mut rsp = alloc.alloc(ENCRYPT_UPDATE_RSP_MAX)?;
    let rsp_len = mbox_execute(CMD_CM_AES_GCM_ENCRYPT_UPDATE, &req, &mut rsp).await?;
    if rsp_len < ENCRYPT_UPDATE_RSP_HDR {
        return Err(INTERNAL_BUG);
    }

    let ct_size_off = MBOX_RESP_HEADER_SIZE + AES_GCM_CTX_SIZE;
    let ct_size = u32::from_le_bytes([
        rsp[ct_size_off],
        rsp[ct_size_off + 1],
        rsp[ct_size_off + 2],
        rsp[ct_size_off + 3],
    ]) as usize;
    if ct_size > MAX_OUTPUT_SIZE || ct_size > out.len() {
        return Err(INVARIANT);
    }

    let ct_start = ENCRYPT_UPDATE_RSP_HDR;
    if ct_start + ct_size > rsp_len {
        return Err(INTERNAL_BUG);
    }
    out[..ct_size].copy_from_slice(&rsp[ct_start..ct_start + ct_size]);

    let mut new_ctx = alloc.alloc(AES_GCM_CTX_SIZE)?;
    new_ctx.copy_from_slice(&rsp[MBOX_RESP_HEADER_SIZE..MBOX_RESP_HEADER_SIZE + AES_GCM_CTX_SIZE]);
    Ok((ct_size, new_ctx))
}

/// Encrypt the final chunk. Returns bytes written and the 16-byte tag.
pub async fn spdm_aes_gcm_encrypt_final<A: ApiAlloc>(
    alloc: &A,
    ctx: &[u8],
    chunk: &[u8],
    out: &mut [u8],
) -> McuResult<(usize, Aes256GcmTag)> {
    if ctx.len() != AES_GCM_CTX_SIZE || chunk.len() > MAX_CMB_DATA_SIZE {
        return Err(INVARIANT);
    }
    let prefix_len = size_of::<EncryptDataReqPrefix>();
    let wire_len = pad4(prefix_len + chunk.len());

    let mut req = alloc.alloc(wire_len)?;
    req.fill(0);
    let pfx =
        EncryptDataReqPrefix::mut_from_bytes(&mut req[..prefix_len]).map_err(|_| INVARIANT)?;
    pfx.context.copy_from_slice(ctx);
    pfx.plaintext_size = U32::new(chunk.len() as u32);
    req[prefix_len..prefix_len + chunk.len()].copy_from_slice(chunk);
    populate_checksum(CMD_CM_AES_GCM_ENCRYPT_FINAL, &mut req)?;

    let mut rsp = alloc.alloc(ENCRYPT_FINAL_RSP_MAX)?;
    let rsp_len = mbox_execute(CMD_CM_AES_GCM_ENCRYPT_FINAL, &req, &mut rsp).await?;
    if rsp_len < ENCRYPT_FINAL_RSP_HDR {
        return Err(INTERNAL_BUG);
    }

    // Parse tag at offset 8
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&rsp[MBOX_RESP_HEADER_SIZE..MBOX_RESP_HEADER_SIZE + 16]);

    let ct_size_off = MBOX_RESP_HEADER_SIZE + 16;
    let ct_size = u32::from_le_bytes([
        rsp[ct_size_off],
        rsp[ct_size_off + 1],
        rsp[ct_size_off + 2],
        rsp[ct_size_off + 3],
    ]) as usize;
    if ct_size > MAX_OUTPUT_SIZE {
        return Err(INTERNAL_BUG);
    }
    if ct_size > out.len() {
        return Err(INVARIANT);
    }

    let ct_start = ENCRYPT_FINAL_RSP_HDR;
    if ct_start + ct_size > rsp_len {
        return Err(INTERNAL_BUG);
    }
    out[..ct_size].copy_from_slice(&rsp[ct_start..ct_start + ct_size]);
    Ok((ct_size, tag))
}

/// Decrypt one chunk (update, not final). Returns bytes written to
/// `out` and the updated context.
pub async fn spdm_aes_gcm_decrypt_update<'a, A: ApiAlloc>(
    alloc: &'a A,
    ctx: &[u8],
    chunk: &[u8],
    out: &mut [u8],
) -> McuResult<(usize, AesGcmCtx<'a, A>)> {
    if ctx.len() != AES_GCM_CTX_SIZE || chunk.len() > MAX_CMB_DATA_SIZE {
        return Err(INVARIANT);
    }
    let prefix_len = size_of::<DecryptDataReqPrefix>();
    let wire_len = pad4(prefix_len + chunk.len());

    let mut req = alloc.alloc(wire_len)?;
    req.fill(0);
    let pfx =
        DecryptDataReqPrefix::mut_from_bytes(&mut req[..prefix_len]).map_err(|_| INVARIANT)?;
    pfx.context.copy_from_slice(ctx);
    pfx.ciphertext_size = U32::new(chunk.len() as u32);
    req[prefix_len..prefix_len + chunk.len()].copy_from_slice(chunk);
    populate_checksum(CMD_CM_AES_GCM_DECRYPT_UPDATE, &mut req)?;

    let mut rsp = alloc.alloc(DECRYPT_UPDATE_RSP_MAX)?;
    let rsp_len = mbox_execute(CMD_CM_AES_GCM_DECRYPT_UPDATE, &req, &mut rsp).await?;
    if rsp_len < DECRYPT_UPDATE_RSP_HDR {
        return Err(INTERNAL_BUG);
    }

    let pt_size_off = MBOX_RESP_HEADER_SIZE + AES_GCM_CTX_SIZE;
    let pt_size = u32::from_le_bytes([
        rsp[pt_size_off],
        rsp[pt_size_off + 1],
        rsp[pt_size_off + 2],
        rsp[pt_size_off + 3],
    ]) as usize;
    if pt_size > MAX_OUTPUT_SIZE || pt_size > out.len() {
        return Err(INVARIANT);
    }

    let pt_start = DECRYPT_UPDATE_RSP_HDR;
    if pt_start + pt_size > rsp_len {
        return Err(INTERNAL_BUG);
    }
    out[..pt_size].copy_from_slice(&rsp[pt_start..pt_start + pt_size]);

    let mut new_ctx = alloc.alloc(AES_GCM_CTX_SIZE)?;
    new_ctx.copy_from_slice(&rsp[MBOX_RESP_HEADER_SIZE..MBOX_RESP_HEADER_SIZE + AES_GCM_CTX_SIZE]);
    Ok((pt_size, new_ctx))
}

/// Decrypt the final chunk with tag verification. Returns bytes
/// written to `out`.
pub async fn spdm_aes_gcm_decrypt_final<A: ApiAlloc>(
    alloc: &A,
    ctx: &[u8],
    tag: &Aes256GcmTag,
    chunk: &[u8],
    out: &mut [u8],
) -> McuResult<usize> {
    if ctx.len() != AES_GCM_CTX_SIZE || chunk.len() > MAX_CMB_DATA_SIZE {
        return Err(INVARIANT);
    }
    let prefix_len = size_of::<DecryptFinalReqPrefix>();
    let wire_len = pad4(prefix_len + chunk.len());

    let mut req = alloc.alloc(wire_len)?;
    req.fill(0);
    let pfx =
        DecryptFinalReqPrefix::mut_from_bytes(&mut req[..prefix_len]).map_err(|_| INVARIANT)?;
    pfx.context.copy_from_slice(ctx);
    pfx.tag_len = U32::new(16);
    pfx.tag.copy_from_slice(tag);
    pfx.ciphertext_size = U32::new(chunk.len() as u32);
    req[prefix_len..prefix_len + chunk.len()].copy_from_slice(chunk);
    populate_checksum(CMD_CM_AES_GCM_DECRYPT_FINAL, &mut req)?;

    let mut rsp = alloc.alloc(DECRYPT_FINAL_RSP_MAX)?;
    let rsp_len = mbox_execute(CMD_CM_AES_GCM_DECRYPT_FINAL, &req, &mut rsp).await?;
    if rsp_len < DECRYPT_FINAL_RSP_HDR {
        return Err(INTERNAL_BUG);
    }

    // tag_verified at offset 8
    let tv = u32::from_le_bytes([rsp[8], rsp[9], rsp[10], rsp[11]]);
    if tv == 0 {
        return Err(INTERNAL_BUG);
    }

    let pt_size_off = MBOX_RESP_HEADER_SIZE + 4;
    let pt_size = u32::from_le_bytes([
        rsp[pt_size_off],
        rsp[pt_size_off + 1],
        rsp[pt_size_off + 2],
        rsp[pt_size_off + 3],
    ]) as usize;
    if pt_size > MAX_OUTPUT_SIZE || pt_size > out.len() {
        return Err(INVARIANT);
    }

    let pt_start = DECRYPT_FINAL_RSP_HDR;
    if pt_start + pt_size > rsp_len {
        return Err(INTERNAL_BUG);
    }
    out[..pt_size].copy_from_slice(&rsp[pt_start..pt_start + pt_size]);
    Ok(pt_size)
}

// ---------------------------------------------------------------------------
// Public one-shot API
// ---------------------------------------------------------------------------

/// Encrypt a message using SPDM-specific AES-256-GCM key/IV
/// derivation.
///
/// Encrypts one secured-message fragment. Callers that need to protect
/// a larger SPDM message must split it at the SPDM chunk layer and call
/// this once per secured fragment.
///
/// Returns `(bytes_written_to_ciphertext, tag)`.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub async fn spdm_aes_gcm_encrypt<A: ApiAlloc>(
    alloc: &A,
    cmk: &Cmk,
    spdm_version: u8,
    seq_number: &[u8; 8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
) -> McuResult<(usize, Aes256GcmTag)> {
    if plaintext.len() > ciphertext.len() || plaintext.len() > MAX_CMB_DATA_SIZE {
        return Err(INVARIANT);
    }
    let ctx = spdm_aes_gcm_encrypt_init(alloc, cmk, spdm_version, seq_number, aad).await?;
    spdm_aes_gcm_encrypt_final(alloc, &ctx, plaintext, ciphertext).await
}

/// Decrypt a message using SPDM-specific AES-256-GCM key/IV
/// derivation with tag verification.
///
/// Decrypts one secured-message fragment. Callers that receive a
/// larger SPDM message must reassemble it at the SPDM chunk layer after
/// decrypting each secured fragment.
///
/// Returns the number of plaintext bytes written.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub async fn spdm_aes_gcm_decrypt<A: ApiAlloc>(
    alloc: &A,
    cmk: &Cmk,
    spdm_version: u8,
    seq_number: &[u8; 8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &Aes256GcmTag,
    plaintext: &mut [u8],
) -> McuResult<usize> {
    if ciphertext.len() > plaintext.len() || ciphertext.len() > MAX_CMB_DATA_SIZE {
        return Err(INVARIANT);
    }
    let ctx = spdm_aes_gcm_decrypt_init(alloc, cmk, spdm_version, seq_number, aad).await?;
    spdm_aes_gcm_decrypt_final(alloc, &ctx, tag, ciphertext, plaintext).await
}
