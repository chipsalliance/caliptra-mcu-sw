// Licensed under the Apache-2.0 license

//! `CM_HMAC`, `CM_HKDF_EXTRACT`, and `CM_HKDF_EXPAND` mailbox
//! commands.
//!
//! All three use SHA-384 internally. HKDF extract/expand produce
//! [`Cmk`] handles — actual key material never leaves Caliptra.

use core::mem::size_of;
use mcu_error::codes::{INTERNAL_BUG, INVARIANT};
use mcu_error::McuResult;
use zerocopy::{little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::import::cm_import;
use crate::types::{CmKeyUsage, Cmk, CMK_SIZE};
use crate::wire::{
    mbox_execute, pad4, populate_checksum, CMD_CM_HKDF_EXPAND, CMD_CM_HKDF_EXTRACT, CMD_CM_HMAC,
    CM_HASH_ALGO_SHA384, MAX_CMB_DATA_SIZE, MBOX_RESP_HEADER_SIZE,
};
use crate::ApiAlloc;

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

/// Maximum HMAC output size (SHA-512 digest, though we only use
/// SHA-384 = 48 bytes today).
pub const CMB_HMAC_MAX_SIZE: usize = 64;

// ---------------------------------------------------------------------------
// Wire types — HMAC
// ---------------------------------------------------------------------------

/// HMAC request prefix: `chksum(4) + cmk(128) + hash_algorithm(4) +
/// data_size(4)`, then `data[variable]`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct HmacReqPrefix {
    chksum: U32,
    cmk: [u8; CMK_SIZE],
    hash_algorithm: U32,
    data_size: U32,
}

const _: () = assert!(size_of::<HmacReqPrefix>() == 4 + CMK_SIZE + 4 + 4);

/// HMAC response: `chksum(4) + fips(4) + data_len(4) + mac(≤64)`.
/// Uses the "var-size" response header — the data_len field tells us
/// how many bytes of `mac` are valid.
const HMAC_RSP_SIZE: usize = MBOX_RESP_HEADER_SIZE + 4 + CMB_HMAC_MAX_SIZE;

// ---------------------------------------------------------------------------
// Wire types — HKDF Extract
// ---------------------------------------------------------------------------

/// HKDF Extract request (fixed size, no variable tail):
/// `chksum(4) + hash_algorithm(4) + salt(128) + ikm(128)`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct HkdfExtractReq {
    chksum: U32,
    hash_algorithm: U32,
    salt: [u8; CMK_SIZE],
    ikm: [u8; CMK_SIZE],
}

const _: () = assert!(size_of::<HkdfExtractReq>() == 4 + 4 + CMK_SIZE + CMK_SIZE);

/// Extract response: `chksum(4) + fips(4) + prk(128)`.
const HKDF_EXTRACT_RSP_SIZE: usize = MBOX_RESP_HEADER_SIZE + CMK_SIZE;

// ---------------------------------------------------------------------------
// Wire types — HKDF Expand
// ---------------------------------------------------------------------------

/// HKDF Expand request prefix: `chksum(4) + prk(128) +
/// hash_algorithm(4) + key_usage(4) + key_size(4) + info_size(4)`,
/// then `info[variable]`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct HkdfExpandReqPrefix {
    chksum: U32,
    prk: [u8; CMK_SIZE],
    hash_algorithm: U32,
    key_usage: U32,
    key_size: U32,
    info_size: U32,
}

const _: () = assert!(size_of::<HkdfExpandReqPrefix>() == 4 + CMK_SIZE + 4 + 4 + 4 + 4);

/// Expand response: `chksum(4) + fips(4) + okm(128)`.
const HKDF_EXPAND_RSP_SIZE: usize = MBOX_RESP_HEADER_SIZE + CMK_SIZE;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Salt input for [`hkdf_extract`]: either an existing CMK handle
/// or raw bytes (which are imported automatically).
pub enum HkdfSalt<'a> {
    /// Salt is already a CMK handle.
    Cmk(&'a Cmk),
    /// Raw salt bytes — will be imported via `cm_import` internally.
    Data(&'a [u8]),
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Compute HMAC-SHA384 over `data` using `cmk` as the key.
///
/// Returns up to 48 bytes of MAC in the prefix of `out`.
#[inline(never)]
pub async fn cm_hmac<A: ApiAlloc>(
    alloc: &A,
    cmk: &Cmk,
    data: &[u8],
    out: &mut [u8],
) -> McuResult<usize> {
    if data.len() > MAX_CMB_DATA_SIZE {
        return Err(INVARIANT);
    }
    let prefix_len = size_of::<HmacReqPrefix>();
    let wire_len = pad4(prefix_len + data.len());

    let mut req = alloc.alloc(wire_len)?;
    req.fill(0);
    let pfx = HmacReqPrefix::mut_from_bytes(&mut req[..prefix_len]).map_err(|_| INVARIANT)?;
    pfx.cmk = cmk.0;
    pfx.hash_algorithm = U32::new(CM_HASH_ALGO_SHA384);
    pfx.data_size = U32::new(data.len() as u32);
    req[prefix_len..prefix_len + data.len()].copy_from_slice(data);
    populate_checksum(CMD_CM_HMAC, &mut req)?;

    let mut rsp = alloc.alloc(HMAC_RSP_SIZE)?;
    let rsp_len = mbox_execute(CMD_CM_HMAC, &req, &mut rsp).await?;
    // Minimum response: header(8) + data_len(4) = 12
    if rsp_len < MBOX_RESP_HEADER_SIZE + 4 {
        return Err(INTERNAL_BUG);
    }

    // data_len is at offset 8 (after chksum + fips)
    let data_len = u32::from_le_bytes([rsp[8], rsp[9], rsp[10], rsp[11]]) as usize;
    if data_len > CMB_HMAC_MAX_SIZE || data_len > out.len() {
        return Err(INVARIANT);
    }
    let mac_start = MBOX_RESP_HEADER_SIZE + 4;
    let mac_end = mac_start + data_len;
    if mac_end > rsp_len {
        return Err(INTERNAL_BUG);
    }
    out[..data_len].copy_from_slice(&rsp[mac_start..mac_end]);
    Ok(data_len)
}

/// HKDF-Extract(salt, ikm) → PRK as a CMK handle.
///
/// If `salt` is [`HkdfSalt::Data`], it is first imported into an
/// encrypted CMK blob via `cm_import`.
#[inline(never)]
pub async fn hkdf_extract<A: ApiAlloc>(alloc: &A, salt: HkdfSalt<'_>, ikm: &Cmk) -> McuResult<Cmk> {
    let salt_cmk: Cmk = match salt {
        HkdfSalt::Cmk(c) => *c,
        HkdfSalt::Data(data) => cm_import(alloc, CmKeyUsage::Hmac, data).await?,
    };

    let req_size = size_of::<HkdfExtractReq>();
    let mut req = alloc.alloc(req_size)?;
    req.fill(0);
    let r = HkdfExtractReq::mut_from_bytes(&mut req[..req_size]).map_err(|_| INVARIANT)?;
    r.hash_algorithm = U32::new(CM_HASH_ALGO_SHA384);
    r.salt = salt_cmk.0;
    r.ikm = ikm.0;
    populate_checksum(CMD_CM_HKDF_EXTRACT, &mut req)?;

    let mut rsp = alloc.alloc(HKDF_EXTRACT_RSP_SIZE)?;
    let rsp_len = mbox_execute(CMD_CM_HKDF_EXTRACT, &req, &mut rsp).await?;

    if rsp_len < HKDF_EXTRACT_RSP_SIZE {
        return Err(INTERNAL_BUG);
    }

    let prk = Cmk(*rsp
        .get(MBOX_RESP_HEADER_SIZE..)
        .and_then(|s| s.first_chunk::<CMK_SIZE>())
        .ok_or(INTERNAL_BUG)?);
    Ok(prk)
}

/// HKDF-Expand(prk, info) → OKM as a CMK handle.
#[inline(never)]
pub async fn hkdf_expand<A: ApiAlloc>(
    alloc: &A,
    prk: &Cmk,
    key_usage: CmKeyUsage,
    key_size: u32,
    info: &[u8],
) -> McuResult<Cmk> {
    if info.len() > MAX_CMB_DATA_SIZE {
        return Err(INVARIANT);
    }
    let prefix_len = size_of::<HkdfExpandReqPrefix>();
    let wire_len = pad4(prefix_len + info.len());

    let mut req = alloc.alloc(wire_len)?;
    req.fill(0);
    let pfx = HkdfExpandReqPrefix::mut_from_bytes(&mut req[..prefix_len]).map_err(|_| INVARIANT)?;
    pfx.prk = prk.0;
    pfx.hash_algorithm = U32::new(CM_HASH_ALGO_SHA384);
    pfx.key_usage = U32::new(key_usage as u32);
    pfx.key_size = U32::new(key_size);
    pfx.info_size = U32::new(info.len() as u32);
    req[prefix_len..prefix_len + info.len()].copy_from_slice(info);
    populate_checksum(CMD_CM_HKDF_EXPAND, &mut req)?;

    let mut rsp = alloc.alloc(HKDF_EXPAND_RSP_SIZE)?;
    let rsp_len = mbox_execute(CMD_CM_HKDF_EXPAND, &req, &mut rsp).await?;
    if rsp_len < HKDF_EXPAND_RSP_SIZE {
        return Err(INTERNAL_BUG);
    }

    let okm = Cmk(*rsp
        .get(MBOX_RESP_HEADER_SIZE..)
        .and_then(|s| s.first_chunk::<CMK_SIZE>())
        .ok_or(INTERNAL_BUG)?);
    Ok(okm)
}
