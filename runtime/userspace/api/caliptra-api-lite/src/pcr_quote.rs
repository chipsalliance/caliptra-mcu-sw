// Licensed under the Apache-2.0 license

//! PCR quote queries via Caliptra mailbox — alloc-backed.

use mcu_error::codes::INVARIANT;
use mcu_error::McuResult;
use zerocopy::{little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::wire::{
    calc_checksum, CMD_QUOTE_PCRS_ECC384, CMD_QUOTE_PCRS_MLDSA87, MBOX_RESP_HEADER_SIZE,
};
use crate::ApiAlloc;

const PCR_VALUE_SIZE: usize = 48;
const NUM_PCRS: usize = 32;
const NONCE_SIZE: usize = 32;
const PCRS_OFFSET: usize = MBOX_RESP_HEADER_SIZE;
const PCRS_SIZE: usize = NUM_PCRS * PCR_VALUE_SIZE;
const NONCE_OFFSET: usize = PCRS_OFFSET + PCRS_SIZE;
const RESET_CTRS_OFFSET: usize = NONCE_OFFSET + NONCE_SIZE;
const RESET_CTRS_SIZE: usize = NUM_PCRS * 4;
const ECC384_DIGEST_OFFSET: usize = RESET_CTRS_OFFSET + RESET_CTRS_SIZE;
const ECC384_DIGEST_SIZE: usize = 48;
const ECC384_SIGNATURE_OFFSET: usize = ECC384_DIGEST_OFFSET + ECC384_DIGEST_SIZE;
const ECC384_SIGNATURE_SIZE: usize = 96;
const MLDSA87_DIGEST_OFFSET: usize = RESET_CTRS_OFFSET + RESET_CTRS_SIZE;
const MLDSA87_DIGEST_SIZE: usize = 64;
const MLDSA87_SIGNATURE_OFFSET: usize = MLDSA87_DIGEST_OFFSET + MLDSA87_DIGEST_SIZE;
const MLDSA87_SIGNATURE_SIZE: usize = 4627;
pub const PCR_QUOTE_ECC384_LEN: usize = ECC384_RSP_SIZE - MBOX_RESP_HEADER_SIZE;
pub const PCR_QUOTE_MLDSA87_LEN: usize = MLDSA87_RSP_SIZE - MBOX_RESP_HEADER_SIZE;
pub const PCR_QUOTE_MAX_LEN: usize = PCR_QUOTE_MLDSA87_LEN;

#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct QuotePcrsReq {
    chksum: U32,
    nonce: [u8; NONCE_SIZE],
}

const REQ_SIZE: usize = core::mem::size_of::<QuotePcrsReq>();
const _: () = assert!(REQ_SIZE == 36);

// Response layout (we don't deserialize the full struct — just extract by offset):
// hdr:        8 bytes (chksum + fips_status)
// pcrs:       32 * 48 = 1536 bytes
// nonce:      32 bytes
// reset_ctrs: 32 * 4 = 128 bytes
// digest:     48 bytes
// sig_r:      48 bytes
// sig_s:      48 bytes
// Total:      1848 bytes
const ECC384_RSP_SIZE: usize = ECC384_SIGNATURE_OFFSET + ECC384_SIGNATURE_SIZE;
const _: () = assert!(ECC384_RSP_SIZE == 1848);
const _: () = assert!(PCR_QUOTE_ECC384_LEN == 1840);

// MLDSA response layout has the same prefix, a 64-byte digest, and a 4627-byte
// signature. The mailbox response struct is 4-byte aligned, so include one
// trailing pad byte to match the Caliptra API response size.
const MLDSA87_RSP_SIZE: usize = align4(MLDSA87_SIGNATURE_OFFSET + MLDSA87_SIGNATURE_SIZE);
const _: () = assert!(MLDSA87_RSP_SIZE == 6396);
const _: () = assert!(PCR_QUOTE_MLDSA87_LEN == 6388);

/// Generate a Caliptra ECC PCR quote into `out`, excluding the mailbox response header.
///
/// The returned payload shape is PCRs, nonce, reset counters, digest, and ECC signature.
#[inline(never)]
pub async fn pcr_quote_ecc384<A: ApiAlloc>(
    alloc: &A,
    nonce: Option<&[u8; NONCE_SIZE]>,
    out: &mut [u8],
) -> McuResult<usize> {
    pcr_quote(alloc, CMD_QUOTE_PCRS_ECC384, nonce, out, ECC384_RSP_SIZE).await
}

/// Generate a Caliptra MLDSA87 PCR quote into `out`, excluding the mailbox response header.
#[inline(never)]
pub async fn pcr_quote_mldsa87<A: ApiAlloc>(
    alloc: &A,
    nonce: Option<&[u8; NONCE_SIZE]>,
    out: &mut [u8],
) -> McuResult<usize> {
    pcr_quote(alloc, CMD_QUOTE_PCRS_MLDSA87, nonce, out, MLDSA87_RSP_SIZE).await
}

async fn pcr_quote<A: ApiAlloc>(
    alloc: &A,
    cmd: u32,
    nonce: Option<&[u8; NONCE_SIZE]>,
    out: &mut [u8],
    rsp_size: usize,
) -> McuResult<usize> {
    let quote_len = rsp_size
        .checked_sub(MBOX_RESP_HEADER_SIZE)
        .ok_or(INVARIANT)?;
    if out.len() < quote_len {
        return Err(INVARIANT);
    }

    let mut req = alloc.alloc(REQ_SIZE)?;
    req.fill(0);
    match nonce {
        Some(nonce) => req[4..4 + NONCE_SIZE].copy_from_slice(nonce),
        None => crate::rng_generate(alloc, &mut req[4..4 + NONCE_SIZE]).await?,
    }
    let checksum = calc_checksum(cmd, &req[4..]);
    req[..4].copy_from_slice(&checksum.to_le_bytes());

    let mut rsp = alloc.alloc(rsp_size)?;
    let rsp_len = crate::wire::mbox_execute(cmd, &req, &mut rsp).await?;
    if rsp_len < rsp_size {
        return Err(INVARIANT);
    }

    if rsp[NONCE_OFFSET..NONCE_OFFSET + NONCE_SIZE] != req[4..4 + NONCE_SIZE] {
        return Err(INVARIANT);
    }

    out[..quote_len].copy_from_slice(&rsp[MBOX_RESP_HEADER_SIZE..rsp_size]);
    Ok(quote_len)
}

const fn align4(value: usize) -> usize {
    (value + 3) & !3
}
