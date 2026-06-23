// Licensed under the Apache-2.0 license

//! Device state queries via Caliptra mailbox — alloc-backed.

use mcu_error::codes::INVARIANT;
use mcu_error::McuResult;
use zerocopy::{little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::wire::{calc_checksum, CMD_QUOTE_PCRS_ECC384, MBOX_RESP_HEADER_SIZE};
use crate::ApiAlloc;

const PCR_VALUE_SIZE: usize = 48;
const NUM_PCRS: usize = 32;
const NONCE_SIZE: usize = 32;
pub const PCR_QUOTE_ECC384_LEN: usize = RSP_SIZE - MBOX_RESP_HEADER_SIZE;

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
const RSP_SIZE: usize = MBOX_RESP_HEADER_SIZE
    + (NUM_PCRS * PCR_VALUE_SIZE)
    + NONCE_SIZE
    + (NUM_PCRS * 4)
    + 48
    + 48
    + 48;
const _: () = assert!(RSP_SIZE == 1848);
const _: () = assert!(PCR_QUOTE_ECC384_LEN == 1840);

/// Generate a Caliptra ECC PCR quote into `out`, excluding the mailbox response header.
///
/// The returned bytes match the non-lite `PcrQuote::pcr_quote(..., with_pqc_sig=false)`
/// payload shape: PCRs, nonce, reset counters, digest, and ECC signature.
#[inline(never)]
pub async fn pcr_quote_ecc384<A: ApiAlloc>(
    alloc: &A,
    nonce: Option<&[u8; NONCE_SIZE]>,
    out: &mut [u8],
) -> McuResult<usize> {
    if out.len() < PCR_QUOTE_ECC384_LEN {
        return Err(INVARIANT);
    }

    let mut req = alloc.alloc(REQ_SIZE)?;
    req.fill(0);
    match nonce {
        Some(nonce) => req[4..4 + NONCE_SIZE].copy_from_slice(nonce),
        None => crate::rng_generate(alloc, &mut req[4..4 + NONCE_SIZE]).await?,
    }
    let checksum = calc_checksum(CMD_QUOTE_PCRS_ECC384, &req[4..]);
    req[..4].copy_from_slice(&checksum.to_le_bytes());

    let mut rsp = alloc.alloc(RSP_SIZE)?;
    let rsp_len = crate::wire::mbox_execute(CMD_QUOTE_PCRS_ECC384, &req, &mut rsp).await?;
    if rsp_len < RSP_SIZE {
        return Err(INVARIANT);
    }

    let nonce_offset = MBOX_RESP_HEADER_SIZE + NUM_PCRS * PCR_VALUE_SIZE;
    if rsp[nonce_offset..nonce_offset + NONCE_SIZE] != req[4..4 + NONCE_SIZE] {
        return Err(INVARIANT);
    }

    out[..PCR_QUOTE_ECC384_LEN].copy_from_slice(&rsp[MBOX_RESP_HEADER_SIZE..RSP_SIZE]);
    Ok(PCR_QUOTE_ECC384_LEN)
}

/// Read a single PCR value from the Caliptra QUOTE_PCRS_ECC384 response.
///
/// Allocates the 1848-byte response via `alloc` (never on the async stack).
#[inline(never)]
pub async fn get_pcr_value<A: ApiAlloc>(
    alloc: &A,
    pcr_index: usize,
) -> McuResult<[u8; PCR_VALUE_SIZE]> {
    if pcr_index >= NUM_PCRS {
        return Err(INVARIANT);
    }

    // Build request (zero nonce — we don't verify the quote signature).
    let mut req = alloc.alloc(REQ_SIZE)?;
    req.fill(0);
    let (cs_slot, body): (&mut [u8; 4], &mut [u8]) =
        req.split_first_chunk_mut::<4>().ok_or(INVARIANT)?;
    *cs_slot = calc_checksum(CMD_QUOTE_PCRS_ECC384, body).to_le_bytes();

    // Execute mailbox command.
    let mut rsp = alloc.alloc(RSP_SIZE)?;
    let rsp_len = crate::wire::mbox_execute(CMD_QUOTE_PCRS_ECC384, &req, &mut rsp).await?;

    if rsp_len < RSP_SIZE {
        return Err(INVARIANT);
    }

    // Extract pcrs[pcr_index] from the response as a 48-byte chunk.
    let offset = MBOX_RESP_HEADER_SIZE + pcr_index * PCR_VALUE_SIZE;
    let digest_slot: &[u8; PCR_VALUE_SIZE] = rsp
        .get(offset..offset + PCR_VALUE_SIZE)
        .and_then(|s| s.try_into().ok())
        .ok_or(INVARIANT)?;
    Ok(*digest_slot)
}
