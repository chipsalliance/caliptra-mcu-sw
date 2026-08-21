// Licensed under the Apache-2.0 license

//! Transport-neutral Caliptra PCR quote evidence format.

use mcu_caliptra_api::{
    pcr_quote_ecc384, pcr_quote_mldsa87, ApiAlloc, PCR_QUOTE_MAX_BUF_LEN, PCR_QUOTE_MAX_LEN,
};
use mcu_error::McuResult;

pub const PCR_QUOTE_MAX_SIZE: usize = PCR_QUOTE_MAX_LEN;
/// Buffer capacity `encode_pcr_quote` requires in `out`, which exceeds
/// [`PCR_QUOTE_MAX_SIZE`] by the mailbox response header. Callers allocating a
/// quote buffer must size it with this, not with `PCR_QUOTE_MAX_SIZE`.
pub const PCR_QUOTE_MAX_BUF_SIZE: usize = PCR_QUOTE_MAX_BUF_LEN;
pub const NONCE_LEN: usize = 32;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PcrQuoteAlgorithm {
    Ecc384,
    Mldsa87,
}

/// Encode a Caliptra ECC PCR quote into `out`.
pub async fn encode_pcr_quote<A: ApiAlloc>(
    alloc: &A,
    algorithm: PcrQuoteAlgorithm,
    nonce: Option<&[u8; NONCE_LEN]>,
    out: &mut [u8],
) -> McuResult<usize> {
    match algorithm {
        PcrQuoteAlgorithm::Ecc384 => pcr_quote_ecc384(alloc, nonce, out).await,
        PcrQuoteAlgorithm::Mldsa87 => pcr_quote_mldsa87(alloc, nonce, out).await,
    }
}
