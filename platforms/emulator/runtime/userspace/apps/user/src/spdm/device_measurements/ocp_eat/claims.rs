// Licensed under the Apache-2.0 license

//! OCP EAT claims generation — platform-state evidence via byte template.
//!
//! Uses a pre-computed 206-byte CBOR template with two fill slots (nonce,
//! digest). Single async call fetches PCR31; the rest is `copy_from_slice`.

use mcu_caliptra_api_lite::eat::stamp_eat_payload;
use mcu_caliptra_api_lite::pcr_quote_digest;
use mcu_error::McuResult;
use mcu_spdm_lite_pal::BitmapAllocator;

/// PCR index for the aggregate platform state measurement.
const PLATFORM_STATE_PCR_INDEX: usize = 31;

/// Generates EAT claims CBOR payload into `claims_buf`.
///
/// Flow:
/// 1. Fetch PCR31 digest via alloc-backed mailbox (only async call)
/// 2. Stamp the byte template with nonce and digest (two memcpys)
pub async fn generate_claims(
    alloc: &BitmapAllocator,
    claims_buf: &mut [u8],
    nonce: &[u8],
) -> McuResult<usize> {
    let digest = pcr_quote_digest(alloc, PLATFORM_STATE_PCR_INDEX).await?;

    // Nonce from SPDM is variable-length; pad/truncate to 32 bytes.
    let mut nonce_buf = [0u8; 32];
    let copy_len = nonce.len().min(32);
    nonce_buf[..copy_len].copy_from_slice(&nonce[..copy_len]);

    stamp_eat_payload(claims_buf, &nonce_buf, &digest)
        .ok_or(mcu_error::codes::INTERNAL_BUG)
}

