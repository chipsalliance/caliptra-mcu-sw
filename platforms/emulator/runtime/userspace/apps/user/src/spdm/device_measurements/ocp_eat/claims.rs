// Licensed under the Apache-2.0 license

//! OCP EAT claims generation — platform-state evidence via byte template.

use caliptra_mcu_spdm_pal::BitmapAllocator;
use caliptra_mcu_spdm_traits::SPDM_NONCE_LEN;
use mcu_caliptra_api_lite::get_pcr_value;
use mcu_caliptra_api_lite::signed_eat::cose_sign1_len;
use mcu_error::McuResult;

include!(concat!(env!("OUT_DIR"), "/eat_claims_template.rs"));

/// PCR index for the aggregate platform state measurement.
const PLATFORM_STATE_PCR_INDEX: usize = 31;
pub const SIGNED_EAT_LEN: usize = cose_sign1_len(EAT_PAYLOAD_LEN);

/// Generates EAT claims CBOR payload into `claims_buf`.
pub async fn generate_claims(
    alloc: &BitmapAllocator,
    claims_buf: &mut [u8],
    nonce: &[u8; SPDM_NONCE_LEN],
) -> McuResult<usize> {
    let pcr_value = get_pcr_value(alloc, PLATFORM_STATE_PCR_INDEX).await?;

    // Nonce from SPDM is variable-length; pad/truncate to 32 bytes.
    // `iter_mut().zip(...)` avoids the `copy_from_slice` length-check
    // panic site (and its file/Location rodata cost).
    let mut nonce_buf = [0u8; 32];
    for (dst, src) in nonce_buf.iter_mut().zip(nonce.iter().take(32)) {
        *dst = *src;
    }

    // Convert the output prefix to a fixed-size array reference once;
    // this is the only panic site for the whole function (single
    // `Location` shared by all writes below).
    let claims_array: &mut [u8; EAT_PAYLOAD_LEN] = claims_buf
        .first_chunk_mut::<EAT_PAYLOAD_LEN>()
        .ok_or(mcu_error::codes::INTERNAL_BUG)?;
    *claims_array = EAT_PAYLOAD_TEMPLATE;

    let nonce_slot = claims_array
        .get_mut(NONCE_OFFSET..)
        .and_then(|s| s.first_chunk_mut::<32>())
        .ok_or(mcu_error::codes::INTERNAL_BUG)?;
    *nonce_slot = nonce_buf;

    let digest_slot = claims_array
        .get_mut(MEASUREMENT_DIGEST_OFFSETS[0]..)
        .and_then(|s| s.first_chunk_mut::<48>())
        .ok_or(mcu_error::codes::INTERNAL_BUG)?;
    *digest_slot = pcr_value;

    Ok(EAT_PAYLOAD_LEN)
}
