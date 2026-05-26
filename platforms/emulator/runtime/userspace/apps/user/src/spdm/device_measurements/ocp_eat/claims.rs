// Licensed under the Apache-2.0 license

//! OCP EAT claims generation — platform-state evidence via byte template.

use mcu_caliptra_api_lite::get_pcr_value;
use mcu_caliptra_api_lite::signed_eat::cose_sign1_len;
use mcu_error::McuResult;
use mcu_spdm_lite_pal::BitmapAllocator;

include!(concat!(env!("OUT_DIR"), "/eat_claims_template.rs"));

/// PCR index for the aggregate platform state measurement.
const PLATFORM_STATE_PCR_INDEX: usize = 31;
pub const SIGNED_EAT_LEN: usize = cose_sign1_len(EAT_PAYLOAD_LEN);

/// Generates EAT claims CBOR payload into `claims_buf`.
pub async fn generate_claims(
    alloc: &BitmapAllocator,
    claims_buf: &mut [u8],
    nonce: &[u8],
) -> McuResult<usize> {
    let pcr_value = get_pcr_value(alloc, PLATFORM_STATE_PCR_INDEX).await?;

    // Nonce from SPDM is variable-length; pad/truncate to 32 bytes.
    let mut nonce_buf = [0u8; 32];
    let copy_len = nonce.len().min(32);
    nonce_buf[..copy_len].copy_from_slice(&nonce[..copy_len]);

    if claims_buf.len() < EAT_PAYLOAD_LEN {
        return Err(mcu_error::codes::INTERNAL_BUG);
    }
    claims_buf[..EAT_PAYLOAD_LEN].copy_from_slice(&EAT_PAYLOAD_TEMPLATE);
    claims_buf[NONCE_OFFSET..NONCE_OFFSET + 32].copy_from_slice(&nonce_buf);
    claims_buf[MEASUREMENT_DIGEST_OFFSETS[0]..MEASUREMENT_DIGEST_OFFSETS[0] + 48]
        .copy_from_slice(&pcr_value);
    Ok(EAT_PAYLOAD_LEN)
}
