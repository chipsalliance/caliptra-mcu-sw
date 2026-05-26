// Licensed under the Apache-2.0 license

//! OCP EAT measurement provider for spdm-lite.
//!
//! Provides a single measurement at index 0xFD (StructuredManifest)
//! containing a COSE_Sign1–signed EAT token with firmware evidence.
//!
//! Uses a **kid** (key identifier) in the COSE unprotected header
//! instead of x5chain, keeping the token small enough for 1024-byte
//! MCTP transport. The same SPDM attestation key signs both the
//! SPDM transcripts and the EAT token.
//!
//! All DPE/SHA mailbox buffers go through caliptra-api-lite
//! ([`BitmapAllocator`]-backed) — nothing large on the async stack.

pub mod claims;

use mcu_caliptra_api_lite::signed_eat::{SignedEatLite, SIG_STRUCTURE_LEN};
use mcu_caliptra_api_lite::{
    dpe_certify_key_pubkey, sha_finish, sha_init, sha_update, DPE_LABEL_LEN, HashAlgo,
};
use mcu_error::McuResult;
use mcu_spdm_lite_pal::BitmapAllocator;
use mcu_spdm_lite_pal::measurements::MeasurementProvider;
use mcu_spdm_lite_traits::{MeasurementInfo, SPDM_NONCE_LEN};

/// Single measurement entry: index 0xFD, StructuredManifest.
const OCP_EAT_MEAS_INFO: [MeasurementInfo; 1] = [MeasurementInfo {
    index: 0xFD,
    value_type: 10, // StructuredManifest
    is_raw: false,
}];

/// Measurement provider that returns OCP EAT signed evidence.
///
/// The token is signed with the SPDM attestation key (same key that
/// signs SPDM transcripts). A `kid` — SHA-384 of the public key
/// coordinates — is placed in the COSE unprotected header so the
/// verifier can correlate it to the SPDM certificate chain.
pub struct OcpEatMeasurementProvider {
    /// DPE key label for the SPDM attestation key (same as cert chain).
    key_label: [u8; DPE_LABEL_LEN],
}

impl OcpEatMeasurementProvider {
    pub fn new(key_label: [u8; DPE_LABEL_LEN]) -> Self {
        Self { key_label }
    }
}

/// CBOR claims buffer — payload is exactly 206 bytes, small margin for safety.
const CLAIMS_BUF_SIZE: usize = 256;

impl MeasurementProvider for OcpEatMeasurementProvider {
    /// Scratch holds claims + sig_context sequentially.
    const SCRATCH_SIZE: usize = CLAIMS_BUF_SIZE + SIG_STRUCTURE_LEN;

    fn measurement_info(&self) -> &[MeasurementInfo] {
        &OCP_EAT_MEAS_INFO
    }

    async fn get_measurement_value(
        &self,
        _index: u8,
        nonce: Option<&[u8; SPDM_NONCE_LEN]>,
        out: &mut [u8],
        scratch: &mut [u8],
        alloc: &BitmapAllocator,
    ) -> McuResult<usize> {
        if scratch.len() < Self::SCRATCH_SIZE {
            return Err(mcu_error::codes::INTERNAL_BUG);
        }

        // Use a zero nonce if none provided (unsigned GET_MEASUREMENTS).
        let zero_nonce = [0u8; SPDM_NONCE_LEN];
        let eat_nonce: &[u8] = match nonce {
            Some(n) => n,
            None => &zero_nonce,
        };

        // Compute kid = SHA-384(pubkey_x || pubkey_y) via alloc-backed DPE.
        let kid = compute_kid(&self.key_label, alloc).await?;

        // Split scratch: [claims (CLAIMS_BUF_SIZE) | sig_context (SIG_STRUCTURE_LEN)]
        let (claims_buf, sig_scratch) =
            scratch[..CLAIMS_BUF_SIZE + SIG_STRUCTURE_LEN].split_at_mut(CLAIMS_BUF_SIZE);

        // 1. Generate CBOR EAT claims payload into scratch.
        let payload_size = claims::generate_claims(alloc, claims_buf, eat_nonce)
            .await
            .map_err(|_| mcu_error::codes::INTERNAL_BUG)?;

        // 2. Sign claims as COSE_Sign1 with kid via api-lite (alloc-backed).
        let signed_eat = SignedEatLite::new(&self.key_label);

        signed_eat
            .generate_with_kid(alloc, &claims_buf[..payload_size], &kid, out, sig_scratch)
            .await
            .map_err(|_| mcu_error::codes::INTERNAL_BUG)
    }
}

/// Compute kid = SHA-384(pubkey_x || pubkey_y) from DPE certify_key.
///
/// All mailbox buffers are allocated via `alloc` (BitmapAllocator).
async fn compute_kid(
    key_label: &[u8; DPE_LABEL_LEN],
    alloc: &BitmapAllocator,
) -> McuResult<[u8; 48]> {
    let mut pubkey_x = [0u8; 48];
    let mut pubkey_y = [0u8; 48];

    dpe_certify_key_pubkey(alloc, key_label, &mut pubkey_x, &mut pubkey_y).await?;

    let mut concat = [0u8; 96];
    concat[..48].copy_from_slice(&pubkey_x);
    concat[48..].copy_from_slice(&pubkey_y);

    let mut kid = [0u8; 48];
    let mut state = sha_init(alloc, HashAlgo::Sha384, &[]).await?;
    sha_update(alloc, &mut state, &concat).await?;
    sha_finish(alloc, &mut state, &mut kid).await?;

    Ok(kid)
}
