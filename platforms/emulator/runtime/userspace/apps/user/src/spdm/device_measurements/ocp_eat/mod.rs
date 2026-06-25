// Licensed under the Apache-2.0 license

//! OCP EAT measurement provider for spdm-lib.
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

use caliptra_mcu_spdm_pal::measurements::MeasurementProvider;
use caliptra_mcu_spdm_pal::BitmapAllocator;
use caliptra_mcu_spdm_traits::{MeasurementInfo, SPDM_NONCE_LEN};
use mcu_caliptra_api_lite::signed_eat::SignedEatLite;
use mcu_caliptra_api_lite::{
    dpe_certify_key_pubkey, sha_finish, sha_init, sha_update, HashAlgo, DPE_LABEL_LEN,
    SHA_CONTEXT_SIZE,
};
use mcu_error::McuResult;

/// Single measurement entry: index 0xFD, StructuredManifest.
const OCP_EAT_MEAS_INFO: [MeasurementInfo; 1] = [MeasurementInfo {
    index: 0xFD,
    value_size: claims::SIGNED_EAT_LEN as u16,
    value_type: 10, // StructuredManifest
    is_raw: true,
    is_tcb: true,
}];
const KID_LEN: usize = 48;
static ZERO_NONCE: [u8; SPDM_NONCE_LEN] = [0u8; SPDM_NONCE_LEN];

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

impl MeasurementProvider for OcpEatMeasurementProvider {
    /// Scratch holds kid plus the claims payload before COSE_Sign1 assembly.
    const SCRATCH_SIZE: usize = KID_LEN + claims::EAT_PAYLOAD_LEN;

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

        let eat_nonce: &[u8; SPDM_NONCE_LEN] = match nonce {
            Some(n) => n,
            None => &ZERO_NONCE,
        };

        let (kid, claims_buf) = scratch.split_at_mut(KID_LEN);
        let kid: &mut [u8; KID_LEN] = kid.try_into().map_err(|_| mcu_error::codes::INTERNAL_BUG)?;

        // Compute kid = SHA-384(pubkey_x || pubkey_y) via alloc-backed DPE.
        compute_kid(&self.key_label, alloc, kid).await?;

        // 1. Generate CBOR EAT claims payload into scratch.
        let payload_size = claims::generate_claims(alloc, claims_buf, eat_nonce)
            .await
            .map_err(|_| mcu_error::codes::INTERNAL_BUG)?;

        // 2. Sign claims as COSE_Sign1 with kid via api-lite (alloc-backed).
        let signed_eat = SignedEatLite::new(&self.key_label);

        signed_eat
            .generate_with_kid(alloc, &claims_buf[..payload_size], kid, out)
            .await
            .map_err(|_| mcu_error::codes::INTERNAL_BUG)
    }
}

/// Compute kid = SHA-384(pubkey_x || pubkey_y) from DPE certify_key.
///
/// All mailbox buffers are allocated via `alloc` (BitmapAllocator).
/// `pubkey_x`/`pubkey_y` are streamed directly into SHA, so no
/// 96-byte concat buffer lives on the async stack.
async fn compute_kid(
    key_label: &[u8; DPE_LABEL_LEN],
    alloc: &BitmapAllocator,
    kid: &mut [u8; KID_LEN],
) -> McuResult<()> {
    let mut pubkey_x = [0u8; KID_LEN];
    let mut pubkey_y = [0u8; KID_LEN];

    dpe_certify_key_pubkey(alloc, key_label, &mut pubkey_x, &mut pubkey_y).await?;

    let sha_buf = alloc.alloc_bytes(SHA_CONTEXT_SIZE)?;
    let mut state = sha_init(alloc, sha_buf, HashAlgo::Sha384, &pubkey_x).await?;
    sha_update(alloc, &mut state, &pubkey_y).await?;
    sha_finish(alloc, &mut state, kid).await?;

    Ok(())
}
