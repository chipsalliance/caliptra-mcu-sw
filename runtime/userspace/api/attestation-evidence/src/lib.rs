// Licensed under the Apache-2.0 license

#![no_std]

//! Transport-neutral signed attestation evidence generation.

pub mod ocp_eat;
#[cfg(feature = "pcr-quote")]
pub mod pcr_quote;

use caliptra_mcu_measurement_api::{
    EvidenceBuilder, ATTESTATION_P384_DIGEST_SIZE, ATTESTATION_P384_SIGNATURE_SIZE,
};
use mcu_caliptra_api_lite::{ApiAlloc, DPE_LABEL_LEN};
use mcu_error::McuResult;
use ocp_eat::{cose_sign1_len, ClaimsPayloadLayout, SignedEat};

pub const KID_LEN: usize = 48;
pub const SIGNED_OCP_EAT_MAX_SIZE: usize = cose_sign1_len(ocp_eat::EAT_PAYLOAD_MAX_SIZE);

const _: () = assert!(SIGNED_OCP_EAT_MAX_SIZE <= u16::MAX as usize);
const _: () = assert!(ocp_eat::EAT_PAYLOAD_MAX_SIZE > u8::MAX as usize);

struct SignedOcpEatBuilder<'a> {
    signed_eat: SignedEat,
    nonce: &'a [u8],
    eat_buffer: &'a mut [u8],
    claims_layout: Option<ClaimsPayloadLayout>,
}

impl<'a> SignedOcpEatBuilder<'a> {
    fn new(nonce: &'a [u8], eat_buffer: &'a mut [u8]) -> Self {
        Self {
            signed_eat: SignedEat::new(),
            nonce,
            eat_buffer,
            claims_layout: None,
        }
    }
}

impl<A: ApiAlloc> EvidenceBuilder<A> for SignedOcpEatBuilder<'_> {
    fn kid_buffer_mut(&mut self) -> McuResult<&mut [u8; ATTESTATION_P384_DIGEST_SIZE]> {
        self.signed_eat.prepare_in_place(self.eat_buffer)
    }

    fn concise_evidence_buffer_mut(&mut self) -> McuResult<&mut [u8]> {
        let payload = self
            .signed_eat
            .payload_buffer_mut(self.eat_buffer, ocp_eat::EAT_PAYLOAD_MAX_SIZE)?;
        let layout = ocp_eat::start_claims_payload(payload, self.nonce)?;
        self.claims_layout = Some(layout);
        ocp_eat::concise_evidence_buffer_mut(payload, layout)
    }

    async fn digest_for_signature(
        &mut self,
        alloc: &A,
        concise_evidence_len: usize,
        digest: &mut [u8; ATTESTATION_P384_DIGEST_SIZE],
    ) -> McuResult<usize> {
        let layout = self.claims_layout.ok_or(mcu_error::codes::INTERNAL_BUG)?;
        let payload_len = {
            let payload = self
                .signed_eat
                .payload_buffer_mut(self.eat_buffer, ocp_eat::EAT_PAYLOAD_MAX_SIZE)?;
            ocp_eat::finish_claims_payload(payload, layout, concise_evidence_len)?
        };
        let payload = self
            .signed_eat
            .payload_slice(self.eat_buffer, payload_len)?;
        self.signed_eat
            .sig_context_digest(alloc, payload, digest)
            .await?;
        Ok(payload_len)
    }

    fn signature_buffer_mut(
        &mut self,
        payload_len: usize,
    ) -> McuResult<(usize, &mut [u8; ATTESTATION_P384_SIGNATURE_SIZE])> {
        self.signed_eat
            .signature_buffer_mut(payload_len, self.eat_buffer)
    }
}

/// Encode a signed OCP EAT token containing Measurement API concise evidence.
///
/// `pki_entity_slot` selects the endorsement hierarchy for the signing key.
///
/// The encoded evidence, payload, key identifier, and signature are written
/// directly into `out`; transient mailbox/SHA buffers come from `alloc`.
pub async fn encode_signed_ocp_eat<A: ApiAlloc>(
    alloc: &A,
    key_label: &[u8; DPE_LABEL_LEN],
    pki_entity_slot: u8,
    nonce: &[u8],
    out: &mut [u8],
) -> McuResult<usize> {
    let mut builder = SignedOcpEatBuilder::new(nonce, out);
    caliptra_mcu_measurement_api::measure_and_sign_evidence(
        alloc,
        key_label,
        pki_entity_slot,
        &mut builder,
    )
    .await
}
