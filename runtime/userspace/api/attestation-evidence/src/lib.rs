// Licensed under the Apache-2.0 license

#![no_std]

//! Transport-neutral signed attestation evidence generation.

pub mod ocp_eat;
pub mod pcr_quote;

use caliptra_mcu_measurement_api::{
    EvidenceBuilder, ATTESTATION_P384_DIGEST_SIZE, ATTESTATION_P384_SIGNATURE_SIZE,
};
use mcu_caliptra_api_lite::signed_eat::{cose_sign1_len, SignedEat};
use mcu_caliptra_api_lite::{ApiAlloc, DPE_LABEL_LEN};
use mcu_error::McuResult;

pub const KID_LEN: usize = 48;
pub const SIGNED_OCP_EAT_MAX_SIZE: usize = cose_sign1_len(ocp_eat::EAT_PAYLOAD_MAX_SIZE);
/// Scratch needed to build signed OCP EAT evidence.
///
/// All EAT and concise-evidence bytes are encoded directly into `out`; only
/// transient mailbox/SHA buffers are allocated through [`ApiAlloc`]. Static EAT
/// claims therefore affect `SIGNED_OCP_EAT_MAX_SIZE` but not caller scratch.
pub const SIGNED_OCP_EAT_WORKSPACE_SIZE: usize = 0;
pub const WORKSPACE_SIZE: usize = SIGNED_OCP_EAT_WORKSPACE_SIZE;

const _: () = assert!(SIGNED_OCP_EAT_MAX_SIZE <= u16::MAX as usize);
const _: () = assert!(ocp_eat::EAT_PAYLOAD_MAX_SIZE > u8::MAX as usize);

struct SignedOcpEatBuilder<'a> {
    signed_eat: SignedEat,
    nonce: &'a [u8],
    eat_buffer: &'a mut [u8],
    claims_layout: Option<ocp_eat::ClaimsPayloadLayout>,
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

    fn finish(
        self,
        payload_len: usize,
        signature: &[u8; ATTESTATION_P384_SIGNATURE_SIZE],
    ) -> McuResult<usize> {
        self.signed_eat
            .finish_in_place(payload_len, signature, self.eat_buffer)
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
}

/// Encode a signed OCP EAT token containing Measurement API concise evidence.
///
/// `workspace` is retained for API compatibility and may be empty. The encoded
/// evidence, payload, key identifier, and signature are written directly into
/// `out`.
pub async fn encode_signed_ocp_eat<A: ApiAlloc>(
    alloc: &A,
    key_label: &[u8; DPE_LABEL_LEN],
    nonce: &[u8],
    _workspace: &mut [u8],
    out: &mut [u8],
) -> McuResult<usize> {
    let mut builder = SignedOcpEatBuilder::new(nonce, out);
    let mut signature = [0u8; ATTESTATION_P384_SIGNATURE_SIZE];
    let payload_len = caliptra_mcu_measurement_api::measure_and_sign_evidence(
        alloc,
        key_label,
        &mut signature,
        &mut builder,
    )
    .await?;
    builder.finish(payload_len, &signature)
}
