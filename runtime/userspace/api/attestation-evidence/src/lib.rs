// Licensed under the Apache-2.0 license

#![no_std]

//! Transport-neutral signed attestation evidence generation.

pub mod ocp_eat;
#[cfg(feature = "pcr-quote")]
pub mod pcr_quote;

use caliptra_mcu_measurement_api::{EvidenceBuilder, MeasurementSigningAlgo, ATTESTATION_KID_SIZE};
use mcu_caliptra_api::{ApiAlloc, DPE_LABEL_LEN, MLDSA87_TR_SIZE};
use mcu_error::McuResult;
use ocp_eat::{cose_sign1_len, ClaimsPayloadLayout, SignedEat};

pub use ocp_eat::OcpEatAlgorithm;

pub const KID_LEN: usize = ATTESTATION_KID_SIZE;
pub const SIGNED_OCP_EAT_MAX_SIZE: usize =
    cose_sign1_len(ocp_eat::EAT_PAYLOAD_MAX_SIZE, OcpEatAlgorithm::Mldsa87);

const _: () = assert!(SIGNED_OCP_EAT_MAX_SIZE <= u16::MAX as usize);
const _: () = assert!(ocp_eat::EAT_PAYLOAD_MAX_SIZE > u8::MAX as usize);

struct SignedOcpEatBuilder<'a> {
    signed_eat: SignedEat,
    nonce: &'a [u8],
    eat_buffer: &'a mut [u8],
    claims_layout: Option<ClaimsPayloadLayout>,
    tr: [u8; MLDSA87_TR_SIZE],
}

impl<'a> SignedOcpEatBuilder<'a> {
    fn new(algo: OcpEatAlgorithm, nonce: &'a [u8], eat_buffer: &'a mut [u8]) -> Self {
        Self {
            signed_eat: SignedEat::new(algo),
            nonce,
            eat_buffer,
            claims_layout: None,
            tr: [0u8; MLDSA87_TR_SIZE],
        }
    }
}

impl<A: ApiAlloc> EvidenceBuilder<A> for SignedOcpEatBuilder<'_> {
    fn signing_algo(&self) -> MeasurementSigningAlgo {
        match self.signed_eat.algo() {
            OcpEatAlgorithm::Esp384 => MeasurementSigningAlgo::EccP384,
            OcpEatAlgorithm::Mldsa87 => MeasurementSigningAlgo::MlDsa87,
        }
    }

    fn kid_buffer_mut(&mut self) -> McuResult<&mut [u8; ATTESTATION_KID_SIZE]> {
        self.signed_eat.prepare_in_place(self.eat_buffer)
    }

    fn set_mldsa87_tr(&mut self, tr: &[u8; MLDSA87_TR_SIZE]) -> McuResult<()> {
        self.tr = *tr;
        Ok(())
    }

    fn concise_evidence_buffer_mut(&mut self) -> McuResult<&mut [u8]> {
        let payload = self
            .signed_eat
            .payload_buffer_mut(self.eat_buffer, ocp_eat::EAT_PAYLOAD_MAX_SIZE)?;
        let layout = ocp_eat::start_claims_payload(payload, self.nonce)?;
        self.claims_layout = Some(layout);
        ocp_eat::concise_evidence_buffer_mut(payload, layout)
    }

    async fn prepare_signing_input(
        &mut self,
        alloc: &A,
        concise_evidence_len: usize,
        signing_input: &mut [u8],
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
            .sig_context_input(alloc, &self.tr, payload, signing_input)
            .await?;
        Ok(payload_len)
    }

    fn signature_buffer_mut(&mut self, payload_len: usize) -> McuResult<(usize, &mut [u8])> {
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
    algo: OcpEatAlgorithm,
    key_label: &[u8; DPE_LABEL_LEN],
    pki_entity_slot: u8,
    nonce: &[u8],
    out: &mut [u8],
) -> McuResult<usize> {
    let mut builder = SignedOcpEatBuilder::new(algo, nonce, out);
    caliptra_mcu_measurement_api::measure_and_sign_evidence(
        alloc,
        key_label,
        pki_entity_slot,
        &mut builder,
    )
    .await
}
