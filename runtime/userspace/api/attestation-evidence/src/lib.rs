// Licensed under the Apache-2.0 license

#![no_std]

//! Transport-neutral signed attestation evidence generation.

pub mod ocp_eat;
#[cfg(feature = "pcr-quote")]
pub mod pcr_quote;

use caliptra_mcu_measurement_api::{ATTESTATION_P384_DIGEST_SIZE, ATTESTATION_P384_SIGNATURE_SIZE};
use mcu_caliptra_api_lite::{ApiAlloc, DPE_LABEL_LEN};
use mcu_error::McuResult;
use ocp_eat::{cose_sign1_len, SignedEat};

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
    let signed_eat = SignedEat::new();
    {
        let kid = signed_eat.prepare_in_place(out)?;
        caliptra_mcu_measurement_api::leaf_kid(alloc, key_label, kid).await?;
    }

    let payload_len = {
        let payload = signed_eat.payload_buffer_mut(out, ocp_eat::EAT_PAYLOAD_MAX_SIZE)?;
        let layout = ocp_eat::start_claims_payload(payload, nonce)?;
        let concise_evidence_len = {
            let concise_evidence = ocp_eat::concise_evidence_buffer_mut(payload, layout)?;
            caliptra_mcu_measurement_api::encode_measurement_evidence(alloc, concise_evidence)
                .await?
        };
        ocp_eat::finish_claims_payload(payload, layout, concise_evidence_len)?
    };

    let mut sig_digest = [0u8; ATTESTATION_P384_DIGEST_SIZE];
    {
        let payload = signed_eat.payload_slice(out, payload_len)?;
        signed_eat
            .sig_context_digest(alloc, payload, &mut sig_digest)
            .await?;
    }
    let mut signature = [0u8; ATTESTATION_P384_SIGNATURE_SIZE];
    let sig_len =
        caliptra_mcu_measurement_api::sign(alloc, key_label, &sig_digest, &mut signature).await?;
    if sig_len != signature.len() {
        return Err(mcu_error::codes::INTERNAL_BUG);
    }
    signed_eat.finish_in_place(payload_len, &signature, out)
}
