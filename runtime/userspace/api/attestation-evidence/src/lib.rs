// Licensed under the Apache-2.0 license

#![no_std]

//! Transport-neutral signed attestation evidence generation.

pub mod ocp_eat;
pub mod pcr_quote;

use caliptra_mcu_measurement_api::{ATTESTATION_P384_DIGEST_SIZE, ATTESTATION_P384_SIGNATURE_SIZE};
use mcu_caliptra_api_lite::signed_eat::{cose_sign1_len, SignedEat};
use mcu_caliptra_api_lite::{ApiAlloc, DPE_LABEL_LEN};
use mcu_error::McuResult;

pub const KID_LEN: usize = 48;
pub const SIGNED_OCP_EAT_MAX_SIZE: usize = cose_sign1_len(ocp_eat::EAT_PAYLOAD_MAX_SIZE);
pub const WORKSPACE_SIZE: usize =
    KID_LEN + ocp_eat::CONCISE_EVIDENCE_WORKSPACE_SIZE + ocp_eat::EAT_PAYLOAD_MAX_SIZE;

const _: () = assert!(SIGNED_OCP_EAT_MAX_SIZE <= u16::MAX as usize);

/// Encode a signed OCP EAT token containing Measurement API concise evidence.
///
/// `workspace` is caller-provided temporary storage and is not retained.
pub async fn encode_signed_ocp_eat<A: ApiAlloc>(
    alloc: &A,
    key_label: &[u8; DPE_LABEL_LEN],
    nonce: &[u8],
    workspace: &mut [u8],
    out: &mut [u8],
) -> McuResult<usize> {
    let (kid, rest) = workspace
        .split_at_mut_checked(KID_LEN)
        .ok_or(mcu_error::codes::INTERNAL_BUG)?;
    let kid: &mut [u8; KID_LEN] = kid.try_into().map_err(|_| mcu_error::codes::INTERNAL_BUG)?;
    let (concise_evidence, eat_payload) = rest
        .split_at_mut_checked(ocp_eat::CONCISE_EVIDENCE_WORKSPACE_SIZE)
        .ok_or(mcu_error::codes::INTERNAL_BUG)?;

    caliptra_mcu_measurement_api::leaf_kid(alloc, key_label, kid).await?;

    let concise_evidence_len =
        caliptra_mcu_measurement_api::encode_measurement_evidence(alloc, concise_evidence).await?;
    let concise_evidence = concise_evidence
        .get(..concise_evidence_len)
        .ok_or(mcu_error::codes::INTERNAL_BUG)?;

    let payload_len = ocp_eat::encode_claims_payload(eat_payload, nonce, concise_evidence)?;
    let payload = eat_payload
        .get(..payload_len)
        .ok_or(mcu_error::codes::INTERNAL_BUG)?;

    let signed_eat = SignedEat::new();
    let mut sig_digest = [0u8; ATTESTATION_P384_DIGEST_SIZE];
    signed_eat
        .sig_context_digest(alloc, payload, &mut sig_digest)
        .await?;
    let mut signature = [0u8; ATTESTATION_P384_SIGNATURE_SIZE];
    let sig_len =
        caliptra_mcu_measurement_api::sign(alloc, key_label, &sig_digest, &mut signature).await?;
    if sig_len != signature.len() {
        return Err(mcu_error::codes::INTERNAL_BUG);
    }
    signed_eat.encode_with_kid_and_signature(payload, kid, &signature, out)
}
