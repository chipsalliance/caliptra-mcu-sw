// Licensed under the Apache-2.0 license

use crate::crypto::rng::Rng;
use crate::error::{CaliptraApiError, CaliptraApiResult};
use ocp_eat::ocp_profile::{ConciseEvidence, DebugStatus, MeasurementFormat, OcpEatClaims};
use ocp_eat::CborEncoder;

/// Scratch buffer size for encoding Concise Evidence.
/// This should be sized based on the expected number of target environments added to the evidence.
const EVIDENCE_SCRATCH_BUFFER_SIZE: usize = 1024;

pub async fn generate_eat_claims(
    issuer: &str,
    eat_nonce: &[u8],
    concise_evidence: ConciseEvidence<'_>,
    buffer: &mut [u8],
) -> CaliptraApiResult<usize> {
    let measurement = MeasurementFormat::new(&concise_evidence);
    let measurements_array = [measurement];

    // cti - unique identifier for the token
    let mut cti = [0u8; 64];
    let cti_len = eat_nonce.len().min(64);
    Rng::generate_random_number(&mut cti[..cti_len]).await?;

    // Debug status - TODO: replace with actual status
    let debug_status = DebugStatus::Disabled;

    // prepare EAT claims
    let mut eat_claims = OcpEatClaims::new(eat_nonce, debug_status, &measurements_array);
    eat_claims.issuer = Some(issuer);
    eat_claims.cti = Some(&cti[..cti_len]);

    eat_claims.validate().map_err(CaliptraApiError::Eat)?;
    // Encode payload
    let payload_len = {
        let mut encoder = CborEncoder::new(buffer);

        let mut evidence_scratch_buf = [0u8; EVIDENCE_SCRATCH_BUFFER_SIZE];

        eat_claims
            .encode(&mut encoder, &mut evidence_scratch_buf)
            .map_err(CaliptraApiError::Eat)?;
        encoder.len()
    };
    Ok(payload_len)
}
