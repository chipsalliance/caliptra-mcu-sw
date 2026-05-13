// Licensed under the Apache-2.0 license

use crate::crypto::rng::Rng;
use crate::error::{CaliptraApiError, CaliptraApiResult};
use caliptra_ocp_eat::ocp_profile::{ConciseEvidence, DebugStatus, MeasurementFormat, OcpEatClaims};
use caliptra_ocp_eat::CborEncoder;

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
    // Encode payload directly into the buffer without a scratch buffer
    let payload_len = {
        let mut encoder = CborEncoder::new(buffer);
        eat_claims
            .encode_in_place(&mut encoder)
            .map_err(CaliptraApiError::Eat)?;
        encoder.len()
    };
    Ok(payload_len)
}
