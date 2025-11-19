// Licensed under the Apache-2.0 license

use crate::crypto::rng::Rng;
use crate::error::{CaliptraApiError, CaliptraApiResult};
use ocp_eat::eat_encoder::{
    CborEncoder, ConciseEvidence, DebugStatus, EatEncoder, MeasurementFormat, OcpEatClaims,
};

const OCP_SECURITY_OID: &str = "1.3.6.1.4.1.42623.1";

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
    let eat_claims = OcpEatClaims::new(
        issuer,
        &cti[..cti_len],
        eat_nonce,
        debug_status,
        OCP_SECURITY_OID,
        &measurements_array,
    );

    EatEncoder::validate_claims(&eat_claims).map_err(CaliptraApiError::Eat)?;
    // Encode payload
    let payload_len = {
        let mut encoder = CborEncoder::new(buffer);
        encoder
            .encode_ocp_eat_claims(&eat_claims)
            .map_err(CaliptraApiError::Eat)?;
        encoder.len()
    };
    Ok(payload_len)
}
