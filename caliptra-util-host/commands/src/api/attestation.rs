// Licensed under the Apache-2.0 license

//! Attestation API functions
//!
//! High-level functions for retrieving signed attestation evidence from the
//! device. Both the SPDM VDM and MCI mailbox transports expose the same
//! `GET_ATTESTATION` contract, so these functions work over either.

use crate::api::{CaliptraApiError, CaliptraResult};
use caliptra_mcu_core_util_host_command_types::{
    attestation::{
        AsymAlgo, EvidenceFormat, GetAttestationRequest, GetAttestationResponse, PkiEntitySlot,
    },
    CaliptraCommandId,
};
use caliptra_util_host_session::CaliptraSession;

/// Retrieve signed attestation evidence from the device.
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
/// - `format`: Evidence format to generate (OCP EAT or PCR quote)
/// - `algorithm`: Signing algorithm (ECC P-384 or ML-DSA-87)
/// - `nonce`: 32-byte freshness nonce, bound into the signed evidence
/// - `entity`: PKI entity whose hierarchy endorses the signing key. Only
///   [`PkiEntitySlot::Vendor`] is accepted by devices today.
///
/// # Returns
///
/// - `Ok(GetAttestationResponse)` on success
/// - `Err(CaliptraApiError)` on failure, including when the device does not
///   support the requested format/algorithm pair, or does not implement the
///   requested entity
pub fn caliptra_cmd_get_attestation(
    session: &mut CaliptraSession,
    format: EvidenceFormat,
    algorithm: AsymAlgo,
    entity: PkiEntitySlot,
    nonce: &[u8; 32],
) -> CaliptraResult<GetAttestationResponse> {
    let request = GetAttestationRequest::new(format, algorithm, entity, nonce);
    session
        .execute_command_with_id(CaliptraCommandId::GetAttestation, &request)
        .map_err(|_| CaliptraApiError::SessionError("GetAttestation command failed"))
}

/// Query which evidence formats the device supports.
///
/// Issues a `GET_ATTESTATION` discovery query (`evidence_format == 0`), whose
/// response carries a supported-format bitmap instead of evidence.
///
/// # Returns
///
/// - `Ok(GetAttestationResponse)` whose `supported_formats()` decodes the bitmap
/// - `Err(CaliptraApiError)` on failure
pub fn caliptra_cmd_get_attestation_formats(
    session: &mut CaliptraSession,
) -> CaliptraResult<GetAttestationResponse> {
    let request = GetAttestationRequest::query();
    session
        .execute_command_with_id(CaliptraCommandId::GetAttestation, &request)
        .map_err(|_| CaliptraApiError::SessionError("GetAttestation format query failed"))
}
