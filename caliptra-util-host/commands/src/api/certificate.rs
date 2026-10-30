// Licensed under the Apache-2.0 license

//! Certificate API functions
//!
//! High-level functions for certificate operations with Caliptra.

use crate::api::{CaliptraApiError, CaliptraResult};
use caliptra_mcu_core_util_host_command_types::{
    attestation::{AsymAlgo, PkiEntitySlot},
    certificate::{
        ExportAttestedCsrRequest, ExportAttestedCsrResponse, ExportIdevidCsrRequest,
        ExportIdevidCsrResponse, GetCertChainInfoRequest, GetCertChainInfoResponse,
        GetCertChainRequest, GetCertChainResponse, SetCertChainRequest, SetCertChainResponse,
    },
    CaliptraCommandId,
};
use caliptra_util_host_session::CaliptraSession;

/// Export an attested CSR or perform keypair discovery from the device
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
/// - `device_key_id`: Device key identifier (0x0000=Discovery / KeyPairInventory, 0x0001=LDevID, 0x0002=FMC Alias, 0x0003=RT Alias)
/// - `algorithm`: Asymmetric algorithm (0x0001=ECC384, 0x0002=MLDSA87)
/// - `nonce`: 32-byte nonce for freshness
///
/// # Returns
///
/// - `Ok(ExportAttestedCsrResponse)` on success
/// - `Err(CaliptraApiError)` on failure
pub fn caliptra_cmd_export_attested_csr(
    session: &mut CaliptraSession,
    device_key_id: u32,
    algorithm: u32,
    nonce: &[u8; 32],
) -> CaliptraResult<ExportAttestedCsrResponse> {
    let request = ExportAttestedCsrRequest {
        device_key_id,
        algorithm,
        nonce: *nonce,
    };
    session
        .execute_command_with_id(CaliptraCommandId::ExportAttestedCsr, &request)
        .map_err(|_| CaliptraApiError::SessionError("ExportAttestedCsr command failed"))
}

/// Export an IDevID CSR from the device (manufacturing mode only)
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
/// - `algorithm`: Asymmetric algorithm (0x0001=ECC384, 0x0002=MLDSA87)
///
/// # Returns
///
/// - `Ok(ExportIdevidCsrResponse)` on success
/// - `Err(CaliptraApiError)` on failure
pub fn caliptra_cmd_export_idevid_csr(
    session: &mut CaliptraSession,
    algorithm: u32,
) -> CaliptraResult<ExportIdevidCsrResponse> {
    let request = ExportIdevidCsrRequest { algorithm };
    session
        .execute_command_with_id(CaliptraCommandId::ExportIdevidCsr, &request)
        .map_err(|_| CaliptraApiError::SessionError("ExportIdevidCsr command failed"))
}

/// Query certificate chain metadata, total byte length, and raw DER SHA-384 digest
/// for `(pki_entity_slot, algorithm)`.
pub fn caliptra_cmd_get_cert_chain_info(
    session: &mut CaliptraSession,
    pki_entity_slot: PkiEntitySlot,
    algorithm: AsymAlgo,
) -> CaliptraResult<GetCertChainInfoResponse> {
    let request = GetCertChainInfoRequest::new(pki_entity_slot, algorithm);
    session
        .execute_command_with_id(CaliptraCommandId::GetCertChainInfo, &request)
        .map_err(|_| CaliptraApiError::SessionError("GetCertChainInfo command failed"))
}

/// Read a chunk of the full raw DER certificate chain for `(pki_entity_slot, algorithm)`.
pub fn caliptra_cmd_get_cert_chain(
    session: &mut CaliptraSession,
    pki_entity_slot: PkiEntitySlot,
    algorithm: AsymAlgo,
    offset: u32,
    length: u32,
) -> CaliptraResult<GetCertChainResponse> {
    let request = GetCertChainRequest::new(pki_entity_slot, algorithm, offset, length);
    session
        .execute_command_with_id(CaliptraCommandId::GetCertChain, &request)
        .map_err(|_| CaliptraApiError::SessionError("GetCertChain command failed"))
}

/// Write a chunk of an endorsement certificate chain (or erase when `offset == 0 && total_size == 0 && chunk.is_empty()`).
pub fn caliptra_cmd_set_cert_chain(
    session: &mut CaliptraSession,
    pki_entity_slot: PkiEntitySlot,
    algorithm: AsymAlgo,
    device_key_id: u32,
    offset: u32,
    total_size: u32,
    chunk: &[u8],
) -> CaliptraResult<SetCertChainResponse> {
    let request = SetCertChainRequest::new(
        pki_entity_slot,
        algorithm,
        device_key_id,
        offset,
        total_size,
        chunk,
    )
    .ok_or(CaliptraApiError::InvalidParameter(
        "SetCertChain chunk exceeds MAX_CERT_CHAIN_CHUNK_SIZE",
    ))?;
    session
        .execute_command_with_id(CaliptraCommandId::SetCertChain, &request)
        .map_err(|_| CaliptraApiError::SessionError("SetCertChain command failed"))
}
