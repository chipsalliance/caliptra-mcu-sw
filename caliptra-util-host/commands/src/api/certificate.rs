// Licensed under the Apache-2.0 license

//! Certificate API functions
//!
//! High-level functions for certificate operations with Caliptra.

use crate::api::{CaliptraApiError, CaliptraResult};
use caliptra_mcu_core_util_host_command_types::{
    certificate::{
        ExportAttestedCsrRequest, ExportAttestedCsrResponse, ExportIdevidCsrRequest,
        ExportIdevidCsrResponse,
    },
    CaliptraCommandId,
};
use caliptra_util_host_session::CaliptraSession;

/// Export an attested CSR from the device
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
/// - `device_key_id`: Device key identifier (0x0001=LDevID, 0x0002=FMC Alias, 0x0003=RT Alias)
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
