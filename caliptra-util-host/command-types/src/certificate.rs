// Licensed under the Apache-2.0 license

//! Certificate Management Commands
//!
//! Command structures for certificate operations

use crate::{CaliptraCommandId, CommandRequest, CommandResponse, CommonResponse};
use zerocopy::{FromBytes, Immutable, IntoBytes};

// Placeholder certificate commands - implement as needed
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct GetIdevidCertRequest {
    // Implementation TBD
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct GetIdevidCertResponse {
    pub common: CommonResponse,
    // Implementation TBD
}

impl CommandRequest for GetIdevidCertRequest {
    type Response = GetIdevidCertResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::GetIdevidCert;
}

impl CommandResponse for GetIdevidCertResponse {}

/// Generic Get Certificate Request
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct GetCertificateRequest {
    /// Certificate index to retrieve
    pub index: u32,
}

/// Generic Get Certificate Response
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct GetCertificateResponse {
    pub common: CommonResponse,
    /// Size of the certificate data
    pub data_size: u32,
    /// Certificate data
    pub cert_data: [u8; 1024],
}

impl CommandRequest for GetCertificateRequest {
    type Response = GetCertificateResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::GetCertificate;
}

impl CommandResponse for GetCertificateResponse {}

/// Generic Set Certificate Request
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct SetCertificateRequest {
    /// Certificate index to set
    pub index: u32,
    /// Size of the certificate data
    pub data_size: u32,
    /// Certificate data
    pub cert_data: [u8; 1024],
}

/// Generic Set Certificate Response
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct SetCertificateResponse {
    pub common: CommonResponse,
}

impl CommandRequest for SetCertificateRequest {
    type Response = SetCertificateResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::SetCertificate;
}

impl CommandResponse for SetCertificateResponse {}

// ============================================================================
// ExportAttestedCsr Command
// ============================================================================

/// Maximum CSR data size (matches MAX_RESP_DATA_SIZE on MCU side)
pub const MAX_CSR_DATA_SIZE: usize = 4 * 1024;

/// Export Attested CSR request
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExportAttestedCsrRequest {
    /// Device key identifier (0x0001=LDevID, 0x0002=FMC Alias, 0x0003=RT Alias)
    pub device_key_id: u32,
    /// Asymmetric algorithm (0x0001=ECC384, 0x0002=MLDSA87)
    pub algorithm: u32,
    /// 32-byte nonce for freshness
    pub nonce: [u8; 32],
}

/// Export Attested CSR response
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExportAttestedCsrResponse {
    pub common: CommonResponse,
    /// Length of CSR data
    pub data_len: u32,
    /// CSR data (variable length, up to MAX_CSR_DATA_SIZE)
    pub csr_data: [u8; MAX_CSR_DATA_SIZE],
}

impl CommandRequest for ExportAttestedCsrRequest {
    type Response = ExportAttestedCsrResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::ExportAttestedCsr;
}

impl CommandResponse for ExportAttestedCsrResponse {}

/// Errors from CSR payload validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestedCsrValidationError {
    /// CSR data is empty (data_len == 0)
    Empty,
    /// CSR data exceeds maximum allowed size
    TooLarge(usize),
}

impl ExportAttestedCsrResponse {
    /// Returns the attested CSR payload as a byte slice (CoseSign1 structure).
    pub fn csr_bytes(&self) -> &[u8] {
        let len = (self.data_len as usize).min(MAX_CSR_DATA_SIZE);
        &self.csr_data[..len]
    }

    /// Validates the CSR payload, returning Ok with the byte length on success.
    pub fn validate_csr_payload(&self) -> Result<usize, AttestedCsrValidationError> {
        let csr = self.csr_bytes();
        if csr.is_empty() {
            return Err(AttestedCsrValidationError::Empty);
        }
        if csr.len() > MAX_CSR_DATA_SIZE {
            return Err(AttestedCsrValidationError::TooLarge(csr.len()));
        }
        Ok(csr.len())
    }
}
