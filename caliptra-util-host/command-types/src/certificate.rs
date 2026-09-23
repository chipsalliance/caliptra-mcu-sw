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

/// Maximum CSR data size (matches MAX_ATTESTED_CSR_RESP_DATA_SIZE on MCU side)
pub const MAX_CSR_DATA_SIZE: usize =
    caliptra_mcu_mbox_common::messages::MAX_ATTESTED_CSR_RESP_DATA_SIZE;

/// Export Attested CSR request
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExportAttestedCsrRequest {
    /// Device key identifier (0x0000=Discovery / KeyPairInventory, 0x0001=LDevID, 0x0002=FMC Alias, 0x0003=RT Alias)
    pub device_key_id: u32,
    /// Asymmetric algorithm (0x0001=ECC384, 0x0002=MLDSA87)
    pub algorithm: u32,
    /// 32-byte nonce for freshness
    pub nonce: [u8; 32],
}

impl ExportAttestedCsrRequest {
    pub const KEY_ID_DISCOVERY: u32 = 0x0000;
    pub const KEY_ID_LDEV_ID: u32 = 0x0001;
    pub const KEY_ID_FMC_ALIAS: u32 = 0x0002;
    pub const KEY_ID_RT_ALIAS: u32 = 0x0003;

    pub const ALGO_ECC384: u32 = 0x0001;
    pub const ALGO_MLDSA87: u32 = 0x0002;
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
        let len = self.data_len as usize;
        if len == 0 {
            return Err(AttestedCsrValidationError::Empty);
        }
        if len > MAX_CSR_DATA_SIZE {
            return Err(AttestedCsrValidationError::TooLarge(len));
        }
        Ok(len)
    }
}

// ============================================================================
// ExportIdevidCsr Command
// ============================================================================

/// Export IDevID CSR request (manufacturing mode only)
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExportIdevidCsrRequest {
    /// Asymmetric algorithm (0x0001=ECC384, 0x0002=MLDSA87)
    pub algorithm: u32,
}

/// Export IDevID CSR response
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExportIdevidCsrResponse {
    pub common: CommonResponse,
    /// Length of CSR data
    pub data_len: u32,
    /// CSR data (variable length, up to MAX_CSR_DATA_SIZE)
    pub csr_data: [u8; MAX_CSR_DATA_SIZE],
}

impl CommandRequest for ExportIdevidCsrRequest {
    type Response = ExportIdevidCsrResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::ExportIdevidCsr;
}

impl CommandResponse for ExportIdevidCsrResponse {}

impl ExportIdevidCsrResponse {
    /// Returns the IDevID CSR payload as a byte slice.
    pub fn csr_bytes(&self) -> &[u8] {
        let len = (self.data_len as usize).min(MAX_CSR_DATA_SIZE);
        &self.csr_data[..len]
    }

    /// Validates the CSR payload, returning Ok with the byte length on success.
    pub fn validate_csr_payload(&self) -> Result<usize, AttestedCsrValidationError> {
        let len = self.data_len as usize;
        if len == 0 {
            return Err(AttestedCsrValidationError::Empty);
        }
        if len > MAX_CSR_DATA_SIZE {
            return Err(AttestedCsrValidationError::TooLarge(len));
        }
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_attested_csr_request_constants() {
        assert_eq!(ExportAttestedCsrRequest::KEY_ID_DISCOVERY, 0x0000);
        assert_eq!(ExportAttestedCsrRequest::KEY_ID_LDEV_ID, 0x0001);
        assert_eq!(ExportAttestedCsrRequest::KEY_ID_FMC_ALIAS, 0x0002);
        assert_eq!(ExportAttestedCsrRequest::KEY_ID_RT_ALIAS, 0x0003);
        assert_eq!(ExportAttestedCsrRequest::ALGO_ECC384, 0x0001);
        assert_eq!(ExportAttestedCsrRequest::ALGO_MLDSA87, 0x0002);

        let req = ExportAttestedCsrRequest {
            device_key_id: ExportAttestedCsrRequest::KEY_ID_DISCOVERY,
            algorithm: ExportAttestedCsrRequest::ALGO_ECC384,
            nonce: [0x5A; 32],
        };
        assert_eq!(core::mem::size_of::<ExportAttestedCsrRequest>(), 40);
        let bytes = req.as_bytes();
        let parsed = ExportAttestedCsrRequest::read_from_bytes(bytes).unwrap();
        assert_eq!(parsed.device_key_id, 0);
        assert_eq!(parsed.algorithm, 1);
        assert_eq!(parsed.nonce, [0x5A; 32]);
    }
}
