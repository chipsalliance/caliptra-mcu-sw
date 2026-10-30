// Licensed under the Apache-2.0 license

//! Certificate Management Commands
//!
//! Command structures for certificate operations

use crate::attestation::{AsymAlgo, PkiEntitySlot};
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

// ============================================================================
// MC_GET_CERT_CHAIN_INFO / MC_GET_CERT_CHAIN / MC_SET_CERT_CHAIN Commands
// ============================================================================

/// Maximum chunk size for certificate chain reads and writes (4 KiB).
pub const MAX_CERT_CHAIN_CHUNK_SIZE: usize = caliptra_mcu_mbox_common::messages::MAX_RESP_DATA_SIZE;

/// SHA-384 digest byte length for `MC_GET_CERT_CHAIN_INFO`.
pub const CERT_CHAIN_DIGEST_SIZE: usize = 48;

/// Request for `MC_GET_CERT_CHAIN_INFO` (`0x4D47_4349`, `"MGCI"`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable)]
pub struct GetCertChainInfoRequest {
    /// PKI entity slot (`PkiEntitySlot` wire value).
    pub pki_entity_slot: u32,
    /// Asymmetric algorithm (`AsymAlgo` wire value).
    pub algorithm: u32,
}

impl GetCertChainInfoRequest {
    pub const fn new(pki_entity_slot: PkiEntitySlot, algorithm: AsymAlgo) -> Self {
        Self {
            pki_entity_slot: pki_entity_slot as u32,
            algorithm: algorithm as u32,
        }
    }
}

/// Response for `MC_GET_CERT_CHAIN_INFO` (`0x4D47_4349`, `"MGCI"`).
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct GetCertChainInfoResponse {
    pub common: CommonResponse,
    /// Logical Caliptra device key bound to the slot's endorsement chain.
    pub device_key_id: u32,
    /// Total byte length of the full DER certificate chain.
    pub chain_len: u32,
    /// SHA-384 digest over the concatenated DER certificates from root CA to leaf.
    pub chain_digest: [u8; CERT_CHAIN_DIGEST_SIZE],
}

impl CommandRequest for GetCertChainInfoRequest {
    type Response = GetCertChainInfoResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::GetCertChainInfo;
}

impl CommandResponse for GetCertChainInfoResponse {}

/// Request for `MC_GET_CERT_CHAIN` (`0x4D47_4343`, `"MGCC"`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable)]
pub struct GetCertChainRequest {
    /// PKI entity slot (`PkiEntitySlot` wire value).
    pub pki_entity_slot: u32,
    /// Asymmetric algorithm (`AsymAlgo` wire value).
    pub algorithm: u32,
    /// Byte offset into the full DER certificate chain.
    pub offset: u32,
    /// Maximum number of bytes to read in this chunk (1..=`MAX_CERT_CHAIN_CHUNK_SIZE`).
    pub length: u32,
}

impl GetCertChainRequest {
    pub const fn new(
        pki_entity_slot: PkiEntitySlot,
        algorithm: AsymAlgo,
        offset: u32,
        length: u32,
    ) -> Self {
        Self {
            pki_entity_slot: pki_entity_slot as u32,
            algorithm: algorithm as u32,
            offset,
            length,
        }
    }
}

/// Response for `MC_GET_CERT_CHAIN` (`0x4D47_4343`, `"MGCC"`).
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct GetCertChainResponse {
    pub common: CommonResponse,
    /// Number of valid bytes in `cert_data`.
    pub data_len: u32,
    /// Raw DER certificate chain chunk bytes.
    pub cert_data: [u8; MAX_CERT_CHAIN_CHUNK_SIZE],
}

impl GetCertChainResponse {
    /// Returns the valid slice of `cert_data` (`..data_len`).
    pub fn cert_bytes(&self) -> &[u8] {
        let len = (self.data_len as usize).min(MAX_CERT_CHAIN_CHUNK_SIZE);
        &self.cert_data[..len]
    }
}

impl CommandRequest for GetCertChainRequest {
    type Response = GetCertChainResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::GetCertChain;
}

impl CommandResponse for GetCertChainResponse {}

/// Request for `MC_SET_CERT_CHAIN` (`0x4D53_4343`, `"MSCC"`).
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct SetCertChainRequest {
    /// Target PKI entity slot (`PkiEntitySlot` wire value).
    pub pki_entity_slot: u32,
    /// Asymmetric algorithm (`AsymAlgo` wire value).
    pub algorithm: u32,
    /// Logical Caliptra device key signed by the endorsement chain's leaf CA (`0` for policy default).
    pub device_key_id: u32,
    /// Byte offset of this chunk within the endorsement chain.
    pub offset: u32,
    /// Total byte length of the complete endorsement chain being provisioned (`0` to erase at `offset == 0 && data_len == 0`).
    pub total_size: u32,
    /// Number of valid bytes in `cert_data` (`0..=MAX_CERT_CHAIN_CHUNK_SIZE`).
    pub data_len: u32,
    /// Endorsement DER chunk bytes.
    pub cert_data: [u8; MAX_CERT_CHAIN_CHUNK_SIZE],
}

impl SetCertChainRequest {
    pub fn new(
        pki_entity_slot: PkiEntitySlot,
        algorithm: AsymAlgo,
        device_key_id: u32,
        offset: u32,
        total_size: u32,
        chunk: &[u8],
    ) -> Option<Self> {
        if chunk.len() > MAX_CERT_CHAIN_CHUNK_SIZE {
            return None;
        }
        let mut cert_data = [0u8; MAX_CERT_CHAIN_CHUNK_SIZE];
        cert_data[..chunk.len()].copy_from_slice(chunk);
        Some(Self {
            pki_entity_slot: pki_entity_slot as u32,
            algorithm: algorithm as u32,
            device_key_id,
            offset,
            total_size,
            data_len: chunk.len() as u32,
            cert_data,
        })
    }
}

/// Response for `MC_SET_CERT_CHAIN` (`0x4D53_4343`, `"MSCC"`).
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct SetCertChainResponse {
    pub common: CommonResponse,
}

impl CommandRequest for SetCertChainRequest {
    type Response = SetCertChainResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::SetCertChain;
}

impl CommandResponse for SetCertChainResponse {}

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
