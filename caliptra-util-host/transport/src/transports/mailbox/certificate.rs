// Licensed under the Apache-2.0 license

//! Certificate commands for mailbox transport
//!
//! This module provides command definitions and implementations for certificate
//! commands using the mailbox transport protocol.

use super::checksum::calc_checksum;
use super::command_traits::*;
use caliptra_mcu_core_util_host_command_types::certificate::{
    ExportAttestedCsrRequest, ExportAttestedCsrResponse, GetCertChainInfoRequest,
    GetCertChainInfoResponse, GetCertChainRequest, GetCertChainResponse, SetCertChainRequest,
    SetCertChainResponse, CERT_CHAIN_DIGEST_SIZE, MAX_CERT_CHAIN_CHUNK_SIZE, MAX_CSR_DATA_SIZE,
};
use caliptra_mcu_core_util_host_command_types::CommonResponse;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub use super::command_traits::{process_command, process_command_with_metadata};

// ============================================================================
// MC_EXPORT_ATTESTED_CSR Command (0x4D45_4143 - "MEAC")
// ============================================================================

/// External command: Export attested CSR request
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdExportAttestedCsrRequest {
    /// Checksum over input data
    pub chksum: u32,
    /// Device key identifier
    pub device_key_id: u32,
    /// Asymmetric algorithm
    pub algorithm: u32,
    /// 32-byte nonce for freshness
    pub nonce: [u8; 32],
}

/// External command: Export attested CSR response
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdExportAttestedCsrResponse {
    /// Checksum field
    pub chksum: u32,
    /// FIPS approved or an error
    pub fips_status: u32,
    /// Length of CSR data
    pub data_len: u32,
    /// CSR data (variable length)
    pub csr_data: [u8; MAX_CSR_DATA_SIZE],
}

impl FromInternalRequest<ExportAttestedCsrRequest> for ExtCmdExportAttestedCsrRequest {
    fn from_internal(internal: &ExportAttestedCsrRequest, command_code: u32) -> Self {
        let chksum = calc_checksum(command_code, internal.as_bytes());
        Self {
            chksum,
            device_key_id: internal.device_key_id,
            algorithm: internal.algorithm,
            nonce: internal.nonce,
        }
    }
}

impl ToInternalResponse<ExportAttestedCsrResponse> for ExtCmdExportAttestedCsrResponse {
    fn to_internal(&self) -> ExportAttestedCsrResponse {
        let mut csr_data = [0u8; MAX_CSR_DATA_SIZE];
        let data_len = (self.data_len as usize).min(MAX_CSR_DATA_SIZE);
        csr_data[..data_len].copy_from_slice(&self.csr_data[..data_len]);

        ExportAttestedCsrResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            data_len: self.data_len,
            csr_data,
        }
    }
}

impl VariableSizeBytes for ExtCmdExportAttestedCsrRequest {}

impl VariableSizeBytes for ExtCmdExportAttestedCsrResponse {
    fn from_bytes_variable(bytes: &[u8]) -> Result<Self, crate::TransportError> {
        if bytes.len() < 12 {
            return Err(crate::TransportError::InvalidMessage);
        }

        let chksum = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let fips_status = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let data_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);

        let data_len_usize = data_len as usize;
        if data_len_usize > MAX_CSR_DATA_SIZE || bytes.len() < 12 + data_len_usize {
            return Err(crate::TransportError::InvalidMessage);
        }

        let mut csr_data = [0u8; MAX_CSR_DATA_SIZE];
        csr_data[..data_len_usize].copy_from_slice(&bytes[12..12 + data_len_usize]);

        Ok(ExtCmdExportAttestedCsrResponse {
            chksum,
            fips_status,
            data_len,
            csr_data,
        })
    }

    fn to_bytes_variable(&self, buffer: &mut [u8]) -> usize {
        let header_size = 12;
        let actual_len = (self.data_len as usize).min(MAX_CSR_DATA_SIZE);
        let total_size = header_size + actual_len;

        if buffer.len() < total_size {
            return 0;
        }

        buffer[0..4].copy_from_slice(&self.chksum.to_le_bytes());
        buffer[4..8].copy_from_slice(&self.fips_status.to_le_bytes());
        buffer[8..12].copy_from_slice(&self.data_len.to_le_bytes());
        buffer[12..12 + actual_len].copy_from_slice(&self.csr_data[..actual_len]);

        total_size
    }
}

// ============================================================================
// Command Metadata Definition
// ============================================================================

use crate::define_command;

define_command!(
    ExportAttestedCsrCmd,
    0x4D45_4143, // MC_EXPORT_ATTESTED_CSR - "MEAC"
    ExportAttestedCsrRequest,
    ExportAttestedCsrResponse,
    ExtCmdExportAttestedCsrRequest,
    ExtCmdExportAttestedCsrResponse
);

// ============================================================================
// MC_GET_CERT_CHAIN_INFO Command (0x4D47_4349 - "MGCI")
// ============================================================================

/// External command: Get certificate chain info request (12 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdGetCertChainInfoRequest {
    pub chksum: u32,
    pub pki_entity_slot: u32,
    pub algorithm: u32,
}

/// External command: Get certificate chain info response (64 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdGetCertChainInfoResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub device_key_id: u32,
    pub chain_len: u32,
    pub chain_digest: [u8; CERT_CHAIN_DIGEST_SIZE],
}

impl FromInternalRequest<GetCertChainInfoRequest> for ExtCmdGetCertChainInfoRequest {
    fn from_internal(internal: &GetCertChainInfoRequest, command_code: u32) -> Self {
        let chksum = calc_checksum(command_code, internal.as_bytes());
        Self {
            chksum,
            pki_entity_slot: internal.pki_entity_slot,
            algorithm: internal.algorithm,
        }
    }
}

impl ToInternalResponse<GetCertChainInfoResponse> for ExtCmdGetCertChainInfoResponse {
    fn to_internal(&self) -> GetCertChainInfoResponse {
        GetCertChainInfoResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            device_key_id: self.device_key_id,
            chain_len: self.chain_len,
            chain_digest: self.chain_digest,
        }
    }
}

impl VariableSizeBytes for ExtCmdGetCertChainInfoRequest {}
impl VariableSizeBytes for ExtCmdGetCertChainInfoResponse {}

define_command!(
    GetCertChainInfoCmd,
    0x4D47_4349, // MC_GET_CERT_CHAIN_INFO - "MGCI"
    GetCertChainInfoRequest,
    GetCertChainInfoResponse,
    ExtCmdGetCertChainInfoRequest,
    ExtCmdGetCertChainInfoResponse
);

// ============================================================================
// MC_GET_CERT_CHAIN Command (0x4D47_4343 - "MGCC")
// ============================================================================

/// External command: Get certificate chain request (20 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdGetCertChainRequest {
    pub chksum: u32,
    pub pki_entity_slot: u32,
    pub algorithm: u32,
    pub offset: u32,
    pub length: u32,
}

/// External command: Get certificate chain response (12 + `data_len` bytes)
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdGetCertChainResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub data_len: u32,
    pub cert_data: [u8; MAX_CERT_CHAIN_CHUNK_SIZE],
}

impl FromInternalRequest<GetCertChainRequest> for ExtCmdGetCertChainRequest {
    fn from_internal(internal: &GetCertChainRequest, command_code: u32) -> Self {
        let chksum = calc_checksum(command_code, internal.as_bytes());
        Self {
            chksum,
            pki_entity_slot: internal.pki_entity_slot,
            algorithm: internal.algorithm,
            offset: internal.offset,
            length: internal.length,
        }
    }
}

impl ToInternalResponse<GetCertChainResponse> for ExtCmdGetCertChainResponse {
    fn to_internal(&self) -> GetCertChainResponse {
        let mut cert_data = [0u8; MAX_CERT_CHAIN_CHUNK_SIZE];
        let data_len = (self.data_len as usize).min(MAX_CERT_CHAIN_CHUNK_SIZE);
        cert_data[..data_len].copy_from_slice(&self.cert_data[..data_len]);

        GetCertChainResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            data_len: self.data_len,
            cert_data,
        }
    }
}

impl VariableSizeBytes for ExtCmdGetCertChainRequest {}

impl VariableSizeBytes for ExtCmdGetCertChainResponse {
    fn from_bytes_variable(bytes: &[u8]) -> Result<Self, crate::TransportError> {
        if bytes.len() < 12 {
            return Err(crate::TransportError::InvalidMessage);
        }

        let chksum = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let fips_status = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let data_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);

        let data_len_usize = data_len as usize;
        if data_len_usize > MAX_CERT_CHAIN_CHUNK_SIZE || bytes.len() < 12 + data_len_usize {
            return Err(crate::TransportError::InvalidMessage);
        }

        let mut cert_data = [0u8; MAX_CERT_CHAIN_CHUNK_SIZE];
        cert_data[..data_len_usize].copy_from_slice(&bytes[12..12 + data_len_usize]);

        Ok(Self {
            chksum,
            fips_status,
            data_len,
            cert_data,
        })
    }

    fn to_bytes_variable(&self, buffer: &mut [u8]) -> usize {
        let header_size = 12;
        let actual_len = (self.data_len as usize).min(MAX_CERT_CHAIN_CHUNK_SIZE);
        let total_size = header_size + actual_len;

        if buffer.len() < total_size {
            return 0;
        }

        buffer[0..4].copy_from_slice(&self.chksum.to_le_bytes());
        buffer[4..8].copy_from_slice(&self.fips_status.to_le_bytes());
        buffer[8..12].copy_from_slice(&self.data_len.to_le_bytes());
        buffer[12..12 + actual_len].copy_from_slice(&self.cert_data[..actual_len]);

        total_size
    }
}

define_command!(
    GetCertChainCmd,
    0x4D47_4343, // MC_GET_CERT_CHAIN - "MGCC"
    GetCertChainRequest,
    GetCertChainResponse,
    ExtCmdGetCertChainRequest,
    ExtCmdGetCertChainResponse
);

// ============================================================================
// MC_SET_CERT_CHAIN Command (0x4D53_4343 - "MSCC")
// ============================================================================

/// External command: Set certificate chain request (28 + `data_len` or 4124 bytes)
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdSetCertChainRequest {
    pub chksum: u32,
    pub pki_entity_slot: u32,
    pub algorithm: u32,
    pub device_key_id: u32,
    pub offset: u32,
    pub total_size: u32,
    pub data_len: u32,
    pub cert_data: [u8; MAX_CERT_CHAIN_CHUNK_SIZE],
}

/// External command: Set certificate chain response (8 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdSetCertChainResponse {
    pub chksum: u32,
    pub fips_status: u32,
}

impl FromInternalRequest<SetCertChainRequest> for ExtCmdSetCertChainRequest {
    fn from_internal(internal: &SetCertChainRequest, command_code: u32) -> Self {
        let mut cert_data = [0u8; MAX_CERT_CHAIN_CHUNK_SIZE];
        let valid_len = (internal.data_len as usize).min(MAX_CERT_CHAIN_CHUNK_SIZE);
        cert_data[..valid_len].copy_from_slice(&internal.cert_data[..valid_len]);

        let mut req = Self {
            chksum: 0,
            pki_entity_slot: internal.pki_entity_slot,
            algorithm: internal.algorithm,
            device_key_id: internal.device_key_id,
            offset: internal.offset,
            total_size: internal.total_size,
            data_len: internal.data_len,
            cert_data,
        };
        req.chksum = calc_checksum(command_code, &req.as_bytes()[4..]);
        req
    }
}

impl ToInternalResponse<SetCertChainResponse> for ExtCmdSetCertChainResponse {
    fn to_internal(&self) -> SetCertChainResponse {
        SetCertChainResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
        }
    }
}

impl VariableSizeBytes for ExtCmdSetCertChainRequest {}
impl VariableSizeBytes for ExtCmdSetCertChainResponse {}

define_command!(
    SetCertChainCmd,
    0x4D53_4343, // MC_SET_CERT_CHAIN - "MSCC"
    SetCertChainRequest,
    SetCertChainResponse,
    ExtCmdSetCertChainRequest,
    ExtCmdSetCertChainResponse
);

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use caliptra_mcu_core_util_host_command_types::attestation::{AsymAlgo, PkiEntitySlot};

    #[test]
    fn get_cert_chain_info_wire_layout_matches_device_struct() {
        assert_eq!(core::mem::size_of::<ExtCmdGetCertChainInfoRequest>(), 12);
        assert_eq!(core::mem::size_of::<ExtCmdGetCertChainInfoResponse>(), 64);

        let internal = GetCertChainInfoRequest::new(PkiEntitySlot::Owner, AsymAlgo::EccP384);
        let ext = ExtCmdGetCertChainInfoRequest::from_internal(&internal, 0x4D47_4349);
        let bytes = ext.as_bytes();
        assert_eq!(bytes[4..8], (PkiEntitySlot::Owner as u32).to_le_bytes());
        assert_eq!(bytes[8..12], (AsymAlgo::EccP384 as u32).to_le_bytes());

        let resp_ext = ExtCmdGetCertChainInfoResponse {
            chksum: 0,
            fips_status: 0,
            device_key_id: 1,
            chain_len: 1742,
            chain_digest: [0xAB; CERT_CHAIN_DIGEST_SIZE],
        };
        let resp_internal = resp_ext.to_internal();
        assert_eq!(resp_internal.device_key_id, 1);
        assert_eq!(resp_internal.chain_len, 1742);
        assert_eq!(resp_internal.chain_digest, [0xAB; CERT_CHAIN_DIGEST_SIZE]);
    }

    #[test]
    fn get_cert_chain_variable_response_round_trips() {
        assert_eq!(core::mem::size_of::<ExtCmdGetCertChainRequest>(), 20);

        let chunk = [0x30u8, 0x82, 0x01, 0x20, 0x55, 0xAA];
        let mut raw = vec![0u8; 12 + chunk.len()];
        raw[8..12].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
        raw[12..].copy_from_slice(&chunk);

        let ext = ExtCmdGetCertChainResponse::from_bytes_variable(&raw).unwrap();
        let internal = ext.to_internal();
        assert_eq!(internal.cert_bytes(), &chunk);

        let mut roundtrip = vec![0u8; raw.len()];
        let n = ext.to_bytes_variable(&mut roundtrip);
        assert_eq!(n, raw.len());
        assert_eq!(roundtrip, raw);
    }

    #[test]
    fn set_cert_chain_request_zero_pads_tail_for_checksum() {
        assert_eq!(core::mem::size_of::<ExtCmdSetCertChainRequest>(), 4124);
        assert_eq!(core::mem::size_of::<ExtCmdSetCertChainResponse>(), 8);

        let chunk = [0x30u8, 0x03, 0x02, 0x01, 0x00];
        let mut req = SetCertChainRequest::new(
            PkiEntitySlot::Tenant,
            AsymAlgo::EccP384,
            1,
            0,
            chunk.len() as u32,
            &chunk,
        )
        .unwrap();
        // Dirty trailing bytes in the internal struct; `from_internal` must zero them.
        req.cert_data[chunk.len()..chunk.len() + 4].copy_from_slice(&[0xFF; 4]);

        let ext = ExtCmdSetCertChainRequest::from_internal(&req, 0x4D53_4343);
        assert!(ext.cert_data[chunk.len()..].iter().all(|&b| b == 0));
        assert_eq!(
            ext.chksum,
            calc_checksum(0x4D53_4343, &ext.as_bytes()[4..28 + chunk.len()])
        );
    }
}
