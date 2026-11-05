// Licensed under the Apache-2.0 license

//! Certificate commands for mailbox transport
//!
//! This module provides command definitions and implementations for certificate
//! commands using the mailbox transport protocol.

use super::checksum::calc_checksum;
use super::command_traits::*;
use caliptra_mcu_core_util_host_command_types::certificate::{
    AuthSetCertChainRequest, AuthSetCertChainResponse, DpeSignerContextCertRequest,
    DpeSignerContextCertResponse, DpeSignerContextSignRequest, DpeSignerContextSignResponse,
    ExportAttestedCsrRequest, ExportAttestedCsrResponse, GetCertChainInfoRequest,
    GetCertChainInfoResponse, GetCertChainRequest, GetCertChainResponse, ProvisionIdevCertRequest,
    ProvisionIdevCertResponse, SetCertChainRequest, SetCertChainResponse, CERT_CHAIN_DIGEST_SIZE,
    MAX_CERT_CHAIN_CHUNK_SIZE, MAX_CSR_DATA_SIZE, MAX_DPE_SIGNER_CERT_SIZE,
    MAX_DPE_SIGNER_SIGN_DATA_SIZE, MAX_DPE_SIGNER_SIG_SIZE, MAX_IDEV_CERT_SIZE,
    MC_AUTH_SET_CERT_CHAIN_CANONICAL_CMD_ID,
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

// ============================================================================
// MC_PROVISION_IDEV_CERT Command (0x4D50_4943 - "MPIC")
// ============================================================================

/// External command: Provision IDevID certificate request (16 + `data_len` bytes)
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdProvisionIdevCertRequest {
    pub chksum: u32,
    pub algorithm: u32,
    pub mode: u32,
    pub data_len: u32,
    pub data: [u8; MAX_IDEV_CERT_SIZE],
}

/// External command: Provision IDevID certificate response (8 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdProvisionIdevCertResponse {
    pub chksum: u32,
    pub fips_status: u32,
}

impl FromInternalRequest<ProvisionIdevCertRequest> for ExtCmdProvisionIdevCertRequest {
    fn from_internal(internal: &ProvisionIdevCertRequest, command_code: u32) -> Self {
        let mut data = [0u8; MAX_IDEV_CERT_SIZE];
        let valid_len = (internal.data_len as usize).min(MAX_IDEV_CERT_SIZE);
        data[..valid_len].copy_from_slice(&internal.data[..valid_len]);

        let mut req = Self {
            chksum: 0,
            algorithm: internal.algorithm,
            mode: internal.mode,
            data_len: internal.data_len,
            data,
        };
        req.chksum = calc_checksum(command_code, &req.as_wire_bytes()[4..]);
        req
    }

    fn as_wire_bytes(&self) -> &[u8] {
        let valid_len = (self.data_len as usize).min(MAX_IDEV_CERT_SIZE);
        &self.as_bytes()[..16 + valid_len]
    }
}

impl ToInternalResponse<ProvisionIdevCertResponse> for ExtCmdProvisionIdevCertResponse {
    fn to_internal(&self) -> ProvisionIdevCertResponse {
        ProvisionIdevCertResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
        }
    }
}

impl VariableSizeBytes for ExtCmdProvisionIdevCertRequest {}
impl VariableSizeBytes for ExtCmdProvisionIdevCertResponse {}

define_command!(
    ProvisionIdevCertCmd,
    0x4D50_4943, // MC_PROVISION_IDEV_CERT - "MPIC"
    ProvisionIdevCertRequest,
    ProvisionIdevCertResponse,
    ExtCmdProvisionIdevCertRequest,
    ExtCmdProvisionIdevCertResponse
);

// ============================================================================
// MC_DPE_SIGNER_CONTEXT_CERT Command (0x4D44_5343 - "MDSC")
// ============================================================================

/// External command: DPE signer context certificate request (12 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdDpeSignerContextCertRequest {
    pub chksum: u32,
    pub target_fw_id: u32,
    pub algorithm: u32,
}

/// External command: DPE signer context certificate response (12 + `data_len` bytes)
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdDpeSignerContextCertResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub data_len: u32,
    pub cert_data: [u8; MAX_DPE_SIGNER_CERT_SIZE],
}

impl FromInternalRequest<DpeSignerContextCertRequest> for ExtCmdDpeSignerContextCertRequest {
    fn from_internal(internal: &DpeSignerContextCertRequest, command_code: u32) -> Self {
        let chksum = calc_checksum(command_code, internal.as_bytes());
        Self {
            chksum,
            target_fw_id: internal.target_fw_id,
            algorithm: internal.algorithm,
        }
    }
}

impl ToInternalResponse<DpeSignerContextCertResponse> for ExtCmdDpeSignerContextCertResponse {
    fn to_internal(&self) -> DpeSignerContextCertResponse {
        let mut cert_data = [0u8; MAX_DPE_SIGNER_CERT_SIZE];
        let data_len = (self.data_len as usize).min(MAX_DPE_SIGNER_CERT_SIZE);
        cert_data[..data_len].copy_from_slice(&self.cert_data[..data_len]);

        DpeSignerContextCertResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            data_len: self.data_len,
            cert_data,
        }
    }
}

impl VariableSizeBytes for ExtCmdDpeSignerContextCertRequest {}

impl VariableSizeBytes for ExtCmdDpeSignerContextCertResponse {
    fn from_bytes_variable(bytes: &[u8]) -> Result<Self, crate::TransportError> {
        if bytes.len() < 12 {
            return Err(crate::TransportError::InvalidMessage);
        }

        let chksum = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let fips_status = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let data_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);

        let data_len_usize = data_len as usize;
        if data_len_usize > MAX_DPE_SIGNER_CERT_SIZE || bytes.len() < 12 + data_len_usize {
            return Err(crate::TransportError::InvalidMessage);
        }

        let mut cert_data = [0u8; MAX_DPE_SIGNER_CERT_SIZE];
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
        let actual_len = (self.data_len as usize).min(MAX_DPE_SIGNER_CERT_SIZE);
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
    DpeSignerContextCertCmd,
    0x4D44_5343, // MC_DPE_SIGNER_CONTEXT_CERT - "MDSC"
    DpeSignerContextCertRequest,
    DpeSignerContextCertResponse,
    ExtCmdDpeSignerContextCertRequest,
    ExtCmdDpeSignerContextCertResponse
);

// ============================================================================
// MC_DPE_SIGNER_CONTEXT_SIGN Command (0x4D44_5353 - "MDSS")
// ============================================================================

/// External command: DPE signer context sign request (16 + 4096 = 4112 bytes)
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdDpeSignerContextSignRequest {
    pub chksum: u32,
    pub target_fw_id: u32,
    pub algorithm: u32,
    pub data_len: u32,
    pub data: [u8; MAX_DPE_SIGNER_SIGN_DATA_SIZE],
}

/// External command: DPE signer context sign response (12 + `data_len` bytes)
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdDpeSignerContextSignResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub data_len: u32,
    pub signature: [u8; MAX_DPE_SIGNER_SIG_SIZE],
}

impl FromInternalRequest<DpeSignerContextSignRequest> for ExtCmdDpeSignerContextSignRequest {
    fn from_internal(internal: &DpeSignerContextSignRequest, command_code: u32) -> Self {
        let mut data = [0u8; MAX_DPE_SIGNER_SIGN_DATA_SIZE];
        let valid_len = (internal.data_len as usize).min(MAX_DPE_SIGNER_SIGN_DATA_SIZE);
        data[..valid_len].copy_from_slice(&internal.data[..valid_len]);

        let mut req = Self {
            chksum: 0,
            target_fw_id: internal.target_fw_id,
            algorithm: internal.algorithm,
            data_len: internal.data_len,
            data,
        };
        req.chksum = calc_checksum(command_code, &req.as_bytes()[4..]);
        req
    }
}

// ============================================================================
// MC_AUTH_SET_CERT_CHAIN Command (0x0000_0012 -> target 0x4D41_5343 "MASC")
// ============================================================================

/// External mailbox request for `MC_AUTH_SET_CERT_CHAIN` (`0x0000_0012`, target `"MASC"`).
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdAuthSetCertChainRequest {
    pub chksum: u32,
    pub target: u32,
    pub internal: AuthSetCertChainRequest,
}

/// External mailbox response for `MC_AUTH_SET_CERT_CHAIN`.
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdAuthSetCertChainResponse {
    pub chksum: u32,
    pub fips_status: u32,
}

impl FromInternalRequest<AuthSetCertChainRequest> for ExtCmdAuthSetCertChainRequest {
    fn from_internal(internal: &AuthSetCertChainRequest, command_code: u32) -> Self {
        let mut req = Self {
            chksum: 0,
            target: MC_AUTH_SET_CERT_CHAIN_CANONICAL_CMD_ID,
            internal: internal.clone(),
        };
        req.chksum = calc_checksum(command_code, &req.as_bytes()[4..]);
        req
    }
}

impl ToInternalResponse<DpeSignerContextSignResponse> for ExtCmdDpeSignerContextSignResponse {
    fn to_internal(&self) -> DpeSignerContextSignResponse {
        let mut signature = [0u8; MAX_DPE_SIGNER_SIG_SIZE];
        let data_len = (self.data_len as usize).min(MAX_DPE_SIGNER_SIG_SIZE);
        signature[..data_len].copy_from_slice(&self.signature[..data_len]);

        DpeSignerContextSignResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            data_len: self.data_len,
            signature,
        }
    }
}

impl ToInternalResponse<AuthSetCertChainResponse> for ExtCmdAuthSetCertChainResponse {
    fn to_internal(&self) -> AuthSetCertChainResponse {
        AuthSetCertChainResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
        }
    }
}

impl VariableSizeBytes for ExtCmdDpeSignerContextSignRequest {}

impl VariableSizeBytes for ExtCmdDpeSignerContextSignResponse {
    fn from_bytes_variable(bytes: &[u8]) -> Result<Self, crate::TransportError> {
        if bytes.len() < 12 {
            return Err(crate::TransportError::InvalidMessage);
        }

        let chksum = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let fips_status = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let data_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);

        let data_len_usize = data_len as usize;
        if data_len_usize > MAX_DPE_SIGNER_SIG_SIZE || bytes.len() < 12 + data_len_usize {
            return Err(crate::TransportError::InvalidMessage);
        }

        let mut signature = [0u8; MAX_DPE_SIGNER_SIG_SIZE];
        signature[..data_len_usize].copy_from_slice(&bytes[12..12 + data_len_usize]);

        Ok(Self {
            chksum,
            fips_status,
            data_len,
            signature,
        })
    }

    fn to_bytes_variable(&self, buffer: &mut [u8]) -> usize {
        let header_size = 12;
        let actual_len = (self.data_len as usize).min(MAX_DPE_SIGNER_SIG_SIZE);
        let total_size = header_size + actual_len;

        if buffer.len() < total_size {
            return 0;
        }

        buffer[0..4].copy_from_slice(&self.chksum.to_le_bytes());
        buffer[4..8].copy_from_slice(&self.fips_status.to_le_bytes());
        buffer[8..12].copy_from_slice(&self.data_len.to_le_bytes());
        buffer[12..12 + actual_len].copy_from_slice(&self.signature[..actual_len]);

        total_size
    }
}

define_command!(
    DpeSignerContextSignCmd,
    0x4D44_5353, // MC_DPE_SIGNER_CONTEXT_SIGN - "MDSS"
    DpeSignerContextSignRequest,
    DpeSignerContextSignResponse,
    ExtCmdDpeSignerContextSignRequest,
    ExtCmdDpeSignerContextSignResponse
);

impl VariableSizeBytes for ExtCmdAuthSetCertChainRequest {}
impl VariableSizeBytes for ExtCmdAuthSetCertChainResponse {}

define_command!(
    AuthSetCertChainCmd,
    0x0000_0012, // MC_AUTHORIZED_COMMAND -> MC_AUTH_SET_CERT_CHAIN ("MASC")
    AuthSetCertChainRequest,
    AuthSetCertChainResponse,
    ExtCmdAuthSetCertChainRequest,
    ExtCmdAuthSetCertChainResponse
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

    #[test]
    fn provision_idevid_cert_request_serializes_variable_payload_and_checksum() {
        use caliptra_mcu_core_util_host_command_types::certificate::ProvisionIdevCertMode;

        assert_eq!(
            core::mem::size_of::<ExtCmdProvisionIdevCertRequest>(),
            16 + MAX_IDEV_CERT_SIZE
        );
        assert_eq!(core::mem::size_of::<ExtCmdProvisionIdevCertResponse>(), 8);

        let cert = [0x30u8, 0x03, 0x02, 0x01, 0x01];
        let mut req = ProvisionIdevCertRequest::new(
            AsymAlgo::EccP384,
            ProvisionIdevCertMode::WriteOtp,
            &cert,
        )
        .unwrap();
        req.data[cert.len()..cert.len() + 4].copy_from_slice(&[0xFF; 4]);

        let ext = ExtCmdProvisionIdevCertRequest::from_internal(&req, 0x4D50_4943);
        let wire = ext.as_wire_bytes();
        assert_eq!(wire.len(), 16 + cert.len());
        assert_eq!(&wire[16..], &cert);
        assert_eq!(ext.chksum, calc_checksum(0x4D50_4943, &wire[4..]));
    }

    #[test]
    fn dpe_signer_context_cert_round_trips() {
        assert_eq!(
            core::mem::size_of::<ExtCmdDpeSignerContextCertRequest>(),
            12
        );

        let internal = DpeSignerContextCertRequest::new(0x10, AsymAlgo::EccP384);
        let ext_req = ExtCmdDpeSignerContextCertRequest::from_internal(&internal, 0x4D44_5343);
        let req_bytes = ext_req.as_bytes();
        assert_eq!(req_bytes[4..8], 0x10u32.to_le_bytes());
        assert_eq!(req_bytes[8..12], (AsymAlgo::EccP384 as u32).to_le_bytes());

        let cert = [0x30u8, 0x82, 0x01, 0x10, 0xAA, 0xBB];
        let mut raw = vec![0u8; 12 + cert.len()];
        raw[8..12].copy_from_slice(&(cert.len() as u32).to_le_bytes());
        raw[12..].copy_from_slice(&cert);

        let ext_resp = ExtCmdDpeSignerContextCertResponse::from_bytes_variable(&raw).unwrap();
        let internal_resp = ext_resp.to_internal();
        assert_eq!(internal_resp.cert_bytes(), &cert);

        let mut roundtrip = vec![0u8; raw.len()];
        let n = ext_resp.to_bytes_variable(&mut roundtrip);
        assert_eq!(n, raw.len());
        assert_eq!(roundtrip, raw);
    }

    #[test]
    fn dpe_signer_context_sign_zero_pads_tail_and_round_trips() {
        assert_eq!(
            core::mem::size_of::<ExtCmdDpeSignerContextSignRequest>(),
            4112
        );

        let digest = [0x42u8; 48];
        let mut req = DpeSignerContextSignRequest::new(0, AsymAlgo::EccP384, &digest).unwrap();
        req.data[digest.len()..digest.len() + 4].copy_from_slice(&[0xFF; 4]);

        let ext_req = ExtCmdDpeSignerContextSignRequest::from_internal(&req, 0x4D44_5353);
        assert!(ext_req.data[digest.len()..].iter().all(|&b| b == 0));
        assert_eq!(
            ext_req.chksum,
            calc_checksum(0x4D44_5353, &ext_req.as_bytes()[4..16 + digest.len()])
        );

        let sig = [0x5Au8; 96];
        let mut raw = vec![0u8; 12 + sig.len()];
        raw[8..12].copy_from_slice(&(sig.len() as u32).to_le_bytes());
        raw[12..].copy_from_slice(&sig);

        let ext_resp = ExtCmdDpeSignerContextSignResponse::from_bytes_variable(&raw).unwrap();
        let internal_resp = ext_resp.to_internal();
        assert_eq!(internal_resp.signature_bytes(), &sig);
    }

    #[test]
    fn auth_set_cert_chain_request_wraps_target_and_checksum() {
        let req = AuthSetCertChainRequest {
            pki_entity_slot: PkiEntitySlot::Owner as u32,
            algorithm: AsymAlgo::EccP384 as u32,
            total_size: 512,
            expected_sha384: [0x5A; CERT_CHAIN_DIGEST_SIZE],
            metadata: Default::default(),
            nonce: [0x11; 48],
            ecc_pub_x: [0x22; 48],
            ecc_pub_y: [0x33; 48],
            mldsa_pub: [0x44; 2592],
            sig: Default::default(),
        };
        let ext = ExtCmdAuthSetCertChainRequest::from_internal(&req, 0x0000_0012);
        assert_eq!(ext.target, MC_AUTH_SET_CERT_CHAIN_CANONICAL_CMD_ID);
        assert_eq!(ext.chksum, calc_checksum(0x0000_0012, &ext.as_bytes()[4..]));
    }
}
