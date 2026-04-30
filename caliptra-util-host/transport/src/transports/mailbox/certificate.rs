// Licensed under the Apache-2.0 license

//! Certificate commands for mailbox transport
//!
//! This module provides command definitions and implementations for certificate
//! commands using the mailbox transport protocol.

use super::checksum::calc_checksum;
use super::command_traits::*;
use caliptra_mcu_core_util_host_command_types::certificate::{
    ExportAttestedCsrRequest, ExportAttestedCsrResponse, MAX_CSR_DATA_SIZE,
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
