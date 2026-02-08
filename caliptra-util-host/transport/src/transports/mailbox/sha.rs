// Licensed under the Apache-2.0 license

//! SHA commands for mailbox transport
//!
//! This module provides command definitions and implementations for SHA hash
//! commands using the mailbox transport protocol.
//!
//! External mailbox command codes:
//! - MC_SHA_INIT   = 0x4D43_5349 ("MCSI")
//! - MC_SHA_UPDATE = 0x4D43_5355 ("MCSU")
//! - MC_SHA_FINAL  = 0x4D43_5346 ("MCSF")

extern crate alloc;

use super::checksum::calc_checksum;
use super::command_traits::*;
use alloc::vec::Vec;
use caliptra_util_host_command_types::crypto_hash::{
    ShaFinalRequest, ShaFinalResponse, ShaInitRequest, ShaInitResponse, ShaUpdateRequest,
    ShaUpdateResponse, MAX_HASH_SIZE, MAX_SHA_INPUT_SIZE, SHA_CONTEXT_SIZE,
};
use caliptra_util_host_command_types::CommonResponse;
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdShaInitRequest {
    pub chksum: u32,
    pub hash_algorithm: u32,
    pub input_size: u32,
    pub input: [u8; MAX_SHA_INPUT_SIZE],
}

impl Default for ExtCmdShaInitRequest {
    fn default() -> Self {
        Self {
            chksum: 0,
            hash_algorithm: 1, // SHA384
            input_size: 0,
            input: [0u8; MAX_SHA_INPUT_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdShaInitResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub context: [u8; SHA_CONTEXT_SIZE],
}

impl Default for ExtCmdShaInitResponse {
    fn default() -> Self {
        Self {
            chksum: 0,
            fips_status: 0,
            context: [0u8; SHA_CONTEXT_SIZE],
        }
    }
}

impl FromInternalRequest<ShaInitRequest> for ExtCmdShaInitRequest {
    fn from_internal(internal: &ShaInitRequest, command_code: u32) -> Self {
        // Build payload for checksum calculation
        let mut payload = Vec::new();
        payload.extend_from_slice(&internal.algorithm.to_le_bytes());
        payload.extend_from_slice(&internal.input_size.to_le_bytes());
        let input_len = core::cmp::min(internal.input_size as usize, MAX_SHA_INPUT_SIZE);
        payload.extend_from_slice(&internal.input[..input_len]);

        let chksum = calc_checksum(command_code, &payload);

        Self {
            chksum,
            hash_algorithm: internal.algorithm,
            input_size: internal.input_size,
            input: internal.input,
        }
    }
}

impl ToInternalResponse<ShaInitResponse> for ExtCmdShaInitResponse {
    fn to_internal(&self) -> ShaInitResponse {
        ShaInitResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            context: self.context,
        }
    }
}

impl VariableSizeBytes for ExtCmdShaInitRequest {}
impl VariableSizeBytes for ExtCmdShaInitResponse {}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdShaUpdateRequest {
    pub chksum: u32,
    pub context: [u8; SHA_CONTEXT_SIZE],
    pub input_size: u32,
    pub input: [u8; MAX_SHA_INPUT_SIZE],
}

impl Default for ExtCmdShaUpdateRequest {
    fn default() -> Self {
        Self {
            chksum: 0,
            context: [0u8; SHA_CONTEXT_SIZE],
            input_size: 0,
            input: [0u8; MAX_SHA_INPUT_SIZE],
        }
    }
}

pub type ExtCmdShaUpdateResponse = ExtCmdShaInitResponse;

impl FromInternalRequest<ShaUpdateRequest> for ExtCmdShaUpdateRequest {
    fn from_internal(internal: &ShaUpdateRequest, command_code: u32) -> Self {
        // Build payload for checksum calculation
        let mut payload = Vec::new();
        payload.extend_from_slice(&internal.context);
        payload.extend_from_slice(&internal.input_size.to_le_bytes());
        let input_len = core::cmp::min(internal.input_size as usize, MAX_SHA_INPUT_SIZE);
        payload.extend_from_slice(&internal.input[..input_len]);

        let chksum = calc_checksum(command_code, &payload);

        Self {
            chksum,
            context: internal.context,
            input_size: internal.input_size,
            input: internal.input,
        }
    }
}

impl VariableSizeBytes for ExtCmdShaUpdateRequest {}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdShaFinalRequest {
    pub chksum: u32,
    pub context: [u8; SHA_CONTEXT_SIZE],
    pub input_size: u32,
    pub input: [u8; MAX_SHA_INPUT_SIZE],
}

impl Default for ExtCmdShaFinalRequest {
    fn default() -> Self {
        Self {
            chksum: 0,
            context: [0u8; SHA_CONTEXT_SIZE],
            input_size: 0,
            input: [0u8; MAX_SHA_INPUT_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdShaFinalResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub data_len: u32,
    pub hash: [u8; MAX_HASH_SIZE],
}

impl Default for ExtCmdShaFinalResponse {
    fn default() -> Self {
        Self {
            chksum: 0,
            fips_status: 0,
            data_len: 0,
            hash: [0u8; MAX_HASH_SIZE],
        }
    }
}

impl FromInternalRequest<ShaFinalRequest> for ExtCmdShaFinalRequest {
    fn from_internal(internal: &ShaFinalRequest, command_code: u32) -> Self {
        // Build payload for checksum calculation
        let mut payload = Vec::new();
        payload.extend_from_slice(&internal.context);
        payload.extend_from_slice(&internal.input_size.to_le_bytes());
        let input_len = core::cmp::min(internal.input_size as usize, MAX_SHA_INPUT_SIZE);
        payload.extend_from_slice(&internal.input[..input_len]);

        let chksum = calc_checksum(command_code, &payload);

        Self {
            chksum,
            context: internal.context,
            input_size: internal.input_size,
            input: internal.input,
        }
    }
}

impl ToInternalResponse<ShaFinalResponse> for ExtCmdShaFinalResponse {
    fn to_internal(&self) -> ShaFinalResponse {
        ShaFinalResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            hash_size: self.data_len,
            hash: self.hash,
        }
    }
}

impl VariableSizeBytes for ExtCmdShaFinalRequest {}

impl VariableSizeBytes for ExtCmdShaFinalResponse {
    fn from_bytes_variable(bytes: &[u8]) -> Result<Self, crate::TransportError> {
        // Minimum size: chksum(4) + fips_status(4) + data_len(4) = 12 bytes
        if bytes.len() < 12 {
            return Err(crate::TransportError::InvalidMessage);
        }

        let chksum = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let fips_status = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let data_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);

        // Validate we have enough data for the hash
        let hash_len = core::cmp::min(data_len as usize, MAX_HASH_SIZE);
        if bytes.len() < 12 + hash_len {
            return Err(crate::TransportError::InvalidMessage);
        }

        let mut hash = [0u8; MAX_HASH_SIZE];
        hash[..hash_len].copy_from_slice(&bytes[12..12 + hash_len]);

        Ok(ExtCmdShaFinalResponse {
            chksum,
            fips_status,
            data_len,
            hash,
        })
    }

    fn to_bytes_variable(&self, buffer: &mut [u8]) -> usize {
        let header_size = 12;
        let hash_len = core::cmp::min(self.data_len as usize, MAX_HASH_SIZE);
        let total_size = header_size + hash_len;

        if buffer.len() < total_size {
            return 0;
        }

        buffer[0..4].copy_from_slice(&self.chksum.to_le_bytes());
        buffer[4..8].copy_from_slice(&self.fips_status.to_le_bytes());
        buffer[8..12].copy_from_slice(&self.data_len.to_le_bytes());
        buffer[12..12 + hash_len].copy_from_slice(&self.hash[..hash_len]);

        total_size
    }
}

// ============================================================================
// Command Metadata Definitions
// ============================================================================

use crate::define_command;

define_command!(
    ShaInitCmd,
    0x4D43_5349, // MC_SHA_INIT
    ShaInitRequest,
    ShaInitResponse,
    ExtCmdShaInitRequest,
    ExtCmdShaInitResponse
);

define_command!(
    ShaUpdateCmd,
    0x4D43_5355, // MC_SHA_UPDATE
    ShaUpdateRequest,
    ShaUpdateResponse,
    ExtCmdShaUpdateRequest,
    ExtCmdShaUpdateResponse
);

define_command!(
    ShaFinalCmd,
    0x4D43_5346, // MC_SHA_FINAL
    ShaFinalRequest,
    ShaFinalResponse,
    ExtCmdShaFinalRequest,
    ExtCmdShaFinalResponse
);
