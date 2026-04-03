// Licensed under the Apache-2.0 license

//! HMAC commands for mailbox transport
//!
//! This module provides command definitions and implementations for HMAC
//! commands using the mailbox transport protocol.
//!
//! External mailbox command codes:
//! - MC_HMAC           = 0x4D43_484D ("MCHM")
//! - MC_HMAC_KDF_COUNTER = 0x4D43_4B43 ("MCKC")

extern crate alloc;

use alloc::vec::Vec;

use super::checksum::calc_checksum;
use super::command_traits::*;
use caliptra_util_host_command_types::crypto_hmac::{
    CmKeyUsage, Cmk, HmacAlgorithm, HmacKdfCounterRequest, HmacKdfCounterResponse, HmacRequest,
    HmacResponse, CMK_SIZE, MAX_HMAC_INPUT_SIZE, MAX_HMAC_SIZE,
};
use caliptra_util_host_command_types::CommonResponse;
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdHmacRequest {
    pub chksum: u32,
    pub cmk: [u8; CMK_SIZE],
    pub hash_algorithm: u32,
    pub data_size: u32,
    pub data: [u8; MAX_HMAC_INPUT_SIZE],
}

impl Default for ExtCmdHmacRequest {
    fn default() -> Self {
        Self {
            chksum: 0,
            cmk: [0u8; CMK_SIZE],
            hash_algorithm: HmacAlgorithm::Sha384 as u32,
            data_size: 0,
            data: [0u8; MAX_HMAC_INPUT_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdHmacResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub data_len: u32,
    pub mac: [u8; MAX_HMAC_SIZE],
}

impl Default for ExtCmdHmacResponse {
    fn default() -> Self {
        Self {
            chksum: 0,
            fips_status: 0,
            data_len: 0,
            mac: [0u8; MAX_HMAC_SIZE],
        }
    }
}

impl FromInternalRequest<HmacRequest> for ExtCmdHmacRequest {
    fn from_internal(internal: &HmacRequest, command_code: u32) -> Self {
        // Build payload for checksum calculation
        let mut payload = Vec::new();
        payload.extend_from_slice(&internal.cmk.0);
        payload.extend_from_slice(&internal.hash_algorithm.to_le_bytes());
        payload.extend_from_slice(&internal.data_size.to_le_bytes());
        let data_len = core::cmp::min(internal.data_size as usize, MAX_HMAC_INPUT_SIZE);
        payload.extend_from_slice(&internal.data[..data_len]);

        let chksum = calc_checksum(command_code, &payload);

        Self {
            chksum,
            cmk: internal.cmk.0,
            hash_algorithm: internal.hash_algorithm,
            data_size: internal.data_size,
            data: internal.data,
        }
    }
}

impl ToInternalResponse<HmacResponse> for ExtCmdHmacResponse {
    fn to_internal(&self) -> HmacResponse {
        HmacResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            mac_size: self.data_len,
            mac: self.mac,
        }
    }
}

impl VariableSizeBytes for ExtCmdHmacRequest {}

impl VariableSizeBytes for ExtCmdHmacResponse {
    fn from_bytes_variable(bytes: &[u8]) -> Result<Self, crate::TransportError> {
        // Minimum size: chksum(4) + fips_status(4) + data_len(4) = 12 bytes
        if bytes.len() < 12 {
            return Err(crate::TransportError::InvalidMessage);
        }

        let chksum = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let fips_status = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let data_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);

        // Validate we have enough data for the MAC
        let mac_len = core::cmp::min(data_len as usize, MAX_HMAC_SIZE);
        if bytes.len() < 12 + mac_len {
            return Err(crate::TransportError::InvalidMessage);
        }

        let mut mac = [0u8; MAX_HMAC_SIZE];
        mac[..mac_len].copy_from_slice(&bytes[12..12 + mac_len]);

        Ok(ExtCmdHmacResponse {
            chksum,
            fips_status,
            data_len,
            mac,
        })
    }

    fn to_bytes_variable(&self, buffer: &mut [u8]) -> usize {
        let header_size = 12;
        let mac_len = core::cmp::min(self.data_len as usize, MAX_HMAC_SIZE);
        let total_size = header_size + mac_len;

        if buffer.len() < total_size {
            return 0;
        }

        buffer[0..4].copy_from_slice(&self.chksum.to_le_bytes());
        buffer[4..8].copy_from_slice(&self.fips_status.to_le_bytes());
        buffer[8..12].copy_from_slice(&self.data_len.to_le_bytes());
        buffer[12..12 + mac_len].copy_from_slice(&self.mac[..mac_len]);

        total_size
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdHmacKdfCounterRequest {
    pub chksum: u32,
    pub kin: [u8; CMK_SIZE],
    pub hash_algorithm: u32,
    pub key_usage: u32,
    pub key_size: u32,
    pub label_size: u32,
    pub label: [u8; MAX_HMAC_INPUT_SIZE],
}

impl Default for ExtCmdHmacKdfCounterRequest {
    fn default() -> Self {
        Self {
            chksum: 0,
            kin: [0u8; CMK_SIZE],
            hash_algorithm: HmacAlgorithm::Sha384 as u32,
            key_usage: CmKeyUsage::Reserved as u32,
            key_size: 0,
            label_size: 0,
            label: [0u8; MAX_HMAC_INPUT_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdHmacKdfCounterResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub kout: [u8; CMK_SIZE],
}

impl Default for ExtCmdHmacKdfCounterResponse {
    fn default() -> Self {
        Self {
            chksum: 0,
            fips_status: 0,
            kout: [0u8; CMK_SIZE],
        }
    }
}

impl FromInternalRequest<HmacKdfCounterRequest> for ExtCmdHmacKdfCounterRequest {
    fn from_internal(internal: &HmacKdfCounterRequest, command_code: u32) -> Self {
        // Build payload for checksum calculation
        let mut payload = Vec::new();
        payload.extend_from_slice(&internal.kin.0);
        payload.extend_from_slice(&internal.hash_algorithm.to_le_bytes());
        payload.extend_from_slice(&internal.key_usage.to_le_bytes());
        payload.extend_from_slice(&internal.key_size.to_le_bytes());
        payload.extend_from_slice(&internal.label_size.to_le_bytes());
        let label_len = internal.label_size as usize;
        payload.extend_from_slice(&internal.label[..label_len]);

        let chksum = calc_checksum(command_code, &payload);

        Self {
            chksum,
            kin: internal.kin.0,
            hash_algorithm: internal.hash_algorithm,
            key_usage: internal.key_usage,
            key_size: internal.key_size,
            label_size: internal.label_size,
            label: internal.label,
        }
    }
}

impl ToInternalResponse<HmacKdfCounterResponse> for ExtCmdHmacKdfCounterResponse {
    fn to_internal(&self) -> HmacKdfCounterResponse {
        HmacKdfCounterResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            kout: Cmk(self.kout),
        }
    }
}

impl VariableSizeBytes for ExtCmdHmacKdfCounterRequest {}
impl VariableSizeBytes for ExtCmdHmacKdfCounterResponse {}

// ============================================================================
// Command Metadata Definitions
// ============================================================================

use crate::define_command;

define_command!(
    HmacCmd,
    0x4D43_484D, // MC_HMAC
    HmacRequest,
    HmacResponse,
    ExtCmdHmacRequest,
    ExtCmdHmacResponse
);

define_command!(
    HmacKdfCounterCmd,
    0x4D43_4B43, // MC_HMAC_KDF_COUNTER
    HmacKdfCounterRequest,
    HmacKdfCounterResponse,
    ExtCmdHmacKdfCounterRequest,
    ExtCmdHmacKdfCounterResponse
);
