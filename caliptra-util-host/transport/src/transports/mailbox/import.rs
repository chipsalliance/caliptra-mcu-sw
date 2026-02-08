// Licensed under the Apache-2.0 license

//! Mailbox transport layer for Import command
//!
//! External mailbox command code:
//! - MC_IMPORT = 0x4D43_494D ("MCIM")

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use super::checksum::calc_checksum;
use super::command_traits::{
    ExternalCommandMetadata, FromInternalRequest, ToInternalResponse, VariableSizeBytes,
};
use caliptra_util_host_command_types::crypto_hmac::{CmKeyUsage, Cmk, CMK_SIZE};
use caliptra_util_host_command_types::crypto_import::{
    ImportRequest, ImportResponse, MAX_IMPORT_KEY_SIZE,
};
use caliptra_util_host_command_types::CommonResponse;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::define_command;

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdImportRequest {
    pub chksum: u32,
    pub key_usage: u32,
    pub input_size: u32,
    pub input: [u8; MAX_IMPORT_KEY_SIZE],
}

impl Default for ExtCmdImportRequest {
    fn default() -> Self {
        Self {
            chksum: 0,
            key_usage: CmKeyUsage::Reserved as u32,
            input_size: 0,
            input: [0u8; MAX_IMPORT_KEY_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdImportResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub cmk: [u8; CMK_SIZE],
}

impl Default for ExtCmdImportResponse {
    fn default() -> Self {
        Self {
            chksum: 0,
            fips_status: 0,
            cmk: [0u8; CMK_SIZE],
        }
    }
}

impl FromInternalRequest<ImportRequest> for ExtCmdImportRequest {
    fn from_internal(internal: &ImportRequest, command_code: u32) -> Self {
        // Build payload for checksum calculation
        let mut payload: Vec<u8> = vec![];
        payload.extend_from_slice(&internal.key_usage.to_le_bytes());
        payload.extend_from_slice(&internal.input_size.to_le_bytes());
        payload.extend_from_slice(&internal.input);

        let chksum = calc_checksum(command_code, &payload);

        Self {
            chksum,
            key_usage: internal.key_usage,
            input_size: internal.input_size,
            input: internal.input,
        }
    }
}

impl ToInternalResponse<ImportResponse> for ExtCmdImportResponse {
    fn to_internal(&self) -> ImportResponse {
        ImportResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            cmk: Cmk::new(self.cmk),
        }
    }
}

impl VariableSizeBytes for ExtCmdImportResponse {}

// ============================================================================
// Command Metadata
// ============================================================================

define_command!(
    ImportCmd,
    0x4D43_494D, // MC_IMPORT
    ImportRequest,
    ImportResponse,
    ExtCmdImportRequest,
    ExtCmdImportResponse
);
