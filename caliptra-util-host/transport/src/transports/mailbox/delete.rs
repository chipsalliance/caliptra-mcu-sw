// Licensed under the Apache-2.0 license

//! Mailbox transport layer for Delete command
//!
//! External mailbox command code:
//! - MC_DELETE = 0x4D43_444C ("MCDL")

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use super::checksum::calc_checksum;
use super::command_traits::{
    ExternalCommandMetadata, FromInternalRequest, ToInternalResponse, VariableSizeBytes,
};
use caliptra_util_host_command_types::crypto_delete::{DeleteRequest, DeleteResponse};
use caliptra_util_host_command_types::crypto_hmac::CMK_SIZE;
use caliptra_util_host_command_types::CommonResponse;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::define_command;

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdDeleteRequest {
    pub chksum: u32,
    pub cmk: [u8; CMK_SIZE],
}

impl Default for ExtCmdDeleteRequest {
    fn default() -> Self {
        Self {
            chksum: 0,
            cmk: [0u8; CMK_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Default, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdDeleteResponse {
    pub chksum: u32,
    pub fips_status: u32,
}

impl FromInternalRequest<DeleteRequest> for ExtCmdDeleteRequest {
    fn from_internal(internal: &DeleteRequest, command_code: u32) -> Self {
        // Build payload for checksum calculation
        let mut payload: Vec<u8> = vec![];
        payload.extend_from_slice(&internal.cmk.0);

        let chksum = calc_checksum(command_code, &payload);

        Self {
            chksum,
            cmk: internal.cmk.0,
        }
    }
}

impl ToInternalResponse<DeleteResponse> for ExtCmdDeleteResponse {
    fn to_internal(&self) -> DeleteResponse {
        DeleteResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
        }
    }
}

impl VariableSizeBytes for ExtCmdDeleteResponse {}

// ============================================================================
// Command Metadata
// ============================================================================

define_command!(
    DeleteCmd,
    0x4D43_444C, // MC_DELETE
    DeleteRequest,
    DeleteResponse,
    ExtCmdDeleteRequest,
    ExtCmdDeleteResponse
);
