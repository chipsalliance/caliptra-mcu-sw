// Licensed under the Apache-2.0 license

//! Mailbox transport layer for authorized fuse commands
//!
//! External mailbox command codes:
//! - MC_GET_AUTH_CMD_CHALLENGE = 0x4D41_4343 ("MACC")
//! - MC_FE_PROG = 0x4D43_4650 ("MCFP")

extern crate alloc;

use super::checksum::calc_checksum;
use super::command_traits::{
    ExternalCommandMetadata, FromInternalRequest, ToInternalResponse, VariableSizeBytes,
};
use alloc::vec::Vec;
use caliptra_mcu_core_util_host_command_types::fuse::{
    FeProgRequest, FeProgResponse, GetAuthCmdChallengeRequest, GetAuthCmdChallengeResponse,
    AUTH_CMD_CHALLENGE_SIZE, AUTH_CMD_MAC_SIZE,
};
use caliptra_mcu_core_util_host_command_types::CommonResponse;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::define_command;

// ============================================================================
// Get Authorization Command Challenge
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Default, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdGetAuthCmdChallengeRequest {
    pub chksum: u32,
    pub flags: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdGetAuthCmdChallengeResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub reserved: u32,
    pub challenge: [u8; AUTH_CMD_CHALLENGE_SIZE],
}

impl Default for ExtCmdGetAuthCmdChallengeResponse {
    fn default() -> Self {
        Self {
            chksum: 0,
            fips_status: 0,
            reserved: 0,
            challenge: [0u8; AUTH_CMD_CHALLENGE_SIZE],
        }
    }
}

impl FromInternalRequest<GetAuthCmdChallengeRequest> for ExtCmdGetAuthCmdChallengeRequest {
    fn from_internal(internal: &GetAuthCmdChallengeRequest, command_code: u32) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(&internal.flags.to_le_bytes());
        payload.extend_from_slice(&internal.reserved.to_le_bytes());

        let chksum = calc_checksum(command_code, &payload);

        Self {
            chksum,
            flags: internal.flags,
            reserved: internal.reserved,
        }
    }
}

impl ToInternalResponse<GetAuthCmdChallengeResponse> for ExtCmdGetAuthCmdChallengeResponse {
    fn to_internal(&self) -> GetAuthCmdChallengeResponse {
        GetAuthCmdChallengeResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            reserved: self.reserved,
            challenge: self.challenge,
        }
    }
}

impl VariableSizeBytes for ExtCmdGetAuthCmdChallengeRequest {}
impl VariableSizeBytes for ExtCmdGetAuthCmdChallengeResponse {}

// ============================================================================
// Field Entropy Programming (FE_PROG)
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdFeProgRequest {
    pub chksum: u32,
    pub partition: u32,
    pub mac: [u8; AUTH_CMD_MAC_SIZE],
}

impl Default for ExtCmdFeProgRequest {
    fn default() -> Self {
        Self {
            chksum: 0,
            partition: 0,
            mac: [0u8; AUTH_CMD_MAC_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Default, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdFeProgResponse {
    pub chksum: u32,
    pub fips_status: u32,
}

impl FromInternalRequest<FeProgRequest> for ExtCmdFeProgRequest {
    fn from_internal(internal: &FeProgRequest, command_code: u32) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(&internal.partition.to_le_bytes());
        // MAC is appended after the command body in the wire format
        payload.extend_from_slice(&internal.mac);

        let chksum = calc_checksum(command_code, &payload);

        Self {
            chksum,
            partition: internal.partition,
            mac: internal.mac,
        }
    }
}

impl ToInternalResponse<FeProgResponse> for ExtCmdFeProgResponse {
    fn to_internal(&self) -> FeProgResponse {
        FeProgResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
        }
    }
}

impl VariableSizeBytes for ExtCmdFeProgRequest {}
impl VariableSizeBytes for ExtCmdFeProgResponse {}

// ============================================================================
// Command Metadata Definitions
// ============================================================================

define_command!(
    GetAuthCmdChallengeCmd,
    0x4D41_4343, // MC_GET_AUTH_CMD_CHALLENGE ("MACC")
    GetAuthCmdChallengeRequest,
    GetAuthCmdChallengeResponse,
    ExtCmdGetAuthCmdChallengeRequest,
    ExtCmdGetAuthCmdChallengeResponse
);

define_command!(
    FeProgCmd,
    0x4D43_4650, // MC_FE_PROG ("MCFP")
    FeProgRequest,
    FeProgResponse,
    ExtCmdFeProgRequest,
    ExtCmdFeProgResponse
);
