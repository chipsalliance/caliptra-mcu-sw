// Licensed under the Apache-2.0 license

//! Mailbox transport layer for Production Debug Unlock commands
//!
//! External mailbox command codes:
//! - MC_PROD_DEBUG_UNLOCK_REQ = 0x4D50_5552 ("MPUR")
//! - MC_PROD_DEBUG_UNLOCK_TOKEN = 0x4D50_5554 ("MPUT")

extern crate alloc;

use super::checksum::calc_checksum;
use super::command_traits::{
    ExternalCommandMetadata, FromInternalRequest, ToInternalResponse, VariableSizeBytes,
};
use alloc::vec::Vec;
use caliptra_mcu_core_util_host_command_types::debug_unlock::{
    ProdDebugUnlockReqRequest, ProdDebugUnlockReqResponse, ProdDebugUnlockTokenRequest,
    ProdDebugUnlockTokenResponse, DEBUG_UNLOCK_CHALLENGE_SIZE, ECC_PUBLIC_KEY_WORD_SIZE,
    ECC_SIGNATURE_WORD_SIZE, MLDSA_PUBLIC_KEY_WORD_SIZE, MLDSA_SIGNATURE_WORD_SIZE,
    UNIQUE_DEVICE_ID_SIZE,
};
use caliptra_mcu_core_util_host_command_types::CommonResponse;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::define_command;

// ============================================================================
// Production Debug Unlock Request (Challenge)
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Default, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdProdDebugUnlockReqRequest {
    pub chksum: u32,
    pub length: u32,
    pub unlock_level: u8,
    pub reserved: [u8; 3],
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdProdDebugUnlockReqResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub length: u32,
    pub unique_device_identifier: [u8; UNIQUE_DEVICE_ID_SIZE],
    pub challenge: [u8; DEBUG_UNLOCK_CHALLENGE_SIZE],
}

impl Default for ExtCmdProdDebugUnlockReqResponse {
    fn default() -> Self {
        Self {
            chksum: 0,
            fips_status: 0,
            length: 0,
            unique_device_identifier: [0u8; UNIQUE_DEVICE_ID_SIZE],
            challenge: [0u8; DEBUG_UNLOCK_CHALLENGE_SIZE],
        }
    }
}

impl FromInternalRequest<ProdDebugUnlockReqRequest> for ExtCmdProdDebugUnlockReqRequest {
    fn from_internal(internal: &ProdDebugUnlockReqRequest, command_code: u32) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(&internal.length.to_le_bytes());
        payload.push(internal.unlock_level);
        payload.extend_from_slice(&internal.reserved);

        let chksum = calc_checksum(command_code, &payload);

        Self {
            chksum,
            length: internal.length,
            unlock_level: internal.unlock_level,
            reserved: internal.reserved,
        }
    }
}

impl ToInternalResponse<ProdDebugUnlockReqResponse> for ExtCmdProdDebugUnlockReqResponse {
    fn to_internal(&self) -> ProdDebugUnlockReqResponse {
        ProdDebugUnlockReqResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            length: self.length,
            unique_device_identifier: self.unique_device_identifier,
            challenge: self.challenge,
        }
    }
}

impl VariableSizeBytes for ExtCmdProdDebugUnlockReqRequest {}
impl VariableSizeBytes for ExtCmdProdDebugUnlockReqResponse {}

// ============================================================================
// Production Debug Unlock Token
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdProdDebugUnlockTokenRequest {
    pub chksum: u32,
    pub length: u32,
    pub unique_device_identifier: [u8; UNIQUE_DEVICE_ID_SIZE],
    pub unlock_level: u8,
    pub reserved: [u8; 3],
    pub challenge: [u8; DEBUG_UNLOCK_CHALLENGE_SIZE],
    pub ecc_public_key: [u32; ECC_PUBLIC_KEY_WORD_SIZE],
    pub mldsa_public_key: [u32; MLDSA_PUBLIC_KEY_WORD_SIZE],
    pub ecc_signature: [u32; ECC_SIGNATURE_WORD_SIZE],
    pub mldsa_signature: [u32; MLDSA_SIGNATURE_WORD_SIZE],
}

impl Default for ExtCmdProdDebugUnlockTokenRequest {
    fn default() -> Self {
        Self {
            chksum: 0,
            length: 0,
            unique_device_identifier: [0u8; UNIQUE_DEVICE_ID_SIZE],
            unlock_level: 0,
            reserved: [0; 3],
            challenge: [0u8; DEBUG_UNLOCK_CHALLENGE_SIZE],
            ecc_public_key: [0u32; ECC_PUBLIC_KEY_WORD_SIZE],
            mldsa_public_key: [0u32; MLDSA_PUBLIC_KEY_WORD_SIZE],
            ecc_signature: [0u32; ECC_SIGNATURE_WORD_SIZE],
            mldsa_signature: [0u32; MLDSA_SIGNATURE_WORD_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Default, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdProdDebugUnlockTokenResponse {
    pub chksum: u32,
    pub fips_status: u32,
}

impl FromInternalRequest<ProdDebugUnlockTokenRequest> for ExtCmdProdDebugUnlockTokenRequest {
    fn from_internal(internal: &ProdDebugUnlockTokenRequest, command_code: u32) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(&internal.length.to_le_bytes());
        payload.extend_from_slice(&internal.unique_device_identifier);
        payload.push(internal.unlock_level);
        payload.extend_from_slice(&internal.reserved);
        payload.extend_from_slice(&internal.challenge);
        for word in &internal.ecc_public_key {
            payload.extend_from_slice(&word.to_le_bytes());
        }
        for word in &internal.mldsa_public_key {
            payload.extend_from_slice(&word.to_le_bytes());
        }
        for word in &internal.ecc_signature {
            payload.extend_from_slice(&word.to_le_bytes());
        }
        for word in &internal.mldsa_signature {
            payload.extend_from_slice(&word.to_le_bytes());
        }

        let chksum = calc_checksum(command_code, &payload);

        Self {
            chksum,
            length: internal.length,
            unique_device_identifier: internal.unique_device_identifier,
            unlock_level: internal.unlock_level,
            reserved: internal.reserved,
            challenge: internal.challenge,
            ecc_public_key: internal.ecc_public_key,
            mldsa_public_key: internal.mldsa_public_key,
            ecc_signature: internal.ecc_signature,
            mldsa_signature: internal.mldsa_signature,
        }
    }
}

impl ToInternalResponse<ProdDebugUnlockTokenResponse> for ExtCmdProdDebugUnlockTokenResponse {
    fn to_internal(&self) -> ProdDebugUnlockTokenResponse {
        ProdDebugUnlockTokenResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
        }
    }
}

impl VariableSizeBytes for ExtCmdProdDebugUnlockTokenRequest {}
impl VariableSizeBytes for ExtCmdProdDebugUnlockTokenResponse {}

// ============================================================================
// Command Metadata Definitions
// ============================================================================

define_command!(
    ProdDebugUnlockReqCmd,
    0x4D50_5552, // MC_PROD_DEBUG_UNLOCK_REQ ("MPUR")
    ProdDebugUnlockReqRequest,
    ProdDebugUnlockReqResponse,
    ExtCmdProdDebugUnlockReqRequest,
    ExtCmdProdDebugUnlockReqResponse
);

define_command!(
    ProdDebugUnlockTokenCmd,
    0x4D50_5554, // MC_PROD_DEBUG_UNLOCK_TOKEN ("MPUT")
    ProdDebugUnlockTokenRequest,
    ProdDebugUnlockTokenResponse,
    ExtCmdProdDebugUnlockTokenRequest,
    ExtCmdProdDebugUnlockTokenResponse
);
