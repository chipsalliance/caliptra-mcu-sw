// Licensed under the Apache-2.0 license

//! Production Debug Unlock Commands
//!
//! Command structures for production authentication debug unlock operations.
//!
//! - `ProdDebugUnlockReqRequest` - Request a debug unlock challenge
//! - `ProdDebugUnlockTokenRequest` - Submit a debug unlock token

use crate::{CaliptraCommandId, CommandRequest, CommandResponse, CommonResponse};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Size of the unique device identifier in bytes
pub const UNIQUE_DEVICE_ID_SIZE: usize = 32;

/// Size of the challenge in bytes (ECC P-384 scalar)
pub const DEBUG_UNLOCK_CHALLENGE_SIZE: usize = 48;

/// ECC public key size in u32 words (24 words = 96 bytes for P-384 X || Y)
pub const ECC_PUBLIC_KEY_WORD_SIZE: usize = 24;

/// ML-DSA public key size in u32 words
pub const MLDSA_PUBLIC_KEY_WORD_SIZE: usize = 648;

/// ECC signature size in u32 words (24 words = 96 bytes for P-384 r || s)
pub const ECC_SIGNATURE_WORD_SIZE: usize = 24;

/// ML-DSA signature size in u32 words
pub const MLDSA_SIGNATURE_WORD_SIZE: usize = 1157;

// ---- Production Debug Unlock Request (Challenge) ----

#[repr(C)]
#[derive(Debug, Clone, Default, IntoBytes, FromBytes, Immutable)]
pub struct ProdDebugUnlockReqRequest {
    pub length: u32,
    pub unlock_level: u8,
    pub reserved: [u8; 3],
}

impl ProdDebugUnlockReqRequest {
    pub fn new(unlock_level: u8) -> Self {
        Self {
            length: 2,
            unlock_level,
            reserved: [0; 3],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ProdDebugUnlockReqResponse {
    pub common: CommonResponse,
    pub length: u32,
    pub unique_device_identifier: [u8; UNIQUE_DEVICE_ID_SIZE],
    pub challenge: [u8; DEBUG_UNLOCK_CHALLENGE_SIZE],
}

impl Default for ProdDebugUnlockReqResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse { fips_status: 0 },
            length: 0,
            unique_device_identifier: [0u8; UNIQUE_DEVICE_ID_SIZE],
            challenge: [0u8; DEBUG_UNLOCK_CHALLENGE_SIZE],
        }
    }
}

impl CommandRequest for ProdDebugUnlockReqRequest {
    type Response = ProdDebugUnlockReqResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::ProdDebugUnlockReq;
}

impl CommandResponse for ProdDebugUnlockReqResponse {}

// ---- Production Debug Unlock Token ----

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ProdDebugUnlockTokenRequest {
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

impl Default for ProdDebugUnlockTokenRequest {
    fn default() -> Self {
        Self {
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
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ProdDebugUnlockTokenResponse {
    pub common: CommonResponse,
}

impl Default for ProdDebugUnlockTokenResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse { fips_status: 0 },
        }
    }
}

impl CommandRequest for ProdDebugUnlockTokenRequest {
    type Response = ProdDebugUnlockTokenResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::ProdDebugUnlockToken;
}

impl CommandResponse for ProdDebugUnlockTokenResponse {}
