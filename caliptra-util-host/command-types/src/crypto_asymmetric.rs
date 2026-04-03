// Licensed under the Apache-2.0 license

//! Asymmetric Crypto Commands
//!
//! Command structures for ECDSA and ECDH operations.
//!
//! ECDSA operations:
//! - `EcdsaPublicKeyRequest` - Get public key from an ECDSA CMK
//! - `EcdsaSignRequest` - Sign a message with an ECDSA CMK
//! - `EcdsaVerifyRequest` - Verify a signature with an ECDSA CMK
//!
//! ECDH operations:
//! - `EcdhGenerateRequest` - Generate an ephemeral ECDH keypair
//! - `EcdhFinishRequest` - Complete ECDH key exchange and derive shared secret

use crate::crypto_hmac::{CmKeyUsage, Cmk};
use crate::{CaliptraCommandId, CommandRequest, CommandResponse, CommonResponse};
use zerocopy::{FromBytes, Immutable, IntoBytes};

// ECC P-384 scalar size in bytes (48 bytes = 384 bits)
pub const ECC384_SCALAR_BYTE_SIZE: usize = 48;

// Maximum size for ECDH exchange data (public key X || Y coordinates)
pub const CMB_ECDH_EXCHANGE_DATA_MAX_SIZE: usize = 96; // 48 * 2

// ECDH encrypted context size (scalar + IV + tag)
pub const CMB_ECDH_ENCRYPTED_CONTEXT_SIZE: usize = 76; // 48 + 12 + 16

// Maximum message data size for crypto operations
pub const MAX_CMB_DATA_SIZE: usize = 4096;

#[repr(C)]
#[derive(Debug, Clone, Default, IntoBytes, FromBytes, Immutable)]
pub struct EcdsaPublicKeyRequest {
    pub cmk: Cmk,
}

impl EcdsaPublicKeyRequest {
    pub fn new(cmk: &Cmk) -> Self {
        Self { cmk: cmk.clone() }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct EcdsaPublicKeyResponse {
    pub common: CommonResponse,
    pub pub_key_x: [u8; ECC384_SCALAR_BYTE_SIZE],
    pub pub_key_y: [u8; ECC384_SCALAR_BYTE_SIZE],
}

impl Default for EcdsaPublicKeyResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse { fips_status: 0 },
            pub_key_x: [0u8; ECC384_SCALAR_BYTE_SIZE],
            pub_key_y: [0u8; ECC384_SCALAR_BYTE_SIZE],
        }
    }
}

impl CommandRequest for EcdsaPublicKeyRequest {
    type Response = EcdsaPublicKeyResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::EcdsaPublicKey;
}

impl CommandResponse for EcdsaPublicKeyResponse {}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct EcdsaSignRequest {
    pub cmk: Cmk,
    pub message_size: u32,
    pub message: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for EcdsaSignRequest {
    fn default() -> Self {
        Self {
            cmk: Cmk::default(),
            message_size: 0,
            message: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl EcdsaSignRequest {
    pub fn new(cmk: &Cmk, message: &[u8]) -> Self {
        let mut req = Self {
            cmk: cmk.clone(),
            message_size: message.len() as u32,
            message: [0u8; MAX_CMB_DATA_SIZE],
        };
        let copy_len = core::cmp::min(message.len(), MAX_CMB_DATA_SIZE);
        req.message[..copy_len].copy_from_slice(&message[..copy_len]);
        req
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct EcdsaSignResponse {
    pub common: CommonResponse,
    pub signature_r: [u8; ECC384_SCALAR_BYTE_SIZE],
    pub signature_s: [u8; ECC384_SCALAR_BYTE_SIZE],
}

impl Default for EcdsaSignResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse { fips_status: 0 },
            signature_r: [0u8; ECC384_SCALAR_BYTE_SIZE],
            signature_s: [0u8; ECC384_SCALAR_BYTE_SIZE],
        }
    }
}

impl CommandRequest for EcdsaSignRequest {
    type Response = EcdsaSignResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::EcdsaSign;
}

impl CommandResponse for EcdsaSignResponse {}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct EcdsaVerifyRequest {
    pub cmk: Cmk,
    pub signature_r: [u8; ECC384_SCALAR_BYTE_SIZE],
    pub signature_s: [u8; ECC384_SCALAR_BYTE_SIZE],
    pub message_size: u32,
    pub message: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for EcdsaVerifyRequest {
    fn default() -> Self {
        Self {
            cmk: Cmk::default(),
            signature_r: [0u8; ECC384_SCALAR_BYTE_SIZE],
            signature_s: [0u8; ECC384_SCALAR_BYTE_SIZE],
            message_size: 0,
            message: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl EcdsaVerifyRequest {
    pub fn new(
        cmk: &Cmk,
        message: &[u8],
        signature_r: &[u8; ECC384_SCALAR_BYTE_SIZE],
        signature_s: &[u8; ECC384_SCALAR_BYTE_SIZE],
    ) -> Self {
        let mut req = Self {
            cmk: cmk.clone(),
            signature_r: *signature_r,
            signature_s: *signature_s,
            message_size: message.len() as u32,
            message: [0u8; MAX_CMB_DATA_SIZE],
        };
        let copy_len = core::cmp::min(message.len(), MAX_CMB_DATA_SIZE);
        req.message[..copy_len].copy_from_slice(&message[..copy_len]);
        req
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct EcdsaVerifyResponse {
    pub common: CommonResponse,
}

impl Default for EcdsaVerifyResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse { fips_status: 0 },
        }
    }
}

impl CommandRequest for EcdsaVerifyRequest {
    type Response = EcdsaVerifyResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::EcdsaVerify;
}

impl CommandResponse for EcdsaVerifyResponse {}

#[repr(C)]
#[derive(Debug, Clone, Default, IntoBytes, FromBytes, Immutable)]
pub struct EcdhGenerateRequest {
    // Empty request - no parameters needed
    _reserved: u32,
}

impl EcdhGenerateRequest {
    pub fn new() -> Self {
        Self::default()
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct EcdhGenerateResponse {
    pub common: CommonResponse,
    pub context: [u8; CMB_ECDH_ENCRYPTED_CONTEXT_SIZE],
    pub exchange_data: [u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
}

impl Default for EcdhGenerateResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse { fips_status: 0 },
            context: [0u8; CMB_ECDH_ENCRYPTED_CONTEXT_SIZE],
            exchange_data: [0u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
        }
    }
}

impl CommandRequest for EcdhGenerateRequest {
    type Response = EcdhGenerateResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::EcdhGenerate;
}

impl CommandResponse for EcdhGenerateResponse {}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct EcdhFinishRequest {
    pub context: [u8; CMB_ECDH_ENCRYPTED_CONTEXT_SIZE],
    pub key_usage: u32,
    pub incoming_exchange_data: [u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
}

impl Default for EcdhFinishRequest {
    fn default() -> Self {
        Self {
            context: [0u8; CMB_ECDH_ENCRYPTED_CONTEXT_SIZE],
            key_usage: CmKeyUsage::Reserved as u32,
            incoming_exchange_data: [0u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
        }
    }
}

impl EcdhFinishRequest {
    pub fn new(
        context: &[u8; CMB_ECDH_ENCRYPTED_CONTEXT_SIZE],
        key_usage: CmKeyUsage,
        incoming_exchange_data: &[u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
    ) -> Self {
        Self {
            context: *context,
            key_usage: key_usage as u32,
            incoming_exchange_data: *incoming_exchange_data,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct EcdhFinishResponse {
    pub common: CommonResponse,
    pub output: Cmk,
}

impl Default for EcdhFinishResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse { fips_status: 0 },
            output: Cmk::default(),
        }
    }
}

impl CommandRequest for EcdhFinishRequest {
    type Response = EcdhFinishResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::EcdhFinish;
}

impl CommandResponse for EcdhFinishResponse {}
