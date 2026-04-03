// Licensed under the Apache-2.0 license

//! Mailbox transport layer for ECDSA and ECDH commands
//!
//! External mailbox command codes:
//! - MC_ECDSA_CMK_PUBLIC_KEY = 0x4D43_4550 ("MCEP")
//! - MC_ECDSA_CMK_SIGN = 0x4D43_4553 ("MCES")
//! - MC_ECDSA_CMK_VERIFY = 0x4D43_4556 ("MCEV")
//! - MC_ECDH_GENERATE = 0x4D43_4547 ("MCEG")
//! - MC_ECDH_FINISH = 0x4D43_4546 ("MCEF")

extern crate alloc;

use super::checksum::calc_checksum;
use super::command_traits::{
    ExternalCommandMetadata, FromInternalRequest, ToInternalResponse, VariableSizeBytes,
};
use alloc::vec::Vec;
use caliptra_util_host_command_types::crypto_asymmetric::{
    EcdhFinishRequest, EcdhFinishResponse, EcdhGenerateRequest, EcdhGenerateResponse,
    EcdsaPublicKeyRequest, EcdsaPublicKeyResponse, EcdsaSignRequest, EcdsaSignResponse,
    EcdsaVerifyRequest, EcdsaVerifyResponse, CMB_ECDH_ENCRYPTED_CONTEXT_SIZE,
    CMB_ECDH_EXCHANGE_DATA_MAX_SIZE, ECC384_SCALAR_BYTE_SIZE, MAX_CMB_DATA_SIZE,
};
use caliptra_util_host_command_types::crypto_hmac::{Cmk, CMK_SIZE};
use caliptra_util_host_command_types::CommonResponse;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::define_command;

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdEcdsaPublicKeyRequest {
    pub chksum: u32,
    pub cmk: [u8; CMK_SIZE],
}

impl Default for ExtCmdEcdsaPublicKeyRequest {
    fn default() -> Self {
        Self {
            chksum: 0,
            cmk: [0u8; CMK_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdEcdsaPublicKeyResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub pub_key_x: [u8; ECC384_SCALAR_BYTE_SIZE],
    pub pub_key_y: [u8; ECC384_SCALAR_BYTE_SIZE],
}

impl Default for ExtCmdEcdsaPublicKeyResponse {
    fn default() -> Self {
        Self {
            chksum: 0,
            fips_status: 0,
            pub_key_x: [0u8; ECC384_SCALAR_BYTE_SIZE],
            pub_key_y: [0u8; ECC384_SCALAR_BYTE_SIZE],
        }
    }
}

impl FromInternalRequest<EcdsaPublicKeyRequest> for ExtCmdEcdsaPublicKeyRequest {
    fn from_internal(internal: &EcdsaPublicKeyRequest, command_code: u32) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(&internal.cmk.0);

        let chksum = calc_checksum(command_code, &payload);
        Self {
            chksum,
            cmk: internal.cmk.0,
        }
    }
}

impl ToInternalResponse<EcdsaPublicKeyResponse> for ExtCmdEcdsaPublicKeyResponse {
    fn to_internal(&self) -> EcdsaPublicKeyResponse {
        EcdsaPublicKeyResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            pub_key_x: self.pub_key_x,
            pub_key_y: self.pub_key_y,
        }
    }
}

impl VariableSizeBytes for ExtCmdEcdsaPublicKeyRequest {}
impl VariableSizeBytes for ExtCmdEcdsaPublicKeyResponse {}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdEcdsaSignRequest {
    pub chksum: u32,
    pub cmk: [u8; CMK_SIZE],
    pub message_size: u32,
    pub message: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for ExtCmdEcdsaSignRequest {
    fn default() -> Self {
        Self {
            chksum: 0,
            cmk: [0u8; CMK_SIZE],
            message_size: 0,
            message: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdEcdsaSignResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub signature_r: [u8; ECC384_SCALAR_BYTE_SIZE],
    pub signature_s: [u8; ECC384_SCALAR_BYTE_SIZE],
}

impl Default for ExtCmdEcdsaSignResponse {
    fn default() -> Self {
        Self {
            chksum: 0,
            fips_status: 0,
            signature_r: [0u8; ECC384_SCALAR_BYTE_SIZE],
            signature_s: [0u8; ECC384_SCALAR_BYTE_SIZE],
        }
    }
}

impl FromInternalRequest<EcdsaSignRequest> for ExtCmdEcdsaSignRequest {
    fn from_internal(internal: &EcdsaSignRequest, command_code: u32) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(&internal.cmk.0);
        payload.extend_from_slice(&internal.message_size.to_le_bytes());
        let msg_len = internal.message_size as usize;
        payload.extend_from_slice(&internal.message[..msg_len]);

        let chksum = calc_checksum(command_code, &payload);

        Self {
            chksum,
            cmk: internal.cmk.0,
            message_size: internal.message_size,
            message: internal.message,
        }
    }
}

impl ToInternalResponse<EcdsaSignResponse> for ExtCmdEcdsaSignResponse {
    fn to_internal(&self) -> EcdsaSignResponse {
        EcdsaSignResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            signature_r: self.signature_r,
            signature_s: self.signature_s,
        }
    }
}

impl VariableSizeBytes for ExtCmdEcdsaSignRequest {}
impl VariableSizeBytes for ExtCmdEcdsaSignResponse {}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdEcdsaVerifyRequest {
    pub chksum: u32,
    // Cryptographic mailbox key
    pub cmk: [u8; CMK_SIZE],
    // Signature R component
    pub signature_r: [u8; ECC384_SCALAR_BYTE_SIZE],
    // Signature S component
    pub signature_s: [u8; ECC384_SCALAR_BYTE_SIZE],
    // Size of message in bytes
    pub message_size: u32,
    // Message that was signed
    pub message: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for ExtCmdEcdsaVerifyRequest {
    fn default() -> Self {
        Self {
            chksum: 0,
            cmk: [0u8; CMK_SIZE],
            signature_r: [0u8; ECC384_SCALAR_BYTE_SIZE],
            signature_s: [0u8; ECC384_SCALAR_BYTE_SIZE],
            message_size: 0,
            message: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Default, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdEcdsaVerifyResponse {
    pub chksum: u32,
    pub fips_status: u32,
}

impl FromInternalRequest<EcdsaVerifyRequest> for ExtCmdEcdsaVerifyRequest {
    fn from_internal(internal: &EcdsaVerifyRequest, command_code: u32) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(&internal.cmk.0);
        payload.extend_from_slice(&internal.signature_r);
        payload.extend_from_slice(&internal.signature_s);
        payload.extend_from_slice(&internal.message_size.to_le_bytes());
        let msg_len = internal.message_size as usize;
        payload.extend_from_slice(&internal.message[..msg_len]);

        let chksum = calc_checksum(command_code, &payload);

        Self {
            chksum,
            cmk: internal.cmk.0,
            signature_r: internal.signature_r,
            signature_s: internal.signature_s,
            message_size: internal.message_size,
            message: internal.message,
        }
    }
}

impl ToInternalResponse<EcdsaVerifyResponse> for ExtCmdEcdsaVerifyResponse {
    fn to_internal(&self) -> EcdsaVerifyResponse {
        EcdsaVerifyResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
        }
    }
}

impl VariableSizeBytes for ExtCmdEcdsaVerifyRequest {}
impl VariableSizeBytes for ExtCmdEcdsaVerifyResponse {}

#[repr(C)]
#[derive(Debug, Clone, Default, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdEcdhGenerateRequest {
    pub chksum: u32,
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdEcdhGenerateResponse {
    pub chksum: u32,
    pub fips_status: u32,
    // Encrypted context
    pub context: [u8; CMB_ECDH_ENCRYPTED_CONTEXT_SIZE],
    // Exchange data (public key X || Y)
    pub exchange_data: [u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
}

impl Default for ExtCmdEcdhGenerateResponse {
    fn default() -> Self {
        Self {
            chksum: 0,
            fips_status: 0,
            context: [0u8; CMB_ECDH_ENCRYPTED_CONTEXT_SIZE],
            exchange_data: [0u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
        }
    }
}

impl FromInternalRequest<EcdhGenerateRequest> for ExtCmdEcdhGenerateRequest {
    fn from_internal(_internal: &EcdhGenerateRequest, command_code: u32) -> Self {
        // Empty payload for generate request
        let payload: Vec<u8> = Vec::new();
        let chksum = calc_checksum(command_code, &payload);

        Self { chksum }
    }
}

impl ToInternalResponse<EcdhGenerateResponse> for ExtCmdEcdhGenerateResponse {
    fn to_internal(&self) -> EcdhGenerateResponse {
        EcdhGenerateResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            context: self.context,
            exchange_data: self.exchange_data,
        }
    }
}

impl VariableSizeBytes for ExtCmdEcdhGenerateRequest {}
impl VariableSizeBytes for ExtCmdEcdhGenerateResponse {}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdEcdhFinishRequest {
    pub chksum: u32,
    // Encrypted context from generate
    pub context: [u8; CMB_ECDH_ENCRYPTED_CONTEXT_SIZE],
    // Key usage for derived key
    pub key_usage: u32,
    // Incoming exchange data (peer's public key)
    pub incoming_exchange_data: [u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
}

impl Default for ExtCmdEcdhFinishRequest {
    fn default() -> Self {
        Self {
            chksum: 0,
            context: [0u8; CMB_ECDH_ENCRYPTED_CONTEXT_SIZE],
            key_usage: 0,
            incoming_exchange_data: [0u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdEcdhFinishResponse {
    pub chksum: u32,
    pub fips_status: u32,
    // Output CMK (derived shared secret)
    pub output: [u8; CMK_SIZE],
}

impl Default for ExtCmdEcdhFinishResponse {
    fn default() -> Self {
        Self {
            chksum: 0,
            fips_status: 0,
            output: [0u8; CMK_SIZE],
        }
    }
}

impl FromInternalRequest<EcdhFinishRequest> for ExtCmdEcdhFinishRequest {
    fn from_internal(internal: &EcdhFinishRequest, command_code: u32) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(&internal.context);
        payload.extend_from_slice(&internal.key_usage.to_le_bytes());
        payload.extend_from_slice(&internal.incoming_exchange_data);

        let chksum = calc_checksum(command_code, &payload);

        Self {
            chksum,
            context: internal.context,
            key_usage: internal.key_usage,
            incoming_exchange_data: internal.incoming_exchange_data,
        }
    }
}

impl ToInternalResponse<EcdhFinishResponse> for ExtCmdEcdhFinishResponse {
    fn to_internal(&self) -> EcdhFinishResponse {
        EcdhFinishResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            output: Cmk::new(self.output),
        }
    }
}

impl VariableSizeBytes for ExtCmdEcdhFinishRequest {}
impl VariableSizeBytes for ExtCmdEcdhFinishResponse {}

// ============================================================================
// Command Metadata Definitions
// ============================================================================

define_command!(
    EcdsaPublicKeyCmd,
    0x4D43_4550, // MC_ECDSA_CMK_PUBLIC_KEY
    EcdsaPublicKeyRequest,
    EcdsaPublicKeyResponse,
    ExtCmdEcdsaPublicKeyRequest,
    ExtCmdEcdsaPublicKeyResponse
);

define_command!(
    EcdsaSignCmd,
    0x4D43_4553, // MC_ECDSA_CMK_SIGN
    EcdsaSignRequest,
    EcdsaSignResponse,
    ExtCmdEcdsaSignRequest,
    ExtCmdEcdsaSignResponse
);

define_command!(
    EcdsaVerifyCmd,
    0x4D43_4556, // MC_ECDSA_CMK_VERIFY
    EcdsaVerifyRequest,
    EcdsaVerifyResponse,
    ExtCmdEcdsaVerifyRequest,
    ExtCmdEcdsaVerifyResponse
);

define_command!(
    EcdhGenerateCmd,
    0x4D43_4547, // MC_ECDH_GENERATE
    EcdhGenerateRequest,
    EcdhGenerateResponse,
    ExtCmdEcdhGenerateRequest,
    ExtCmdEcdhGenerateResponse
);

define_command!(
    EcdhFinishCmd,
    0x4D43_4546, // MC_ECDH_FINISH
    EcdhFinishRequest,
    EcdhFinishResponse,
    ExtCmdEcdhFinishRequest,
    ExtCmdEcdhFinishResponse
);
