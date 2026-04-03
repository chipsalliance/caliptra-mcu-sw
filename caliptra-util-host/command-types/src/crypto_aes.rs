// Licensed under the Apache-2.0 license

//! AES and Symmetric Crypto Commands
//!
//! Command structures for AES encrypt/decrypt operations via mailbox transport.
//!
//! Supports:
//! - AES-CBC and AES-CTR modes (Init + Update pattern)
//! - AES-GCM authenticated encryption (Init + Update* + Final pattern)

use crate::crypto_hmac::Cmk;
use crate::{CaliptraCommandId, CommandRequest, CommandResponse, CommonResponse};
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const MAX_AES_DATA_SIZE: usize = 4096;
pub const AES_CONTEXT_SIZE: usize = 156;
pub const AES_GCM_CONTEXT_SIZE: usize = 128;
pub const AES_IV_SIZE: usize = 16;
pub const AES_GCM_IV_SIZE: usize = 12;
pub const AES_GCM_TAG_SIZE: usize = 16;
pub const MAX_AES_GCM_OUTPUT_SIZE: usize = MAX_AES_DATA_SIZE + AES_GCM_TAG_SIZE;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesMode {
    Reserved = 0,
    Cbc = 1,
    Ctr = 2,
}

impl From<u32> for AesMode {
    fn from(value: u32) -> Self {
        match value {
            1 => AesMode::Cbc,
            2 => AesMode::Ctr,
            _ => AesMode::Reserved,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct AesEncryptInitRequest {
    // Encrypted CMK for AES key
    pub cmk: Cmk,
    // AES mode (CBC=1, CTR=2)
    pub mode: u32,
    // Size of plaintext in bytes
    pub plaintext_size: u32,
    // Plaintext data
    pub plaintext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for AesEncryptInitRequest {
    fn default() -> Self {
        Self {
            cmk: Cmk::default(),
            mode: AesMode::Cbc as u32,
            plaintext_size: 0,
            plaintext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct AesEncryptInitResponse {
    pub common: CommonResponse,
    // Encrypted context for subsequent Update calls
    pub context: [u8; AES_CONTEXT_SIZE],
    // Generated IV
    pub iv: [u8; AES_IV_SIZE],
    // Size of ciphertext in bytes
    pub ciphertext_size: u32,
    // Ciphertext data
    pub ciphertext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for AesEncryptInitResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse { fips_status: 0 },
            context: [0u8; AES_CONTEXT_SIZE],
            iv: [0u8; AES_IV_SIZE],
            ciphertext_size: 0,
            ciphertext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

impl CommandRequest for AesEncryptInitRequest {
    type Response = AesEncryptInitResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::AesEncryptInit;
}

impl CommandResponse for AesEncryptInitResponse {}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct AesEncryptUpdateRequest {
    // Encrypted context from Init/previous Update
    pub context: [u8; AES_CONTEXT_SIZE],
    // Size of plaintext in bytes
    pub plaintext_size: u32,
    // Plaintext data
    pub plaintext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for AesEncryptUpdateRequest {
    fn default() -> Self {
        Self {
            context: [0u8; AES_CONTEXT_SIZE],
            plaintext_size: 0,
            plaintext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct AesEncryptUpdateResponse {
    pub common: CommonResponse,
    // Updated context
    pub context: [u8; AES_CONTEXT_SIZE],
    // Size of ciphertext in bytes
    pub ciphertext_size: u32,
    // Ciphertext data
    pub ciphertext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for AesEncryptUpdateResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse { fips_status: 0 },
            context: [0u8; AES_CONTEXT_SIZE],
            ciphertext_size: 0,
            ciphertext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

impl CommandRequest for AesEncryptUpdateRequest {
    type Response = AesEncryptUpdateResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::AesEncryptUpdate;
}

impl CommandResponse for AesEncryptUpdateResponse {}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct AesDecryptInitRequest {
    // Encrypted CMK for AES key
    pub cmk: Cmk,
    // AES mode (CBC=1, CTR=2)
    pub mode: u32,
    // IV used during encryption
    pub iv: [u8; AES_IV_SIZE],
    // Size of ciphertext in bytes
    pub ciphertext_size: u32,
    // Ciphertext data
    pub ciphertext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for AesDecryptInitRequest {
    fn default() -> Self {
        Self {
            cmk: Cmk::default(),
            mode: AesMode::Cbc as u32,
            iv: [0u8; AES_IV_SIZE],
            ciphertext_size: 0,
            ciphertext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct AesDecryptInitResponse {
    pub common: CommonResponse,
    // Encrypted context for subsequent Update calls
    pub context: [u8; AES_CONTEXT_SIZE],
    // Size of plaintext in bytes
    pub plaintext_size: u32,
    // Plaintext data
    pub plaintext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for AesDecryptInitResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse { fips_status: 0 },
            context: [0u8; AES_CONTEXT_SIZE],
            plaintext_size: 0,
            plaintext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

impl CommandRequest for AesDecryptInitRequest {
    type Response = AesDecryptInitResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::AesDecryptInit;
}

impl CommandResponse for AesDecryptInitResponse {}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct AesDecryptUpdateRequest {
    // Encrypted context from Init/previous Update
    pub context: [u8; AES_CONTEXT_SIZE],
    // Size of ciphertext in bytes
    pub ciphertext_size: u32,
    // Ciphertext data
    pub ciphertext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for AesDecryptUpdateRequest {
    fn default() -> Self {
        Self {
            context: [0u8; AES_CONTEXT_SIZE],
            ciphertext_size: 0,
            ciphertext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct AesDecryptUpdateResponse {
    pub common: CommonResponse,
    // Updated context
    pub context: [u8; AES_CONTEXT_SIZE],
    // Size of plaintext in bytes
    pub plaintext_size: u32,
    // Plaintext data
    pub plaintext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for AesDecryptUpdateResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse { fips_status: 0 },
            context: [0u8; AES_CONTEXT_SIZE],
            plaintext_size: 0,
            plaintext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

impl CommandRequest for AesDecryptUpdateRequest {
    type Response = AesDecryptUpdateResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::AesDecryptUpdate;
}

impl CommandResponse for AesDecryptUpdateResponse {}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct AesGcmEncryptInitRequest {
    // Flags (reserved)
    pub flags: u32,
    // Encrypted CMK for AES key
    pub cmk: Cmk,
    // Size of AAD in bytes
    pub aad_size: u32,
    // Additional Authenticated Data
    pub aad: [u8; MAX_AES_DATA_SIZE],
}

impl Default for AesGcmEncryptInitRequest {
    fn default() -> Self {
        Self {
            flags: 0,
            cmk: Cmk::default(),
            aad_size: 0,
            aad: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct AesGcmEncryptInitResponse {
    pub common: CommonResponse,
    // Encrypted context for subsequent calls
    pub context: [u8; AES_GCM_CONTEXT_SIZE],
    // Generated IV
    pub iv: [u8; AES_GCM_IV_SIZE],
}

impl Default for AesGcmEncryptInitResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse { fips_status: 0 },
            context: [0u8; AES_GCM_CONTEXT_SIZE],
            iv: [0u8; AES_GCM_IV_SIZE],
        }
    }
}

impl CommandRequest for AesGcmEncryptInitRequest {
    type Response = AesGcmEncryptInitResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::AesGcmEncryptInit;
}

impl CommandResponse for AesGcmEncryptInitResponse {}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct AesGcmEncryptUpdateRequest {
    // Encrypted context
    pub context: [u8; AES_GCM_CONTEXT_SIZE],
    // Size of plaintext in bytes
    pub plaintext_size: u32,
    // Plaintext data
    pub plaintext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for AesGcmEncryptUpdateRequest {
    fn default() -> Self {
        Self {
            context: [0u8; AES_GCM_CONTEXT_SIZE],
            plaintext_size: 0,
            plaintext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct AesGcmEncryptUpdateResponse {
    pub common: CommonResponse,
    // Updated context
    pub context: [u8; AES_GCM_CONTEXT_SIZE],
    // Size of ciphertext in bytes
    pub ciphertext_size: u32,
    // Ciphertext data
    pub ciphertext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for AesGcmEncryptUpdateResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse { fips_status: 0 },
            context: [0u8; AES_GCM_CONTEXT_SIZE],
            ciphertext_size: 0,
            ciphertext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

impl CommandRequest for AesGcmEncryptUpdateRequest {
    type Response = AesGcmEncryptUpdateResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::AesGcmEncryptUpdate;
}

impl CommandResponse for AesGcmEncryptUpdateResponse {}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct AesGcmEncryptFinalRequest {
    // Encrypted context
    pub context: [u8; AES_GCM_CONTEXT_SIZE],
    // Size of final plaintext in bytes
    pub plaintext_size: u32,
    // Final plaintext data
    pub plaintext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for AesGcmEncryptFinalRequest {
    fn default() -> Self {
        Self {
            context: [0u8; AES_GCM_CONTEXT_SIZE],
            plaintext_size: 0,
            plaintext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct AesGcmEncryptFinalResponse {
    pub common: CommonResponse,
    // Authentication tag
    pub tag: [u8; AES_GCM_TAG_SIZE],
    // Size of ciphertext in bytes
    pub ciphertext_size: u32,
    // Ciphertext data
    pub ciphertext: [u8; MAX_AES_GCM_OUTPUT_SIZE],
}

impl Default for AesGcmEncryptFinalResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse { fips_status: 0 },
            tag: [0u8; AES_GCM_TAG_SIZE],
            ciphertext_size: 0,
            ciphertext: [0u8; MAX_AES_GCM_OUTPUT_SIZE],
        }
    }
}

impl CommandRequest for AesGcmEncryptFinalRequest {
    type Response = AesGcmEncryptFinalResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::AesGcmEncryptFinal;
}

impl CommandResponse for AesGcmEncryptFinalResponse {}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct AesGcmDecryptInitRequest {
    // Flags (reserved)
    pub flags: u32,
    // Encrypted CMK for AES key
    pub cmk: Cmk,
    // IV used during encryption
    pub iv: [u8; AES_GCM_IV_SIZE],
    // Size of AAD in bytes
    pub aad_size: u32,
    // Additional Authenticated Data
    pub aad: [u8; MAX_AES_DATA_SIZE],
}

impl Default for AesGcmDecryptInitRequest {
    fn default() -> Self {
        Self {
            flags: 0,
            cmk: Cmk::default(),
            iv: [0u8; AES_GCM_IV_SIZE],
            aad_size: 0,
            aad: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct AesGcmDecryptInitResponse {
    pub common: CommonResponse,
    // Encrypted context for subsequent calls
    pub context: [u8; AES_GCM_CONTEXT_SIZE],
}

impl Default for AesGcmDecryptInitResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse { fips_status: 0 },
            context: [0u8; AES_GCM_CONTEXT_SIZE],
        }
    }
}

impl CommandRequest for AesGcmDecryptInitRequest {
    type Response = AesGcmDecryptInitResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::AesGcmDecryptInit;
}

impl CommandResponse for AesGcmDecryptInitResponse {}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct AesGcmDecryptUpdateRequest {
    // Encrypted context
    pub context: [u8; AES_GCM_CONTEXT_SIZE],
    // Size of ciphertext in bytes
    pub ciphertext_size: u32,
    // Ciphertext data
    pub ciphertext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for AesGcmDecryptUpdateRequest {
    fn default() -> Self {
        Self {
            context: [0u8; AES_GCM_CONTEXT_SIZE],
            ciphertext_size: 0,
            ciphertext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct AesGcmDecryptUpdateResponse {
    pub common: CommonResponse,
    // Updated context
    pub context: [u8; AES_GCM_CONTEXT_SIZE],
    // Size of plaintext in bytes
    pub plaintext_size: u32,
    // Plaintext data
    pub plaintext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for AesGcmDecryptUpdateResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse { fips_status: 0 },
            context: [0u8; AES_GCM_CONTEXT_SIZE],
            plaintext_size: 0,
            plaintext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

impl CommandRequest for AesGcmDecryptUpdateRequest {
    type Response = AesGcmDecryptUpdateResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::AesGcmDecryptUpdate;
}

impl CommandResponse for AesGcmDecryptUpdateResponse {}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct AesGcmDecryptFinalRequest {
    // Encrypted context
    pub context: [u8; AES_GCM_CONTEXT_SIZE],
    // Length of tag (always 16)
    pub tag_len: u32,
    // Authentication tag to verify
    pub tag: [u8; AES_GCM_TAG_SIZE],
    // Size of ciphertext in bytes
    pub ciphertext_size: u32,
    // Ciphertext data
    pub ciphertext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for AesGcmDecryptFinalRequest {
    fn default() -> Self {
        Self {
            context: [0u8; AES_GCM_CONTEXT_SIZE],
            tag_len: AES_GCM_TAG_SIZE as u32,
            tag: [0u8; AES_GCM_TAG_SIZE],
            ciphertext_size: 0,
            ciphertext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct AesGcmDecryptFinalResponse {
    pub common: CommonResponse,
    // Tag verification result (1 = verified, 0 = failed)
    pub tag_verified: u32,
    // Size of plaintext in bytes
    pub plaintext_size: u32,
    // Plaintext data
    pub plaintext: [u8; MAX_AES_GCM_OUTPUT_SIZE],
}

impl Default for AesGcmDecryptFinalResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse { fips_status: 0 },
            tag_verified: 0,
            plaintext_size: 0,
            plaintext: [0u8; MAX_AES_GCM_OUTPUT_SIZE],
        }
    }
}

impl CommandRequest for AesGcmDecryptFinalRequest {
    type Response = AesGcmDecryptFinalResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::AesGcmDecryptFinal;
}

impl CommandResponse for AesGcmDecryptFinalResponse {}
