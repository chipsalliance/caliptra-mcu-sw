// Licensed under the Apache-2.0 license

//! Cryptographic HMAC and KDF Commands
//!
//! Command structures for HMAC and HMAC-based KDF operations.
//!
//! HMAC operations:
//! - `HmacRequest` - Compute HMAC-SHA384/SHA512 over data using a key
//!
//! KDF operations:
//! - `HmacKdfCounterRequest` - Derive a key using HMAC-based KDF in counter mode

use crate::{CaliptraCommandId, CommandRequest, CommandResponse, CommonResponse};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Maximum input data size per HMAC/KDF request (matches MAX_CMB_DATA_SIZE from caliptra-api)
pub const MAX_HMAC_INPUT_SIZE: usize = 4096;

/// Maximum HMAC output size (SHA512 = 64 bytes)
pub const MAX_HMAC_SIZE: usize = 64;

/// Cryptographic Mailbox Key size in bytes
pub const CMK_SIZE: usize = 128;

/// Cryptographic Mailbox Key (CMK)
///
/// An opaque, encrypted 128-byte wrapper around a cryptographic key.
/// Keys are encrypted by the MCU and cannot be accessed directly by the host.
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable, PartialEq, Eq)]
pub struct Cmk(pub [u8; CMK_SIZE]);

impl Default for Cmk {
    fn default() -> Self {
        Self([0u8; CMK_SIZE])
    }
}

impl Cmk {
    /// Create a new CMK from raw bytes
    pub fn new(data: [u8; CMK_SIZE]) -> Self {
        Self(data)
    }

    /// Get the raw bytes of the CMK
    pub fn as_bytes(&self) -> &[u8; CMK_SIZE] {
        &self.0
    }
}

/// Key usage types for cryptographic operations
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CmKeyUsage {
    /// Reserved/invalid
    #[default]
    Reserved = 0,
    /// HMAC operations
    Hmac = 1,
    /// AES encryption/decryption
    Aes = 2,
    /// ECDSA signing
    Ecdsa = 3,
    /// ML-DSA signing
    Mldsa = 4,
}

impl From<u32> for CmKeyUsage {
    fn from(value: u32) -> Self {
        match value {
            1 => CmKeyUsage::Hmac,
            2 => CmKeyUsage::Aes,
            3 => CmKeyUsage::Ecdsa,
            4 => CmKeyUsage::Mldsa,
            _ => CmKeyUsage::Reserved,
        }
    }
}

impl From<CmKeyUsage> for u32 {
    fn from(usage: CmKeyUsage) -> Self {
        usage as u32
    }
}

/// HMAC algorithm selection
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HmacAlgorithm {
    /// SHA-384 (48-byte MAC output)
    #[default]
    Sha384 = 1,
    /// SHA-512 (64-byte MAC output)
    Sha512 = 2,
}

impl HmacAlgorithm {
    /// Get the MAC output size in bytes
    pub fn mac_size(&self) -> usize {
        match self {
            HmacAlgorithm::Sha384 => 48,
            HmacAlgorithm::Sha512 => 64,
        }
    }
}

impl From<u32> for HmacAlgorithm {
    fn from(value: u32) -> Self {
        match value {
            1 => HmacAlgorithm::Sha384,
            2 => HmacAlgorithm::Sha512,
            _ => HmacAlgorithm::Sha384, // Default to SHA384
        }
    }
}

impl From<HmacAlgorithm> for u32 {
    fn from(algo: HmacAlgorithm) -> Self {
        algo as u32
    }
}

// ============================================================================
// HMAC Command
// ============================================================================

/// HMAC request - compute HMAC over data using a key
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct HmacRequest {
    /// Cryptographic mailbox key (encrypted)
    pub cmk: Cmk,
    /// Hash algorithm (1 = SHA384, 2 = SHA512)
    pub hash_algorithm: u32,
    /// Size of input data in bytes
    pub data_size: u32,
    /// Input data (variable length, up to MAX_HMAC_INPUT_SIZE)
    pub data: [u8; MAX_HMAC_INPUT_SIZE],
}

impl Default for HmacRequest {
    fn default() -> Self {
        Self {
            cmk: Cmk::default(),
            hash_algorithm: HmacAlgorithm::Sha384 as u32,
            data_size: 0,
            data: [0u8; MAX_HMAC_INPUT_SIZE],
        }
    }
}

impl HmacRequest {
    /// Create a new HMAC request
    pub fn new(cmk: &Cmk, algorithm: HmacAlgorithm, data: &[u8]) -> Self {
        let mut req = Self {
            cmk: cmk.clone(),
            hash_algorithm: algorithm as u32,
            data_size: data.len() as u32,
            data: [0u8; MAX_HMAC_INPUT_SIZE],
        };
        let copy_len = core::cmp::min(data.len(), MAX_HMAC_INPUT_SIZE);
        req.data[..copy_len].copy_from_slice(&data[..copy_len]);
        req
    }
}

/// HMAC response - contains the computed MAC
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct HmacResponse {
    /// Common response header
    pub common: CommonResponse,
    /// Size of the MAC in bytes (48 for SHA384, 64 for SHA512)
    pub mac_size: u32,
    /// MAC output (up to 64 bytes)
    pub mac: [u8; MAX_HMAC_SIZE],
}

impl Default for HmacResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse { fips_status: 0 },
            mac_size: 0,
            mac: [0u8; MAX_HMAC_SIZE],
        }
    }
}

impl CommandRequest for HmacRequest {
    type Response = HmacResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::Hmac;
}

impl CommandResponse for HmacResponse {}

// ============================================================================
// HMAC KDF Counter Command
// ============================================================================

/// HMAC KDF Counter request - derive a key using HMAC-based KDF in counter mode
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct HmacKdfCounterRequest {
    /// Input key (encrypted CMK)
    pub kin: Cmk,
    /// Hash algorithm (1 = SHA384, 2 = SHA512)
    pub hash_algorithm: u32,
    /// Key usage for the derived key
    pub key_usage: u32,
    /// Size of the derived key in bytes (32 for AES, 48 for ECDSA/SHA384-HMAC, 64 for SHA512-HMAC)
    pub key_size: u32,
    /// Size of the label in bytes
    pub label_size: u32,
    /// Label data (variable length, up to MAX_HMAC_INPUT_SIZE)
    pub label: [u8; MAX_HMAC_INPUT_SIZE],
}

impl Default for HmacKdfCounterRequest {
    fn default() -> Self {
        Self {
            kin: Cmk::default(),
            hash_algorithm: HmacAlgorithm::Sha384 as u32,
            key_usage: CmKeyUsage::Reserved as u32,
            key_size: 0,
            label_size: 0,
            label: [0u8; MAX_HMAC_INPUT_SIZE],
        }
    }
}

impl HmacKdfCounterRequest {
    /// Create a new HMAC KDF Counter request
    pub fn new(
        kin: &Cmk,
        algorithm: HmacAlgorithm,
        key_usage: CmKeyUsage,
        key_size: u32,
        label: &[u8],
    ) -> Self {
        let mut req = Self {
            kin: kin.clone(),
            hash_algorithm: algorithm as u32,
            key_usage: key_usage as u32,
            key_size,
            label_size: label.len() as u32,
            label: [0u8; MAX_HMAC_INPUT_SIZE],
        };
        let copy_len = core::cmp::min(label.len(), MAX_HMAC_INPUT_SIZE);
        req.label[..copy_len].copy_from_slice(&label[..copy_len]);
        req
    }
}

/// HMAC KDF Counter response - contains the derived key
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct HmacKdfCounterResponse {
    /// Common response header
    pub common: CommonResponse,
    /// Output key (encrypted CMK)
    pub kout: Cmk,
}

impl Default for HmacKdfCounterResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse { fips_status: 0 },
            kout: Cmk::default(),
        }
    }
}

impl CommandRequest for HmacKdfCounterRequest {
    type Response = HmacKdfCounterResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::HmacKdfCounter;
}

impl CommandResponse for HmacKdfCounterResponse {}
