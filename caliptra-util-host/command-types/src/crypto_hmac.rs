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

pub const MAX_HMAC_INPUT_SIZE: usize = 4096;

pub const MAX_HMAC_SIZE: usize = 64;

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
    pub fn new(data: [u8; CMK_SIZE]) -> Self {
        Self(data)
    }

    pub fn as_bytes(&self) -> &[u8; CMK_SIZE] {
        &self.0
    }
}

// Key usage types for cryptographic operations
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CmKeyUsage {
    #[default]
    Reserved = 0,
    Hmac = 1,
    Aes = 2,
    Ecdsa = 3,
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

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HmacAlgorithm {
    #[default]
    Sha384 = 1,
    Sha512 = 2,
}

impl HmacAlgorithm {
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
            _ => HmacAlgorithm::Sha384,
        }
    }
}

impl From<HmacAlgorithm> for u32 {
    fn from(algo: HmacAlgorithm) -> Self {
        algo as u32
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct HmacRequest {
    pub cmk: Cmk,
    pub hash_algorithm: u32,
    pub data_size: u32,
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
    pub fn new(cmk: &Cmk, algorithm: HmacAlgorithm, data: &[u8]) -> Self {
        let copy_len = core::cmp::min(data.len(), MAX_HMAC_INPUT_SIZE);
        let mut req = Self {
            cmk: cmk.clone(),
            hash_algorithm: algorithm as u32,
            data_size: copy_len as u32,
            data: [0u8; MAX_HMAC_INPUT_SIZE],
        };
        req.data[..copy_len].copy_from_slice(&data[..copy_len]);
        req
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct HmacResponse {
    pub common: CommonResponse,
    pub mac_size: u32,
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

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct HmacKdfCounterRequest {
    pub kin: Cmk,
    pub hash_algorithm: u32,
    pub key_usage: u32,
    pub key_size: u32,
    pub label_size: u32,
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

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct HmacKdfCounterResponse {
    pub common: CommonResponse,
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
