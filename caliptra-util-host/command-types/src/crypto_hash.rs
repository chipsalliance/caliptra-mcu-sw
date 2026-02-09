// Licensed under the Apache-2.0 license

//! Cryptographic Hash Commands
//!
//! Command structures for SHA operations (SHA384, SHA512)
//!
//! SHA operations use a three-phase pattern:
//! 1. `ShaInit` - Initialize hash context with optional initial data
//! 2. `ShaUpdate` - Add more data to the hash (can be called multiple times)
//! 3. `ShaFinal` - Finalize and get the hash result

use crate::{CaliptraCommandId, CommandRequest, CommandResponse, CommonResponse};
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const MAX_SHA_INPUT_SIZE: usize = 4096;
pub const SHA_CONTEXT_SIZE: usize = 200;
pub const MAX_HASH_SIZE: usize = 64;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShaAlgorithm {
    #[default]
    Sha384 = 1,
    Sha512 = 2,
}

impl ShaAlgorithm {
    pub fn hash_size(&self) -> usize {
        match self {
            ShaAlgorithm::Sha384 => 48,
            ShaAlgorithm::Sha512 => 64,
        }
    }
}

impl From<u32> for ShaAlgorithm {
    fn from(value: u32) -> Self {
        match value {
            1 => ShaAlgorithm::Sha384,
            2 => ShaAlgorithm::Sha512,
            _ => ShaAlgorithm::Sha384, // Default to SHA384
        }
    }
}

impl From<ShaAlgorithm> for u32 {
    fn from(algo: ShaAlgorithm) -> Self {
        algo as u32
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ShaInitRequest {
    pub algorithm: u32,
    pub input_size: u32,
    pub input: [u8; MAX_SHA_INPUT_SIZE],
}

impl Default for ShaInitRequest {
    fn default() -> Self {
        Self {
            algorithm: ShaAlgorithm::Sha384 as u32,
            input_size: 0,
            input: [0u8; MAX_SHA_INPUT_SIZE],
        }
    }
}

impl ShaInitRequest {
    pub fn new(algorithm: ShaAlgorithm, data: &[u8]) -> Self {
        let copy_len = core::cmp::min(data.len(), MAX_SHA_INPUT_SIZE);
        let mut req = Self {
            algorithm: algorithm as u32,
            input_size: copy_len as u32,
            input: [0u8; MAX_SHA_INPUT_SIZE],
        };
        req.input[..copy_len].copy_from_slice(&data[..copy_len]);
        req
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ShaInitResponse {
    pub common: CommonResponse,
    pub context: [u8; SHA_CONTEXT_SIZE],
}

impl Default for ShaInitResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse { fips_status: 0 },
            context: [0u8; SHA_CONTEXT_SIZE],
        }
    }
}

impl CommandRequest for ShaInitRequest {
    type Response = ShaInitResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::HashInit;
}

impl CommandResponse for ShaInitResponse {}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ShaUpdateRequest {
    pub context: [u8; SHA_CONTEXT_SIZE],
    pub input_size: u32,
    pub input: [u8; MAX_SHA_INPUT_SIZE],
}

impl Default for ShaUpdateRequest {
    fn default() -> Self {
        Self {
            context: [0u8; SHA_CONTEXT_SIZE],
            input_size: 0,
            input: [0u8; MAX_SHA_INPUT_SIZE],
        }
    }
}

impl ShaUpdateRequest {
    pub fn new(context: &[u8; SHA_CONTEXT_SIZE], data: &[u8]) -> Self {
        let mut req = Self {
            context: *context,
            input_size: data.len() as u32,
            input: [0u8; MAX_SHA_INPUT_SIZE],
        };
        let copy_len = core::cmp::min(data.len(), MAX_SHA_INPUT_SIZE);
        req.input[..copy_len].copy_from_slice(&data[..copy_len]);
        req
    }
}

pub type ShaUpdateResponse = ShaInitResponse;

impl CommandRequest for ShaUpdateRequest {
    type Response = ShaUpdateResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::HashUpdate;
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ShaFinalRequest {
    pub context: [u8; SHA_CONTEXT_SIZE],
    pub input_size: u32,
    pub input: [u8; MAX_SHA_INPUT_SIZE],
}

impl Default for ShaFinalRequest {
    fn default() -> Self {
        Self {
            context: [0u8; SHA_CONTEXT_SIZE],
            input_size: 0,
            input: [0u8; MAX_SHA_INPUT_SIZE],
        }
    }
}

impl ShaFinalRequest {
    pub fn new(context: &[u8; SHA_CONTEXT_SIZE]) -> Self {
        Self {
            context: *context,
            input_size: 0,
            input: [0u8; MAX_SHA_INPUT_SIZE],
        }
    }

    pub fn new_with_data(context: &[u8; SHA_CONTEXT_SIZE], data: &[u8]) -> Self {
        let copy_len = core::cmp::min(data.len(), MAX_SHA_INPUT_SIZE);
        let mut req = Self {
            context: *context,
            input_size: copy_len as u32,
            input: [0u8; MAX_SHA_INPUT_SIZE],
        };
        req.input[..copy_len].copy_from_slice(&data[..copy_len]);
        req
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ShaFinalResponse {
    pub common: CommonResponse,
    pub hash_size: u32,
    pub hash: [u8; MAX_HASH_SIZE],
}

impl Default for ShaFinalResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse { fips_status: 0 },
            hash_size: 0,
            hash: [0u8; MAX_HASH_SIZE],
        }
    }
}

impl CommandRequest for ShaFinalRequest {
    type Response = ShaFinalResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::HashFinalize;
}

impl CommandResponse for ShaFinalResponse {}
