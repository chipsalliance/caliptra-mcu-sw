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

/// Maximum input data size per SHA request (matches MAX_CMB_DATA_SIZE from caliptra-api)
pub const MAX_SHA_INPUT_SIZE: usize = 4096;

/// SHA context size (opaque context passed between init/update/final)
/// This matches CMB_SHA_CONTEXT_SIZE from caliptra-api
pub const SHA_CONTEXT_SIZE: usize = 200;

/// Maximum hash output size (SHA512 = 64 bytes)
pub const MAX_HASH_SIZE: usize = 64;

/// SHA algorithm selection
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShaAlgorithm {
    /// SHA-384 (48-byte hash output)
    #[default]
    Sha384 = 1,
    /// SHA-512 (64-byte hash output)
    Sha512 = 2,
}

impl ShaAlgorithm {
    /// Get the hash output size in bytes
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

// ============================================================================
// SHA Init Command
// ============================================================================

/// SHA Init request - initialize hash context with optional initial data
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ShaInitRequest {
    /// Hash algorithm (1 = SHA384, 2 = SHA512)
    pub algorithm: u32,
    /// Size of input data in bytes
    pub input_size: u32,
    /// Input data (variable length, up to MAX_SHA_INPUT_SIZE)
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
    /// Create a new SHA init request
    pub fn new(algorithm: ShaAlgorithm, data: &[u8]) -> Self {
        let mut req = Self {
            algorithm: algorithm as u32,
            input_size: data.len() as u32,
            input: [0u8; MAX_SHA_INPUT_SIZE],
        };
        let copy_len = core::cmp::min(data.len(), MAX_SHA_INPUT_SIZE);
        req.input[..copy_len].copy_from_slice(&data[..copy_len]);
        req
    }
}

/// SHA Init response - contains opaque context for subsequent operations
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ShaInitResponse {
    /// Common response header
    pub common: CommonResponse,
    /// Opaque context to pass to update/final operations
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

// ============================================================================
// SHA Update Command
// ============================================================================

/// SHA Update request - add more data to the hash context
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ShaUpdateRequest {
    /// Context from previous init or update operation
    pub context: [u8; SHA_CONTEXT_SIZE],
    /// Size of input data in bytes
    pub input_size: u32,
    /// Input data (variable length, up to MAX_SHA_INPUT_SIZE)
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
    /// Create a new SHA update request
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

/// SHA Update response - same as init response (updated context)
pub type ShaUpdateResponse = ShaInitResponse;

impl CommandRequest for ShaUpdateRequest {
    type Response = ShaUpdateResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::HashUpdate;
}

// ============================================================================
// SHA Final Command
// ============================================================================

/// SHA Final request - finalize hash and get result
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ShaFinalRequest {
    /// Context from previous init or update operation
    pub context: [u8; SHA_CONTEXT_SIZE],
    /// Size of any remaining input data in bytes
    pub input_size: u32,
    /// Any remaining input data (variable length)
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
    /// Create a new SHA final request with no additional data
    pub fn new(context: &[u8; SHA_CONTEXT_SIZE]) -> Self {
        Self {
            context: *context,
            input_size: 0,
            input: [0u8; MAX_SHA_INPUT_SIZE],
        }
    }

    /// Create a new SHA final request with additional data
    pub fn new_with_data(context: &[u8; SHA_CONTEXT_SIZE], data: &[u8]) -> Self {
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

/// SHA Final response - contains the hash result
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ShaFinalResponse {
    /// Common response header
    pub common: CommonResponse,
    /// Size of the hash in bytes (48 for SHA384, 64 for SHA512)
    pub hash_size: u32,
    /// Hash output (up to 64 bytes)
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
