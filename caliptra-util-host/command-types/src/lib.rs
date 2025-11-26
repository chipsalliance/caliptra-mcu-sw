// Licensed under the Apache-2.0 license

//! Caliptra Command Types
//!
//! Shared command definitions, types, and traits for Caliptra Utility Host Library

#![no_std]

use zerocopy::{FromBytes, Immutable, IntoBytes};

// Re-export zerocopy traits for convenience
pub use zerocopy::{
    FromBytes as ZeroCopyFromBytes, FromZeros as ZeroCopyFromZeros, IntoBytes as ZeroCopyIntoBytes,
};

pub mod certificate;
pub mod crypto_aes;
pub mod crypto_asymmetric;
pub mod crypto_hash;
pub mod debug;
pub mod device_info;
pub mod error;
pub mod fuse;

// Re-export all types
pub use certificate::*;
pub use crypto_aes::*;
pub use crypto_asymmetric::*;
pub use crypto_hash::*;
pub use debug::*;
pub use device_info::*;
pub use error::*;
pub use fuse::*;

/// Caliptra command IDs matching the documentation
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaliptraCommandId {
    // Device Info Commands (0x0001-0x000F)
    GetFirmwareVersion = 0x0001,
    GetDeviceCapabilities = 0x0002,
    GetDeviceId = 0x0003,
    GetDeviceInfo = 0x0004,

    // Certificate Commands (0x1001-0x101F)
    GetIdevidCert = 0x1001,
    GetLdevidCert = 0x1002,
    GetFmcAliasCert = 0x1003,
    GetRtAliasCert = 0x1004,
    GetCertChain = 0x1010,
    StoreCertificate = 0x1011,
    GetCertificate = 0x1012, // Generic get certificate
    SetCertificate = 0x1013, // Generic set certificate

    // Hash Commands (0x2001-0x201F)
    HashInit = 0x2001,
    HashUpdate = 0x2002,
    HashFinalize = 0x2003,
    HashOneShot = 0x2004,
    HmacInit = 0x2010,
    HmacUpdate = 0x2011,
    HmacFinalize = 0x2012,
    HmacOneShot = 0x2013,

    // Symmetric Crypto Commands (0x3001-0x302F)
    AesInit = 0x3001,
    AesUpdate = 0x3002,
    AesFinalize = 0x3003,
    AesOneShot = 0x3004,
    AesGcmInit = 0x3010,
    AesGcmUpdateAad = 0x3011,
    KeyWrap = 0x3020,
    KeyUnwrap = 0x3021,

    // Asymmetric Crypto Commands (0x4001-0x402F)
    EcdsaSign = 0x4001,
    EcdsaVerify = 0x4002,
    EcdhDerive = 0x4003,
    EccKeygen = 0x4004,
    LmsKeygen = 0x4010,
    LmsSign = 0x4011,
    LmsVerify = 0x4012,
    MldsaKeygen = 0x4020,
    MldsaSign = 0x4021,
    MldsaVerify = 0x4022,

    // Debug Commands (0x7001-0x701F)
    DebugEcho = 0x7001,
    DebugGetStatus = 0x7002,
    DebugReadMemory = 0x7003,
    DebugWriteMemory = 0x7004,
    DebugGetLog = 0x7005,
    DebugSetConfig = 0x7006,
    DebugReset = 0x7007,

    // Fuse Commands (0x8001-0x801F)
    FuseRead = 0x8001,
    FuseWrite = 0x8002,
    FuseLock = 0x8003,
    FuseGetInfo = 0x8004,
    FuseProvision = 0x8005,
    FuseGetManifest = 0x8006,
}

/// Common response header for all commands
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct CommonResponse {
    pub fips_status: u32, // FIPS compliance status
}

/// Trait for command request structures
pub trait CommandRequest: IntoBytes + FromBytes + Immutable + Sized {
    type Response: CommandResponse;
    const COMMAND_ID: CaliptraCommandId;

    /// Parse request from raw bytes
    fn from_bytes(data: &[u8]) -> Result<Self, CommandError> {
        zerocopy::FromBytes::read_from_bytes(data).map_err(|_| CommandError::InvalidResponseLength)
    }

    /// Serialize request to fixed buffer
    fn to_bytes(&self, buffer: &mut [u8]) -> Result<usize, CommandError> {
        let data = zerocopy::IntoBytes::as_bytes(self);
        if buffer.len() < data.len() {
            return Err(CommandError::BufferTooSmall);
        }
        buffer[..data.len()].copy_from_slice(data);
        Ok(data.len())
    }
}

/// Trait for command response structures  
pub trait CommandResponse: IntoBytes + FromBytes + Immutable + Sized {
    /// Parse response from raw bytes
    fn from_bytes(data: &[u8]) -> Result<Self, CommandError> {
        zerocopy::FromBytes::read_from_bytes(data).map_err(|_| CommandError::InvalidResponseLength)
    }

    /// Serialize response to fixed buffer
    fn to_bytes(&self, buffer: &mut [u8]) -> Result<usize, CommandError> {
        let data = zerocopy::IntoBytes::as_bytes(self);
        if buffer.len() < data.len() {
            return Err(CommandError::BufferTooSmall);
        }
        buffer[..data.len()].copy_from_slice(data);
        Ok(data.len())
    }
}
