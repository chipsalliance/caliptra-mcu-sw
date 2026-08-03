// Licensed under the Apache-2.0 license

//! Device Information Commands
//!
//! Command structures for device identification and capabilities

use crate::{CaliptraCommandId, CommandRequest, CommandResponse, CommonResponse};
use zerocopy::{FromBytes, Immutable, IntoBytes};

// ============================================================================
// GET_FIRMWARE_VERSION Command (0x0001)
// ============================================================================

/// Firmware index enumeration
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareIndex {
    Rom = 0,
    Runtime = 1,
}

/// Get firmware version request
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct GetFirmwareVersionRequest {
    pub index: u32, // Use u32 instead of enum for zerocopy compatibility
}

/// Firmware version response
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct GetFirmwareVersionResponse {
    pub common: CommonResponse,
    pub version: [u32; 4],   // Major, minor, patch, build
    pub commit_id: [u8; 20], // Git commit SHA
}

impl CommandRequest for GetFirmwareVersionRequest {
    type Response = GetFirmwareVersionResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::GetFirmwareVersion;
}

impl CommandResponse for GetFirmwareVersionResponse {}

// ============================================================================
// GET_DEVICE_CAPABILITIES Command (0x0002)
// ============================================================================

/// Device capabilities flags
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityFlags {
    Sha256 = 0x01,
    Sha384 = 0x02,
    Sha512 = 0x04,
    Aes128 = 0x10,
    Aes256 = 0x20,
    EccP256 = 0x100,
    EccP384 = 0x200,
}

/// Get device capabilities request
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct GetDeviceCapabilitiesRequest {
    // Empty request
}

/// Device capabilities response
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct GetDeviceCapabilitiesResponse {
    pub common: CommonResponse,
    pub capabilities: u32, // Bitfield of CapabilityFlags
    pub max_cert_size: u32,
    pub max_csr_size: u32,
    pub device_lifecycle: u32,
}

impl CommandRequest for GetDeviceCapabilitiesRequest {
    type Response = GetDeviceCapabilitiesResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::GetDeviceCapabilities;
}

impl CommandResponse for GetDeviceCapabilitiesResponse {}
