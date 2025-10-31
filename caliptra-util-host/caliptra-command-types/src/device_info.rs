//! Device Information Commands
//!
//! Command structures for device identification and capabilities

use crate::{CommandRequest, CommandResponse, CommonResponse, CaliptraCommandId, CommandError};
use zerocopy::{AsBytes, FromBytes, FromZeroes};

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
#[derive(Debug, Clone, AsBytes, FromBytes, FromZeroes)]
pub struct GetFirmwareVersionRequest {
    pub index: u32, // Use u32 instead of enum for zerocopy compatibility
}

/// Firmware version response
#[repr(C)]
#[derive(Debug, Clone, AsBytes, FromBytes, FromZeroes)]
pub struct GetFirmwareVersionResponse {
    pub common: CommonResponse,
    pub version: [u32; 4], // Major, minor, patch, build
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
#[derive(Debug, Clone, AsBytes, FromBytes, FromZeroes)]
pub struct GetDeviceCapabilitiesRequest {
    // Empty request
}

/// Device capabilities response
#[repr(C)]
#[derive(Debug, Clone, AsBytes, FromBytes, FromZeroes)]
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

// ============================================================================
// GET_DEVICE_ID Command (0x0003)
// ============================================================================

/// Get device ID request (for external mailbox MC_DEVICE_ID)
#[repr(C)]
#[derive(Debug, Clone, AsBytes, FromBytes, FromZeroes)]
pub struct GetDeviceIdRequest {
    /// Checksum field (as per external mailbox spec)
    pub chksum: u32,
}

/// Get device ID response (matching MC_DEVICE_ID format)
#[repr(C)]
#[derive(Debug, Clone, AsBytes, FromBytes, FromZeroes)]
pub struct GetDeviceIdResponse {
    /// Checksum field (as per external mailbox spec)
    pub chksum: u32,
    
    /// FIPS approved status or error code
    pub fips_status: u32,
    
    /// Vendor ID (LSB)
    pub vendor_id: u16,
    
    /// Device ID (LSB)  
    pub device_id: u16,
    
    /// Subsystem Vendor ID (LSB)
    pub subsystem_vendor_id: u16,
    
    /// Subsystem ID (LSB)
    pub subsystem_id: u16,
}

impl CommandRequest for GetDeviceIdRequest {
    type Response = GetDeviceIdResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::GetDeviceId;
}

impl CommandResponse for GetDeviceIdResponse {}

// ============================================================================
// GET_DEVICE_INFO Command (0x0004) 
// ============================================================================

/// Get device info request
#[repr(C)]
#[derive(Debug, Clone, AsBytes, FromBytes, FromZeroes)]
pub struct GetDeviceInfoRequest {
    pub info_type: u32, // Type of info to retrieve
}

/// Device info response
#[repr(C)]
#[derive(Debug, Clone, AsBytes, FromBytes, FromZeroes)]
pub struct GetDeviceInfoResponse {
    pub common: CommonResponse,
    pub info_length: u32,
    pub info_data: [u8; 64], // Fixed-size buffer for info data
}

impl CommandRequest for GetDeviceInfoRequest {
    type Response = GetDeviceInfoResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::GetDeviceInfo;
}

impl CommandResponse for GetDeviceInfoResponse {}