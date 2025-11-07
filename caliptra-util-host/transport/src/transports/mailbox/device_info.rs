// Licensed under the Apache-2.0 license

//! Device information commands for mailbox transport
//!
//! This module provides command definitions and implementations for device information
//! commands using the mailbox transport protocol.
//!
//! These types match the external mailbox command specification from external_mailbox_cmds.md
//! They are prefixed with ExtCmd to distinguish them from internal command types.

use super::checksum::calc_checksum;
use super::command_traits::*;
use caliptra_util_host_command_types::*;
use zerocopy::{FromBytes, Immutable, IntoBytes};

// Re-export the common functions for use by transport module
pub use super::command_traits::{process_command, process_command_with_metadata};

// ============================================================================
// Device Information Command Definitions
// ============================================================================

// Define all command metadata using the macro
// To add a new command:
// 1. Define external types (ExtCmd* structs) with trait implementations below
// 2. Add one line here: define_command!(YourCommand, 0xCODE, InternalReq, InternalResp, ExtReq, ExtResp);
// 3. Add one line to command_mapping below: (CaliptraCommandId::YourCommand, YourCommand),
// That's it! The generic processor handles everything else automatically.

crate::define_command!(
    GetDeviceIdCommand,
    0x4D44_4944,
    GetDeviceIdRequest,
    GetDeviceIdResponse,
    ExtCmdGetDeviceIdRequest,
    ExtCmdGetDeviceIdResponse
); // "MDID"
crate::define_command!(
    GetDeviceCapabilitiesCommand,
    0x4D43_4150,
    GetDeviceCapabilitiesRequest,
    GetDeviceCapabilitiesResponse,
    ExtCmdGetDeviceCapabilitiesRequest,
    ExtCmdGetDeviceCapabilitiesResponse
); // "MCAP"
crate::define_command!(
    GetFirmwareVersionCommand,
    0x4D46_5756,
    GetFirmwareVersionRequest,
    GetFirmwareVersionResponse,
    ExtCmdGetFirmwareVersionRequest,
    ExtCmdGetFirmwareVersionResponse
); // "MFWV"
crate::define_command!(
    GetDeviceInfoCommand,
    0x4D44_494E,
    GetDeviceInfoRequest,
    GetDeviceInfoResponse,
    ExtCmdGetDeviceInfoRequest,
    ExtCmdGetDeviceInfoResponse
); // "MDIN"

// Generate command handler mappings using CaliptraCommandId enum values
crate::command_mapping! {
    (CaliptraCommandId::GetFirmwareVersion, GetFirmwareVersionCommand),
    (CaliptraCommandId::GetDeviceCapabilities, GetDeviceCapabilitiesCommand),
    (CaliptraCommandId::GetDeviceId, GetDeviceIdCommand),
    (CaliptraCommandId::GetDeviceInfo, GetDeviceInfoCommand),
}

// ============================================================================
// MC_DEVICE_ID Command (0x4D44_4944 - "MDID")
// ============================================================================

/// External command: Get device ID request (MC_DEVICE_ID)
/// Matches the format specified in external_mailbox_cmds.md
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdGetDeviceIdRequest {
    /// Checksum over input data
    pub chksum: u32,
}

/// External command: Get device ID response (MC_DEVICE_ID)
/// Matches the format specified in external_mailbox_cmds.md
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdGetDeviceIdResponse {
    /// Checksum field
    pub chksum: u32,

    /// FIPS approved or an error
    pub fips_status: u32,

    /// Vendor ID; LSB
    pub vendor_id: u16,

    /// Device ID; LSB
    pub device_id: u16,

    /// Subsystem Vendor ID; LSB
    pub subsystem_vendor_id: u16,

    /// Subsystem ID; LSB
    pub subsystem_id: u16,
}

impl FromInternalRequest<GetDeviceIdRequest> for ExtCmdGetDeviceIdRequest {
    fn from_internal(_internal: &GetDeviceIdRequest, command_code: u32) -> Self {
        // For empty requests, the payload is empty, so checksum is calculated with empty data
        let chksum = calc_checksum(command_code, &[]);
        Self { chksum }
    }
}

impl ToInternalResponse<GetDeviceIdResponse> for ExtCmdGetDeviceIdResponse {
    fn to_internal(&self) -> GetDeviceIdResponse {
        GetDeviceIdResponse {
            vendor_id: self.vendor_id,
            device_id: self.device_id,
            subsystem_vendor_id: self.subsystem_vendor_id,
            subsystem_id: self.subsystem_id,
        }
    }
}

// ============================================================================
// MC_DEVICE_CAPABILITIES Command (0x4D43_4150 - "MCAP")
// ============================================================================

/// External command: Get device capabilities request (MC_DEVICE_CAPABILITIES)
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdGetDeviceCapabilitiesRequest {
    /// Checksum over input data
    pub chksum: u32,
}

/// External command: Get device capabilities response (MC_DEVICE_CAPABILITIES)
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdGetDeviceCapabilitiesResponse {
    /// Checksum field
    pub chksum: u32,

    /// FIPS approved or an error
    pub fips_status: u32,

    /// Device capabilities as defined in external mailbox spec
    /// - Bytes [0:7]: Reserved for Caliptra RT
    /// - Bytes [8:11]: Reserved for Caliptra FMC  
    /// - Bytes [12:15]: Reserved for Caliptra ROM
    /// - Bytes [16:23]: Reserved for MCU RT
    /// - Bytes [24:27]: Reserved for MCU ROM
    /// - Bytes [28:31]: Reserved
    pub caps: [u8; 32],
}

impl FromInternalRequest<GetDeviceCapabilitiesRequest> for ExtCmdGetDeviceCapabilitiesRequest {
    fn from_internal(_internal: &GetDeviceCapabilitiesRequest, command_code: u32) -> Self {
        // For empty requests, the payload is empty, so checksum is calculated with empty data
        let chksum = calc_checksum(command_code, &[]);
        Self { chksum }
    }
}

impl ToInternalResponse<GetDeviceCapabilitiesResponse> for ExtCmdGetDeviceCapabilitiesResponse {
    fn to_internal(&self) -> GetDeviceCapabilitiesResponse {
        GetDeviceCapabilitiesResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            capabilities: u32::from_le_bytes([
                self.caps[0],
                self.caps[1],
                self.caps[2],
                self.caps[3],
            ]),
            max_cert_size: u32::from_le_bytes([
                self.caps[4],
                self.caps[5],
                self.caps[6],
                self.caps[7],
            ]),
            max_csr_size: u32::from_le_bytes([
                self.caps[8],
                self.caps[9],
                self.caps[10],
                self.caps[11],
            ]),
            device_lifecycle: u32::from_le_bytes([
                self.caps[12],
                self.caps[13],
                self.caps[14],
                self.caps[15],
            ]),
        }
    }
}

impl FromInternalRequest<GetFirmwareVersionRequest> for ExtCmdGetFirmwareVersionRequest {
    fn from_internal(internal: &GetFirmwareVersionRequest, command_code: u32) -> Self {
        // Calculate checksum using zerocopy as_bytes() for the entire payload
        let chksum = calc_checksum(command_code, internal.as_bytes());
        Self {
            chksum,
            index: internal.index,
        }
    }
}

impl ToInternalResponse<GetFirmwareVersionResponse> for ExtCmdGetFirmwareVersionResponse {
    fn to_internal(&self) -> GetFirmwareVersionResponse {
        let mut version = [0u32; 4];
        let mut commit_id = [0u8; 20];

        // Parse version from ASCII format - simplified implementation
        // In real implementation, would parse semantic version from self.version
        version[0] = 1; // Major
        version[1] = 0; // Minor
        version[2] = 0; // Patch
        version[3] = 0; // Build

        // Copy commit ID from version string if available
        let commit_bytes = &self.version[..20.min(self.version.len())];
        commit_id[..commit_bytes.len()].copy_from_slice(commit_bytes);

        GetFirmwareVersionResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            version,
            commit_id,
        }
    }
}

impl FromInternalRequest<GetDeviceInfoRequest> for ExtCmdGetDeviceInfoRequest {
    fn from_internal(internal: &GetDeviceInfoRequest, command_code: u32) -> Self {
        // Calculate checksum using zerocopy as_bytes() for the entire payload
        let chksum = calc_checksum(command_code, internal.as_bytes());
        Self {
            chksum,
            index: internal.info_type, // Map info_type to index
        }
    }
}

impl ToInternalResponse<GetDeviceInfoResponse> for ExtCmdGetDeviceInfoResponse {
    fn to_internal(&self) -> GetDeviceInfoResponse {
        let mut info_data = [0u8; 64];
        let data_len = (self.data_size as usize).min(64);
        info_data[..data_len].copy_from_slice(&self.data[..data_len]);

        GetDeviceInfoResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            info_length: self.data_size,
            info_data,
        }
    }
}

// ============================================================================
// MC_FIRMWARE_VERSION Command (0x4D46_5756 - "MFWV")
// ============================================================================

/// External command: Get firmware version request (MC_FIRMWARE_VERSION)
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdGetFirmwareVersionRequest {
    /// Checksum over input data
    pub chksum: u32,

    /// Firmware index:
    /// - 0x00 = Caliptra core firmware
    /// - 0x01 = MCU runtime firmware  
    /// - 0x02 = SoC firmware
    ///   Additional indexes are firmware-specific
    pub index: u32,
}

/// External command: Get firmware version response (MC_FIRMWARE_VERSION)
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdGetFirmwareVersionResponse {
    /// Checksum field
    pub chksum: u32,

    /// FIPS approved or an error
    pub fips_status: u32,

    /// Firmware Version Number in ASCII format
    pub version: [u8; 32],
}

// ============================================================================
// MC_DEVICE_INFO Command (0x4D44_494E - "MDIN")
// ============================================================================

/// External command: Get device info request (MC_DEVICE_INFO)
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdGetDeviceInfoRequest {
    /// Checksum over input data
    pub chksum: u32,

    /// Information Index:
    /// - 0x00 = Unique Chip Identifier
    ///   Additional indexes are firmware-specific
    pub index: u32,
}

/// External command: Get device info response (MC_DEVICE_INFO)
/// Note: This uses a fixed-size buffer for simplicity in this implementation
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdGetDeviceInfoResponse {
    /// Checksum field
    pub chksum: u32,

    /// FIPS approved or an error
    pub fips_status: u32,

    /// Size of the requested data in bytes
    pub data_size: u32,

    /// Requested information in binary format (fixed size for this implementation)
    pub data: [u8; 64],
}
