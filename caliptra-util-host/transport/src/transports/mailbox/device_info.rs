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
use caliptra_mcu_core_util_host_command_types::*;
use zerocopy::{FromBytes, Immutable, IntoBytes};

// Re-export the common functions and traits for use by transport module
pub use super::command_traits::{process_command, process_command_with_metadata};

// ============================================================================
// Forward Declarations - All structs are defined first, then traits, then macros
// ============================================================================

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

        // Use data_len to determine actual version string length
        let actual_len = core::cmp::min(self.data_len as usize, 32);
        let version_str = core::str::from_utf8(&self.version[..actual_len])
            .unwrap_or("")
            .trim_end_matches('\0');

        if let Some((version_part, _)) = version_str.split_once(' ') {
            // Try to parse semantic version
            for (part_index, part) in version_part.split('.').take(4).enumerate() {
                if let Ok(num) = part.parse::<u32>() {
                    version[part_index] = num;
                }
            }
        }

        // Extract commit ID if present after version (after space)
        if let Some((_, commit_part)) = version_str.split_once(' ') {
            let commit_bytes = commit_part.as_bytes();
            let copy_len = core::cmp::min(commit_bytes.len(), 20);
            commit_id[..copy_len].copy_from_slice(&commit_bytes[..copy_len]);
        }

        GetFirmwareVersionResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            version,
            commit_id,
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
/// This mirrors the MCU's FirmwareVersionResp structure with MailboxRespHeaderVarSize
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdGetFirmwareVersionResponse {
    /// Checksum field
    pub chksum: u32,

    /// FIPS approved or an error
    pub fips_status: u32,

    /// Length of firmware version data
    pub data_len: u32,

    /// Firmware Version Number in ASCII format (variable length)
    pub version: [u8; 32],
}

impl ExtCmdGetFirmwareVersionResponse {
    /// Create a new response from MCU data with variable length
    pub fn from_mcu_data(
        chksum: u32,
        fips_status: u32,
        data_len: u32,
        version_data: &[u8],
    ) -> Self {
        let mut version = [0u8; 32];
        let copy_len = (data_len as usize).min(32).min(version_data.len());
        version[..copy_len].copy_from_slice(&version_data[..copy_len]);

        Self {
            chksum,
            fips_status,
            data_len,
            version,
        }
    }
}

impl VariableSizeBytes for ExtCmdGetFirmwareVersionResponse {
    fn from_bytes_variable(bytes: &[u8]) -> Result<Self, crate::TransportError> {
        if bytes.len() < 12 {
            return Err(crate::TransportError::InvalidMessage);
        }

        let chksum = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let fips_status = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let data_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);

        if bytes.len() < 12 + (data_len as usize) {
            return Err(crate::TransportError::InvalidMessage);
        }

        let mut version = [0u8; 32];
        let copy_len = core::cmp::min(data_len as usize, 32);
        version[..copy_len].copy_from_slice(&bytes[12..12 + copy_len]);

        Ok(ExtCmdGetFirmwareVersionResponse {
            chksum,
            fips_status,
            data_len,
            version,
        })
    }

    fn to_bytes_variable(&self, buffer: &mut [u8]) -> usize {
        let header_size = 12;
        let actual_len = core::cmp::min(self.data_len as usize, 32);
        let total_size = header_size + actual_len;

        if buffer.len() < total_size {
            return 0; // Insufficient buffer space
        }

        buffer[0..4].copy_from_slice(&self.chksum.to_le_bytes());
        buffer[4..8].copy_from_slice(&self.fips_status.to_le_bytes());
        buffer[8..12].copy_from_slice(&self.data_len.to_le_bytes());
        buffer[12..12 + actual_len].copy_from_slice(&self.version[..actual_len]);

        total_size
    }
}

// ============================================================================
// Default VariableSizeBytes Implementations for Fixed-Size Types
// ============================================================================

// Implement VariableSizeBytes for all request types (they are all fixed-size)
impl VariableSizeBytes for ExtCmdGetDeviceCapabilitiesRequest {}
impl VariableSizeBytes for ExtCmdGetFirmwareVersionRequest {}

// Fixed-size response types
impl VariableSizeBytes for ExtCmdGetDeviceCapabilitiesResponse {}

// ============================================================================
// Command Metadata Definitions
// ============================================================================

use crate::define_command;

define_command!(
    GetDeviceCapabilitiesCmd,
    0x4D43_4150, // MC_DEVICE_CAPABILITIES - "MCAP"
    GetDeviceCapabilitiesRequest,
    GetDeviceCapabilitiesResponse,
    ExtCmdGetDeviceCapabilitiesRequest,
    ExtCmdGetDeviceCapabilitiesResponse
);

define_command!(
    GetFirmwareVersionCmd,
    0x4D46_5756, // MC_FIRMWARE_VERSION - "MFWV"
    GetFirmwareVersionRequest,
    GetFirmwareVersionResponse,
    ExtCmdGetFirmwareVersionRequest,
    ExtCmdGetFirmwareVersionResponse
);
