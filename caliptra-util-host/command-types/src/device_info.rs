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

pub const DEVICE_CAPABILITIES_SIZE: usize = 64;

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
    pub caps: [u8; DEVICE_CAPABILITIES_SIZE],
}

impl GetDeviceCapabilitiesResponse {
    pub fn caliptra_runtime_capabilities(&self) -> u64 {
        u64::from_be_bytes(self.caps[0..8].try_into().unwrap())
    }

    pub fn caliptra_fmc_capabilities(&self) -> u32 {
        u32::from_be_bytes(self.caps[8..12].try_into().unwrap())
    }

    pub fn caliptra_rom_capabilities(&self) -> u32 {
        u32::from_be_bytes(self.caps[12..16].try_into().unwrap())
    }

    pub fn mcu_rom_capabilities(&self) -> u32 {
        u32::from_be_bytes(self.caps[16..20].try_into().unwrap())
    }

    pub fn mcu_runtime_capabilities(&self) -> u32 {
        u32::from_be_bytes(self.caps[20..24].try_into().unwrap())
    }

    pub fn external_command_capabilities(&self) -> u32 {
        u32::from_be_bytes(self.caps[24..28].try_into().unwrap())
    }

    pub fn authorized_subcommand_capabilities(&self) -> u32 {
        u32::from_be_bytes(self.caps[28..32].try_into().unwrap())
    }

    pub fn reserved_capabilities(&self) -> &[u8; 16] {
        self.caps[32..48].try_into().unwrap()
    }

    pub fn vendor_capabilities(&self) -> &[u8; 16] {
        self.caps[48..64].try_into().unwrap()
    }
}

impl CommandRequest for GetDeviceCapabilitiesRequest {
    type Response = GetDeviceCapabilitiesResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::GetDeviceCapabilities;
}

impl CommandResponse for GetDeviceCapabilitiesResponse {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_capability_accessors_use_big_endian_component_fields() {
        let mut caps = [0u8; DEVICE_CAPABILITIES_SIZE];
        caps[0..8].copy_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
        caps[8..12].copy_from_slice(&0x1112_1314u32.to_be_bytes());
        caps[12..16].copy_from_slice(&0x2122_2324u32.to_be_bytes());
        caps[16..20].copy_from_slice(&0x3132_3334u32.to_be_bytes());
        caps[20..24].copy_from_slice(&0x0000_00FFu32.to_be_bytes());
        caps[24..28].copy_from_slice(&0x0002_00EFu32.to_be_bytes());
        caps[28..32].copy_from_slice(&0x0000_0009u32.to_be_bytes());
        caps[32..48].copy_from_slice(&[0xA5; 16]);
        caps[48..64].copy_from_slice(&[0x5A; 16]);
        let response = GetDeviceCapabilitiesResponse {
            common: CommonResponse { fips_status: 0 },
            caps,
        };

        assert_eq!(
            response.caliptra_runtime_capabilities(),
            0x0102_0304_0506_0708
        );
        assert_eq!(response.caliptra_fmc_capabilities(), 0x1112_1314);
        assert_eq!(response.caliptra_rom_capabilities(), 0x2122_2324);
        assert_eq!(response.mcu_runtime_capabilities(), 0x0000_00FF);
        assert_eq!(response.mcu_rom_capabilities(), 0x3132_3334);
        assert_eq!(response.external_command_capabilities(), 0x0002_00EF);
        assert_eq!(response.authorized_subcommand_capabilities(), 0x0000_0009);
        assert_eq!(response.reserved_capabilities(), &[0xA5; 16]);
        assert_eq!(response.vendor_capabilities(), &[0x5A; 16]);
    }
}
