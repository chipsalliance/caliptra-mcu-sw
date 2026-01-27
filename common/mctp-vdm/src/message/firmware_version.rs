// Licensed under the Apache-2.0 license

//! Firmware Version command (0x01)
//!
//! Retrieves the version of the target firmware.

use crate::protocol::{VdmCommand, VdmMsgHeader};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Maximum length of firmware version string.
pub const MAX_FW_VERSION_LEN: usize = 32;

/// Firmware Version Request.
///
/// Request Payload:
/// - Bytes 0:3 - area_index (u32): Area Index
///   - 0x00 = Caliptra core firmware
///   - 0x01 = MCU runtime firmware
///   - 0x02 = SoC firmware
///   - Additional indexes are firmware-specific
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct FirmwareVersionRequest {
    /// VDM message header.
    pub hdr: VdmMsgHeader,
    /// Area index specifying which firmware version to retrieve.
    pub area_index: u32,
}

impl FirmwareVersionRequest {
    /// Create a new Firmware Version request.
    pub fn new(area_index: u32) -> Self {
        FirmwareVersionRequest {
            hdr: VdmMsgHeader::new_request(VdmCommand::FirmwareVersion.into()),
            area_index,
        }
    }
}

impl Default for FirmwareVersionRequest {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Firmware Version Response.
///
/// Response Payload:
/// - Bytes 0:3 - completion_code (u32): Command completion status
/// - Bytes 4:35 - version (u8[32]): Firmware Version Number in ASCII format
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct FirmwareVersionResponse {
    /// VDM message header.
    pub hdr: VdmMsgHeader,
    /// Command completion status.
    pub completion_code: u32,
    /// Firmware version number in ASCII format.
    pub version: [u8; MAX_FW_VERSION_LEN],
}

impl FirmwareVersionResponse {
    /// Create a new successful Firmware Version response.
    pub fn new(completion_code: u32, version: &[u8]) -> Self {
        let mut ver = [0u8; MAX_FW_VERSION_LEN];
        let len = version.len().min(MAX_FW_VERSION_LEN);
        ver[..len].copy_from_slice(&version[..len]);

        FirmwareVersionResponse {
            hdr: VdmMsgHeader::new_response(VdmCommand::FirmwareVersion.into()),
            completion_code,
            version: ver,
        }
    }
}

impl Default for FirmwareVersionResponse {
    fn default() -> Self {
        FirmwareVersionResponse {
            hdr: VdmMsgHeader::new_response(VdmCommand::FirmwareVersion.into()),
            completion_code: 0,
            version: [0u8; MAX_FW_VERSION_LEN],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::VdmCodec;
    use crate::protocol::{VdmCompletionCode, VDM_MSG_HEADER_LEN};

    #[test]
    fn test_firmware_version_request() {
        let req = FirmwareVersionRequest::new(1);
        assert!(req.hdr.is_request());
        let command_code = req.hdr.command_code;
        let area_index = req.area_index;
        assert_eq!(command_code, VdmCommand::FirmwareVersion as u8);
        assert_eq!(area_index, 1);

        let mut buffer = [0u8; 64];
        let size = req.encode(&mut buffer).unwrap();
        assert_eq!(size, VDM_MSG_HEADER_LEN + 4);

        let decoded = FirmwareVersionRequest::decode(&buffer).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_firmware_version_response() {
        let version = b"1.0.0-release";
        let resp = FirmwareVersionResponse::new(VdmCompletionCode::Success as u32, version);
        assert!(resp.hdr.is_response());
        let completion_code = resp.completion_code;
        let resp_version = resp.version;
        assert_eq!(completion_code, 0);
        assert_eq!(&resp_version[..version.len()], version);

        let mut buffer = [0u8; 64];
        let size = resp.encode(&mut buffer).unwrap();
        assert_eq!(size, VDM_MSG_HEADER_LEN + 4 + MAX_FW_VERSION_LEN);

        let decoded = FirmwareVersionResponse::decode(&buffer).unwrap();
        assert_eq!(resp, decoded);
    }
}
