// Licensed under the Apache-2.0 license

//! Device Capabilities command (0x02)
//!
//! Retrieves device capabilities.

use crate::protocol::{VdmCommand, VdmMsgHeader};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Size of device capabilities data.
pub const DEVICE_CAPS_SIZE: usize = 32;

/// Device Capabilities Request.
///
/// Request Payload: Empty (only header)
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct DeviceCapabilitiesRequest {
    /// VDM message header.
    pub hdr: VdmMsgHeader,
}

impl DeviceCapabilitiesRequest {
    /// Create a new Device Capabilities request.
    pub fn new() -> Self {
        DeviceCapabilitiesRequest {
            hdr: VdmMsgHeader::new_request(VdmCommand::DeviceCapabilities.into()),
        }
    }
}

impl Default for DeviceCapabilitiesRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// Device Capabilities Response.
///
/// Response Payload:
/// - Bytes 0:3 - completion_code (u32): Command completion status
/// - Bytes 4:35 - caps (u8[32]): Device Capabilities
///   - Bytes [0:7]: Reserved for Caliptra RT
///   - Bytes [8:11]: Reserved for Caliptra FMC
///   - Bytes [12:15]: Reserved for Caliptra ROM
///   - Bytes [16:23]: Reserved for MCU RT
///   - Bytes [24:27]: Reserved for MCU ROM
///   - Bytes [28:31]: Reserved
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct DeviceCapabilitiesResponse {
    /// VDM message header.
    pub hdr: VdmMsgHeader,
    /// Command completion status.
    pub completion_code: u32,
    /// Device capabilities (32 bytes).
    pub caps: [u8; DEVICE_CAPS_SIZE],
}

impl DeviceCapabilitiesResponse {
    /// Create a new successful Device Capabilities response.
    pub fn new(completion_code: u32, caps: &[u8; DEVICE_CAPS_SIZE]) -> Self {
        DeviceCapabilitiesResponse {
            hdr: VdmMsgHeader::new_response(VdmCommand::DeviceCapabilities.into()),
            completion_code,
            caps: *caps,
        }
    }
}

impl Default for DeviceCapabilitiesResponse {
    fn default() -> Self {
        DeviceCapabilitiesResponse {
            hdr: VdmMsgHeader::new_response(VdmCommand::DeviceCapabilities.into()),
            completion_code: 0,
            caps: [0u8; DEVICE_CAPS_SIZE],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::VdmCodec;
    use crate::protocol::{VdmCompletionCode, VDM_MSG_HEADER_LEN};

    #[test]
    fn test_device_capabilities_request() {
        let req = DeviceCapabilitiesRequest::new();
        assert!(req.hdr.is_request());
        let command_code = req.hdr.command_code;
        assert_eq!(command_code, VdmCommand::DeviceCapabilities as u8);

        let mut buffer = [0u8; 64];
        let size = req.encode(&mut buffer).unwrap();
        assert_eq!(size, VDM_MSG_HEADER_LEN);

        let decoded = DeviceCapabilitiesRequest::decode(&buffer).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_device_capabilities_response() {
        let mut caps = [0u8; DEVICE_CAPS_SIZE];
        caps[0] = 0x01;
        caps[16] = 0x02;

        let resp = DeviceCapabilitiesResponse::new(VdmCompletionCode::Success as u32, &caps);
        assert!(resp.hdr.is_response());
        let completion_code = resp.completion_code;
        assert_eq!(completion_code, 0);
        let resp_caps = resp.caps;
        assert_eq!(resp_caps[0], 0x01);
        assert_eq!(resp_caps[16], 0x02);

        let mut buffer = [0u8; 64];
        let size = resp.encode(&mut buffer).unwrap();
        assert_eq!(size, VDM_MSG_HEADER_LEN + 4 + DEVICE_CAPS_SIZE);

        let decoded = DeviceCapabilitiesResponse::decode(&buffer).unwrap();
        assert_eq!(resp, decoded);
    }
}
