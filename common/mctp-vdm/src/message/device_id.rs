// Licensed under the Apache-2.0 license

//! Device ID command (0x03)
//!
//! Retrieves the device ID. The request contains no additional payload.

use crate::protocol::{VdmCommand, VdmMsgHeader};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Device ID Request.
///
/// Request Payload: Empty (only header)
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct DeviceIdRequest {
    /// VDM message header.
    pub hdr: VdmMsgHeader,
}

impl DeviceIdRequest {
    /// Create a new Device ID request.
    pub fn new() -> Self {
        DeviceIdRequest {
            hdr: VdmMsgHeader::new_request(VdmCommand::DeviceId.into()),
        }
    }
}

impl Default for DeviceIdRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// Device ID Response.
///
/// Response Payload:
/// - Bytes 0:3 - completion_code (u32): Command completion status
/// - Bytes 4:5 - vendor_id (u16): Vendor ID (LSB)
/// - Bytes 6:7 - device_id (u16): Device ID (LSB)
/// - Bytes 8:9 - subsystem_vendor_id (u16): Subsystem Vendor ID (LSB)
/// - Bytes 10:11 - subsystem_id (u16): Subsystem ID (LSB)
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct DeviceIdResponse {
    /// VDM message header.
    pub hdr: VdmMsgHeader,
    /// Command completion status.
    pub completion_code: u32,
    /// Vendor ID (LSB).
    pub vendor_id: u16,
    /// Device ID (LSB).
    pub device_id: u16,
    /// Subsystem Vendor ID (LSB).
    pub subsystem_vendor_id: u16,
    /// Subsystem ID (LSB).
    pub subsystem_id: u16,
}

impl DeviceIdResponse {
    /// Create a new successful Device ID response.
    pub fn new(
        completion_code: u32,
        vendor_id: u16,
        device_id: u16,
        subsystem_vendor_id: u16,
        subsystem_id: u16,
    ) -> Self {
        DeviceIdResponse {
            hdr: VdmMsgHeader::new_response(VdmCommand::DeviceId.into()),
            completion_code,
            vendor_id,
            device_id,
            subsystem_vendor_id,
            subsystem_id,
        }
    }
}

impl Default for DeviceIdResponse {
    fn default() -> Self {
        DeviceIdResponse {
            hdr: VdmMsgHeader::new_response(VdmCommand::DeviceId.into()),
            completion_code: 0,
            vendor_id: 0,
            device_id: 0,
            subsystem_vendor_id: 0,
            subsystem_id: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::VdmCodec;
    use crate::protocol::{VdmCompletionCode, VDM_MSG_HEADER_LEN};

    #[test]
    fn test_device_id_request() {
        let req = DeviceIdRequest::new();
        assert!(req.hdr.is_request());
        let command_code = req.hdr.command_code;
        assert_eq!(command_code, VdmCommand::DeviceId as u8);

        let mut buffer = [0u8; 64];
        let size = req.encode(&mut buffer).unwrap();
        assert_eq!(size, VDM_MSG_HEADER_LEN);

        let decoded = DeviceIdRequest::decode(&buffer).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_device_id_response() {
        let resp = DeviceIdResponse::new(
            VdmCompletionCode::Success as u32,
            0x1414, // vendor_id
            0x0001, // device_id
            0x1234, // subsystem_vendor_id
            0x5678, // subsystem_id
        );
        assert!(resp.hdr.is_response());
        let completion_code = resp.completion_code;
        let vendor_id = resp.vendor_id;
        let device_id = resp.device_id;
        let subsystem_vendor_id = resp.subsystem_vendor_id;
        let subsystem_id = resp.subsystem_id;
        assert_eq!(completion_code, 0);
        assert_eq!(vendor_id, 0x1414);
        assert_eq!(device_id, 0x0001);
        assert_eq!(subsystem_vendor_id, 0x1234);
        assert_eq!(subsystem_id, 0x5678);

        let mut buffer = [0u8; 64];
        let size = resp.encode(&mut buffer).unwrap();
        assert_eq!(size, VDM_MSG_HEADER_LEN + 4 + 8);

        let decoded = DeviceIdResponse::decode(&buffer).unwrap();
        assert_eq!(resp, decoded);
    }
}
