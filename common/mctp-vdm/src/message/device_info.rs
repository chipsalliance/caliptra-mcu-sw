// Licensed under the Apache-2.0 license

//! Device Information command (0x04)
//!
//! Retrieves information about the target device.

use crate::codec::{VdmCodec, VdmCodecError};
use crate::protocol::{VdmCommand, VdmMsgHeader};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Maximum size of device information data.
pub const MAX_DEVICE_INFO_SIZE: usize = 64;

/// Device Information index values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DeviceInfoIndex {
    /// Unique Chip Identifier.
    UniqueChipId = 0x00,
}

/// Device Information Request.
///
/// Request Payload:
/// - Bytes 0:3 - info_index (u32): Information Index
///   - 0x00 = Unique Chip Identifier
///   - Additional indexes are firmware-specific
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct DeviceInfoRequest {
    /// VDM message header.
    pub hdr: VdmMsgHeader,
    /// Information index specifying which device info to retrieve.
    pub info_index: u32,
}

impl DeviceInfoRequest {
    /// Create a new Device Information request.
    pub fn new(info_index: u32) -> Self {
        DeviceInfoRequest {
            hdr: VdmMsgHeader::new_request(VdmCommand::DeviceInfo.into()),
            info_index,
        }
    }
}

impl Default for DeviceInfoRequest {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Device Information Response (fixed header part).
///
/// Response Payload:
/// - Bytes 0:3 - completion_code (u32): Command completion status
/// - Bytes 4:7 - data_size (u32): Size of the requested data in bytes
/// - Bytes 8:N - data (u8[data_size]): Requested information in binary format
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct DeviceInfoResponseHeader {
    /// VDM message header.
    pub hdr: VdmMsgHeader,
    /// Command completion status.
    pub completion_code: u32,
    /// Size of the data in bytes.
    pub data_size: u32,
}

impl DeviceInfoResponseHeader {
    /// Create a new Device Information response header.
    pub fn new(completion_code: u32, data_size: u32) -> Self {
        DeviceInfoResponseHeader {
            hdr: VdmMsgHeader::new_response(VdmCommand::DeviceInfo.into()),
            completion_code,
            data_size,
        }
    }
}

impl Default for DeviceInfoResponseHeader {
    fn default() -> Self {
        DeviceInfoResponseHeader {
            hdr: VdmMsgHeader::new_response(VdmCommand::DeviceInfo.into()),
            completion_code: 0,
            data_size: 0,
        }
    }
}

/// Device Information Response with variable-length data.
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceInfoResponse {
    /// Response header.
    pub header: DeviceInfoResponseHeader,
    /// Data buffer.
    pub data: [u8; MAX_DEVICE_INFO_SIZE],
}

impl DeviceInfoResponse {
    /// Create a new Device Information response.
    pub fn new(completion_code: u32, data: &[u8]) -> Self {
        let data_size = data.len().min(MAX_DEVICE_INFO_SIZE);
        let mut response_data = [0u8; MAX_DEVICE_INFO_SIZE];
        response_data[..data_size].copy_from_slice(&data[..data_size]);

        DeviceInfoResponse {
            header: DeviceInfoResponseHeader::new(completion_code, data_size as u32),
            data: response_data,
        }
    }

    /// Get the actual data size.
    pub fn data_size(&self) -> usize {
        self.header.data_size as usize
    }

    /// Get a slice of the actual data.
    pub fn data(&self) -> &[u8] {
        let size = self.data_size().min(MAX_DEVICE_INFO_SIZE);
        &self.data[..size]
    }
}

impl Default for DeviceInfoResponse {
    fn default() -> Self {
        DeviceInfoResponse {
            header: DeviceInfoResponseHeader::default(),
            data: [0u8; MAX_DEVICE_INFO_SIZE],
        }
    }
}

impl VdmCodec for DeviceInfoResponse {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, VdmCodecError> {
        let header_size = core::mem::size_of::<DeviceInfoResponseHeader>();
        let data_size = self.data_size();
        let total_size = header_size + data_size;

        if buffer.len() < total_size {
            return Err(VdmCodecError::BufferTooShort);
        }

        // Encode header
        self.header.encode(buffer)?;

        // Copy data
        buffer[header_size..total_size].copy_from_slice(&self.data[..data_size]);

        Ok(total_size)
    }

    fn decode(buffer: &[u8]) -> Result<Self, VdmCodecError> {
        let header_size = core::mem::size_of::<DeviceInfoResponseHeader>();

        if buffer.len() < header_size {
            return Err(VdmCodecError::BufferTooShort);
        }

        let header = DeviceInfoResponseHeader::decode(buffer)?;
        let data_size = (header.data_size as usize).min(MAX_DEVICE_INFO_SIZE);

        if buffer.len() < header_size + data_size {
            return Err(VdmCodecError::BufferTooShort);
        }

        let mut data = [0u8; MAX_DEVICE_INFO_SIZE];
        data[..data_size].copy_from_slice(&buffer[header_size..header_size + data_size]);

        Ok(DeviceInfoResponse { header, data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{VdmCompletionCode, VDM_MSG_HEADER_LEN};

    #[test]
    fn test_device_info_request() {
        let req = DeviceInfoRequest::new(DeviceInfoIndex::UniqueChipId as u32);
        assert!(req.hdr.is_request());
        let command_code = req.hdr.command_code;
        let info_index = req.info_index;
        assert_eq!(command_code, VdmCommand::DeviceInfo as u8);
        assert_eq!(info_index, 0);

        let mut buffer = [0u8; 64];
        let size = req.encode(&mut buffer).unwrap();
        assert_eq!(size, VDM_MSG_HEADER_LEN + 4);

        let decoded = DeviceInfoRequest::decode(&buffer).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_device_info_response() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let resp = DeviceInfoResponse::new(VdmCompletionCode::Success as u32, &data);
        assert!(resp.header.hdr.is_response());
        let completion_code = resp.header.completion_code;
        let data_size_val = resp.header.data_size;
        assert_eq!(completion_code, 0);
        assert_eq!(data_size_val, 8);
        assert_eq!(resp.data(), &data);

        let mut buffer = [0u8; 128];
        let size = resp.encode(&mut buffer).unwrap();
        let header_size = core::mem::size_of::<DeviceInfoResponseHeader>();
        assert_eq!(size, header_size + 8);

        let decoded = DeviceInfoResponse::decode(&buffer).unwrap();
        assert_eq!(resp.header, decoded.header);
        assert_eq!(resp.data(), decoded.data());
    }

    #[test]
    fn test_device_info_response_empty() {
        let resp = DeviceInfoResponse::new(VdmCompletionCode::Success as u32, &[]);
        assert_eq!(resp.data_size(), 0);
        assert_eq!(resp.data(), &[]);
    }
}
