// Licensed under the Apache-2.0 license

//! Get Log command (0x08)
//!
//! Retrieves log entries from the target device.

use crate::codec::{VdmCodec, VdmCodecError};
use crate::protocol::{VdmCommand, VdmMsgHeader};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Maximum size of log data in a VDM response.
pub const MAX_LOG_DATA_SIZE: usize = 900;

/// Get Log Request.
///
/// Request Payload:
/// - Bytes 0:3 - log_type (u32): Type of log to retrieve
///   - 0x00 = Debug Log
///   - 0x01 = Attestation Log
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct GetLogRequest {
    /// VDM message header.
    pub hdr: VdmMsgHeader,
    /// Type of log to retrieve.
    pub log_type: u32,
}

impl GetLogRequest {
    /// Create a new Get Log request.
    pub fn new(log_type: u32) -> Self {
        GetLogRequest {
            hdr: VdmMsgHeader::new_request(VdmCommand::GetLog.into()),
            log_type,
        }
    }
}

impl Default for GetLogRequest {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Get Log Response (fixed header part).
///
/// Response Payload:
/// - Bytes 0:3 - completion_code (u32): Command completion status
/// - Bytes 4:7 - data_size (u32): Size of the log data in bytes
/// - Bytes 8:N - data (u8[data_size]): Log entries
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct GetLogResponseHeader {
    /// VDM message header.
    pub hdr: VdmMsgHeader,
    /// Command completion status.
    pub completion_code: u32,
    /// Size of the log data in bytes.
    pub data_size: u32,
}

impl GetLogResponseHeader {
    /// Create a new Get Log response header.
    pub fn new(completion_code: u32, data_size: u32) -> Self {
        GetLogResponseHeader {
            hdr: VdmMsgHeader::new_response(VdmCommand::GetLog.into()),
            completion_code,
            data_size,
        }
    }
}

impl Default for GetLogResponseHeader {
    fn default() -> Self {
        GetLogResponseHeader {
            hdr: VdmMsgHeader::new_response(VdmCommand::GetLog.into()),
            completion_code: 0,
            data_size: 0,
        }
    }
}

/// Get Log Response with variable-length data.
#[derive(Debug, Clone, PartialEq)]
pub struct GetLogResponse {
    /// Response header.
    pub header: GetLogResponseHeader,
    /// Data buffer.
    pub data: [u8; MAX_LOG_DATA_SIZE],
}

impl GetLogResponse {
    /// Create a new Get Log response.
    pub fn new(completion_code: u32, data: &[u8]) -> Self {
        let data_size = data.len().min(MAX_LOG_DATA_SIZE);
        let mut response_data = [0u8; MAX_LOG_DATA_SIZE];
        response_data[..data_size].copy_from_slice(&data[..data_size]);

        GetLogResponse {
            header: GetLogResponseHeader::new(completion_code, data_size as u32),
            data: response_data,
        }
    }

    /// Get the actual data size.
    pub fn data_size(&self) -> usize {
        self.header.data_size as usize
    }

    /// Get a slice of the actual data.
    pub fn data(&self) -> &[u8] {
        let size = self.data_size().min(MAX_LOG_DATA_SIZE);
        &self.data[..size]
    }
}

impl Default for GetLogResponse {
    fn default() -> Self {
        GetLogResponse {
            header: GetLogResponseHeader::default(),
            data: [0u8; MAX_LOG_DATA_SIZE],
        }
    }
}

impl VdmCodec for GetLogResponse {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, VdmCodecError> {
        let header_size = core::mem::size_of::<GetLogResponseHeader>();
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
        let header_size = core::mem::size_of::<GetLogResponseHeader>();

        if buffer.len() < header_size {
            return Err(VdmCodecError::BufferTooShort);
        }

        let header = GetLogResponseHeader::decode(buffer)?;
        let data_size = (header.data_size as usize).min(MAX_LOG_DATA_SIZE);

        if buffer.len() < header_size + data_size {
            return Err(VdmCodecError::BufferTooShort);
        }

        let mut data = [0u8; MAX_LOG_DATA_SIZE];
        data[..data_size].copy_from_slice(&buffer[header_size..header_size + data_size]);

        Ok(GetLogResponse { header, data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{VdmCompletionCode, VDM_MSG_HEADER_LEN};

    #[test]
    fn test_get_log_request() {
        let req = GetLogRequest::new(0);
        assert!(req.hdr.is_request());
        let command_code = req.hdr.command_code;
        let log_type = req.log_type;
        assert_eq!(command_code, VdmCommand::GetLog as u8);
        assert_eq!(log_type, 0);

        let mut buffer = [0u8; 64];
        let size = req.encode(&mut buffer).unwrap();
        assert_eq!(size, VDM_MSG_HEADER_LEN + 4);

        let decoded = GetLogRequest::decode(&buffer).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_get_log_response() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let resp = GetLogResponse::new(VdmCompletionCode::Success as u32, &data);
        assert!(resp.header.hdr.is_response());
        let completion_code = resp.header.completion_code;
        let data_size_val = resp.header.data_size;
        assert_eq!(completion_code, 0);
        assert_eq!(data_size_val, 8);
        assert_eq!(resp.data(), &data);

        let mut buffer = [0u8; 1024];
        let size = resp.encode(&mut buffer).unwrap();
        let header_size = core::mem::size_of::<GetLogResponseHeader>();
        assert_eq!(size, header_size + 8);

        let decoded = GetLogResponse::decode(&buffer).unwrap();
        assert_eq!(resp.header, decoded.header);
        assert_eq!(resp.data(), decoded.data());
    }

    #[test]
    fn test_get_log_response_empty() {
        let resp = GetLogResponse::new(VdmCompletionCode::Success as u32, &[]);
        assert_eq!(resp.data_size(), 0);
        assert_eq!(resp.data(), &[]);
    }
}
