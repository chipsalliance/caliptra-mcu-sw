// Licensed under the Apache-2.0 license

//! Get Debug Log command (0x03)
//!
//! Drains entries from the MCU debug log.

use crate::codec::{VdmCodec, VdmCodecError};
use crate::protocol::{VdmCommand, VdmMsgHeader};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Maximum size of log data carried in a single VDM response.
pub const MAX_LOG_DATA_SIZE: usize = 900;

/// Get Debug Log Request — header only.
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct GetDebugLogRequest {
    /// VDM message header.
    pub hdr: VdmMsgHeader,
}

impl GetDebugLogRequest {
    /// Create a new Get Debug Log request.
    pub fn new() -> Self {
        Self {
            hdr: VdmMsgHeader::new_request(VdmCommand::GetDebugLog.into()),
        }
    }
}

impl Default for GetDebugLogRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// Get Debug Log Response (fixed header part).
///
/// Response Payload:
/// - Bytes 0:3 - completion_code (u32)
/// - Bytes 4:7 - more_data (u32) — 1 if more entries remain, else 0
/// - Bytes 8:11 - data_size (u32) — size of `data` in bytes
/// - Bytes 12:N - data (u8[data_size]) — concatenated complete log entries
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct GetDebugLogResponseHeader {
    /// VDM message header.
    pub hdr: VdmMsgHeader,
    /// Command completion status.
    pub completion_code: u32,
    /// Non-zero if more log entries remain to be drained.
    pub more_data: u32,
    /// Size of the data buffer in bytes.
    pub data_size: u32,
}

impl GetDebugLogResponseHeader {
    pub fn new(completion_code: u32, more_data: u32, data_size: u32) -> Self {
        Self {
            hdr: VdmMsgHeader::new_response(VdmCommand::GetDebugLog.into()),
            completion_code,
            more_data,
            data_size,
        }
    }
}

impl Default for GetDebugLogResponseHeader {
    fn default() -> Self {
        Self {
            hdr: VdmMsgHeader::new_response(VdmCommand::GetDebugLog.into()),
            completion_code: 0,
            more_data: 0,
            data_size: 0,
        }
    }
}

/// Get Debug Log Response with variable-length data.
#[derive(Debug, Clone, PartialEq)]
pub struct GetDebugLogResponse {
    pub header: GetDebugLogResponseHeader,
    pub data: [u8; MAX_LOG_DATA_SIZE],
}

impl GetDebugLogResponse {
    pub fn new(completion_code: u32, more_data: bool, data: &[u8]) -> Self {
        let data_size = data.len().min(MAX_LOG_DATA_SIZE);
        let mut response_data = [0u8; MAX_LOG_DATA_SIZE];
        response_data[..data_size].copy_from_slice(&data[..data_size]);

        Self {
            header: GetDebugLogResponseHeader::new(
                completion_code,
                if more_data { 1 } else { 0 },
                data_size as u32,
            ),
            data: response_data,
        }
    }

    pub fn data_size(&self) -> usize {
        self.header.data_size as usize
    }

    pub fn more_data(&self) -> bool {
        self.header.more_data != 0
    }

    pub fn data(&self) -> &[u8] {
        let size = self.data_size().min(MAX_LOG_DATA_SIZE);
        &self.data[..size]
    }
}

impl Default for GetDebugLogResponse {
    fn default() -> Self {
        Self {
            header: GetDebugLogResponseHeader::default(),
            data: [0u8; MAX_LOG_DATA_SIZE],
        }
    }
}

impl VdmCodec for GetDebugLogResponse {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, VdmCodecError> {
        let header_size = core::mem::size_of::<GetDebugLogResponseHeader>();
        let data_size = self.data_size();
        let total_size = header_size + data_size;

        if buffer.len() < total_size {
            return Err(VdmCodecError::BufferTooShort);
        }

        self.header.encode(buffer)?;
        buffer[header_size..total_size].copy_from_slice(&self.data[..data_size]);
        Ok(total_size)
    }

    fn decode(buffer: &[u8]) -> Result<Self, VdmCodecError> {
        let header_size = core::mem::size_of::<GetDebugLogResponseHeader>();
        if buffer.len() < header_size {
            return Err(VdmCodecError::BufferTooShort);
        }

        let header = GetDebugLogResponseHeader::decode(buffer)?;
        let data_size = (header.data_size as usize).min(MAX_LOG_DATA_SIZE);

        if buffer.len() < header_size + data_size {
            return Err(VdmCodecError::BufferTooShort);
        }

        let mut data = [0u8; MAX_LOG_DATA_SIZE];
        data[..data_size].copy_from_slice(&buffer[header_size..header_size + data_size]);
        Ok(Self { header, data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{VdmCompletionCode, VDM_MSG_HEADER_LEN};

    #[test]
    fn test_request_roundtrip() {
        let req = GetDebugLogRequest::new();
        assert!(req.hdr.is_request());
        let cmd = req.hdr.command_code;
        assert_eq!(cmd, VdmCommand::GetDebugLog as u8);

        let mut buf = [0u8; 16];
        let n = req.encode(&mut buf).unwrap();
        assert_eq!(n, VDM_MSG_HEADER_LEN);

        let decoded = GetDebugLogRequest::decode(&buf).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_response_roundtrip() {
        let payload = [0x10u8, 0x11, 0x12, 0x13];
        let resp = GetDebugLogResponse::new(VdmCompletionCode::Success as u32, true, &payload);
        assert!(resp.header.hdr.is_response());
        assert_eq!(resp.data_size(), payload.len());
        assert!(resp.more_data());
        assert_eq!(resp.data(), &payload);

        let mut buf = [0u8; 1024];
        let n = resp.encode(&mut buf).unwrap();
        assert_eq!(
            n,
            core::mem::size_of::<GetDebugLogResponseHeader>() + payload.len()
        );

        let decoded = GetDebugLogResponse::decode(&buf).unwrap();
        assert_eq!(resp.header, decoded.header);
        assert_eq!(resp.data(), decoded.data());
    }

    #[test]
    fn test_response_empty() {
        let resp = GetDebugLogResponse::new(VdmCompletionCode::Success as u32, false, &[]);
        assert_eq!(resp.data_size(), 0);
        assert!(!resp.more_data());
        assert_eq!(resp.data(), &[]);
    }
}
