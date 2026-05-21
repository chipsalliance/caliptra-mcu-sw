// Licensed under the Apache-2.0 license

//! Get Attestation Log command (0x07)
//!
//! Drains entries from the Caliptra attestation log.

use crate::codec::{VdmCodec, VdmCodecError};
use crate::message::get_debug_log::MAX_LOG_DATA_SIZE;
use crate::protocol::{VdmCommand, VdmMsgHeader};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Get Attestation Log Request — header only.
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct GetAttestationLogRequest {
    pub hdr: VdmMsgHeader,
}

impl GetAttestationLogRequest {
    pub fn new() -> Self {
        Self {
            hdr: VdmMsgHeader::new_request(VdmCommand::GetAttestationLog.into()),
        }
    }
}

impl Default for GetAttestationLogRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// Get Attestation Log Response (fixed header part).
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct GetAttestationLogResponseHeader {
    pub hdr: VdmMsgHeader,
    pub completion_code: u32,
    pub more_data: u32,
    pub data_size: u32,
}

impl GetAttestationLogResponseHeader {
    pub fn new(completion_code: u32, more_data: u32, data_size: u32) -> Self {
        Self {
            hdr: VdmMsgHeader::new_response(VdmCommand::GetAttestationLog.into()),
            completion_code,
            more_data,
            data_size,
        }
    }
}

impl Default for GetAttestationLogResponseHeader {
    fn default() -> Self {
        Self {
            hdr: VdmMsgHeader::new_response(VdmCommand::GetAttestationLog.into()),
            completion_code: 0,
            more_data: 0,
            data_size: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetAttestationLogResponse {
    pub header: GetAttestationLogResponseHeader,
    pub data: [u8; MAX_LOG_DATA_SIZE],
}

impl GetAttestationLogResponse {
    pub fn new(completion_code: u32, more_data: bool, data: &[u8]) -> Self {
        let data_size = data.len().min(MAX_LOG_DATA_SIZE);
        let mut response_data = [0u8; MAX_LOG_DATA_SIZE];
        response_data[..data_size].copy_from_slice(&data[..data_size]);

        Self {
            header: GetAttestationLogResponseHeader::new(
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

impl Default for GetAttestationLogResponse {
    fn default() -> Self {
        Self {
            header: GetAttestationLogResponseHeader::default(),
            data: [0u8; MAX_LOG_DATA_SIZE],
        }
    }
}

impl VdmCodec for GetAttestationLogResponse {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, VdmCodecError> {
        let header_size = core::mem::size_of::<GetAttestationLogResponseHeader>();
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
        let header_size = core::mem::size_of::<GetAttestationLogResponseHeader>();
        if buffer.len() < header_size {
            return Err(VdmCodecError::BufferTooShort);
        }

        let header = GetAttestationLogResponseHeader::decode(buffer)?;
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
        let req = GetAttestationLogRequest::new();
        assert!(req.hdr.is_request());
        let cmd = req.hdr.command_code;
        assert_eq!(cmd, VdmCommand::GetAttestationLog as u8);

        let mut buf = [0u8; 16];
        let n = req.encode(&mut buf).unwrap();
        assert_eq!(n, VDM_MSG_HEADER_LEN);

        let decoded = GetAttestationLogRequest::decode(&buf).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_response_roundtrip() {
        let payload = [0xAAu8, 0xBB, 0xCC];
        let resp =
            GetAttestationLogResponse::new(VdmCompletionCode::Success as u32, false, &payload);
        assert!(resp.header.hdr.is_response());
        assert_eq!(resp.data_size(), payload.len());
        assert!(!resp.more_data());

        let mut buf = [0u8; 1024];
        let n = resp.encode(&mut buf).unwrap();
        assert_eq!(
            n,
            core::mem::size_of::<GetAttestationLogResponseHeader>() + payload.len()
        );

        let decoded = GetAttestationLogResponse::decode(&buf).unwrap();
        assert_eq!(resp.header, decoded.header);
        assert_eq!(resp.data(), decoded.data());
    }
}
