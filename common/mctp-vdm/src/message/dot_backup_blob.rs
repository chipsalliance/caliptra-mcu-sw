// Licensed under the Apache-2.0 license

//! Get DOT Backup Blob command.
//!
//! Returns a copy of the current Device Ownership Transfer (DOT) blob so a
//! platform/BMC can keep an out-of-band backup for DOT_RECOVERY.

use crate::codec::{VdmCodec, VdmCodecError};
use crate::protocol::{VdmCommand, VdmMsgHeader};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Size of the DOT_BLOB authenticated by the ROM DOT flow.
pub const DOT_BLOB_SIZE: usize = 168;

/// Get DOT Backup Blob Request.
///
/// No additional fields beyond the Caliptra VDM header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct GetDotBackupBlobRequest {
    pub hdr: VdmMsgHeader,
}

impl GetDotBackupBlobRequest {
    pub fn new() -> Self {
        Self {
            hdr: VdmMsgHeader::new_request(VdmCommand::GetDotBackupBlob.into()),
        }
    }
}

impl Default for GetDotBackupBlobRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// Get DOT Backup Blob Response header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct GetDotBackupBlobResponseHeader {
    pub hdr: VdmMsgHeader,
    pub completion_code: u32,
}

impl GetDotBackupBlobResponseHeader {
    pub fn new(completion_code: u32) -> Self {
        Self {
            hdr: VdmMsgHeader::new_response(VdmCommand::GetDotBackupBlob.into()),
            completion_code,
        }
    }
}

impl Default for GetDotBackupBlobResponseHeader {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Get DOT Backup Blob Response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetDotBackupBlobResponse {
    pub header: GetDotBackupBlobResponseHeader,
    pub blob: [u8; DOT_BLOB_SIZE],
}

impl GetDotBackupBlobResponse {
    pub fn new(completion_code: u32, blob: &[u8; DOT_BLOB_SIZE]) -> Self {
        Self {
            header: GetDotBackupBlobResponseHeader::new(completion_code),
            blob: *blob,
        }
    }

    pub fn error(completion_code: u32) -> Self {
        Self {
            header: GetDotBackupBlobResponseHeader::new(completion_code),
            blob: [0u8; DOT_BLOB_SIZE],
        }
    }
}

impl Default for GetDotBackupBlobResponse {
    fn default() -> Self {
        Self::error(0)
    }
}

impl VdmCodec for GetDotBackupBlobResponse {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, VdmCodecError> {
        let header_size = core::mem::size_of::<GetDotBackupBlobResponseHeader>();
        let total_size = header_size + DOT_BLOB_SIZE;

        if buffer.len() < total_size {
            return Err(VdmCodecError::BufferTooShort);
        }

        self.header.encode(buffer)?;
        buffer[header_size..total_size].copy_from_slice(&self.blob);

        Ok(total_size)
    }

    fn decode(buffer: &[u8]) -> Result<Self, VdmCodecError> {
        let header_size = core::mem::size_of::<GetDotBackupBlobResponseHeader>();
        let total_size = header_size + DOT_BLOB_SIZE;

        if buffer.len() < total_size {
            return Err(VdmCodecError::BufferTooShort);
        }

        let header = GetDotBackupBlobResponseHeader::decode(buffer)?;
        let mut blob = [0u8; DOT_BLOB_SIZE];
        blob.copy_from_slice(&buffer[header_size..total_size]);

        Ok(Self { header, blob })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{VdmCompletionCode, VDM_MSG_HEADER_LEN};

    #[test]
    fn get_dot_backup_blob_request_round_trips() {
        let req = GetDotBackupBlobRequest::new();
        assert!(req.hdr.is_request());
        let command_code = req.hdr.command_code;
        assert_eq!(command_code, VdmCommand::GetDotBackupBlob as u8);

        let mut buffer = [0u8; 64];
        let size = req.encode(&mut buffer).unwrap();
        assert_eq!(size, VDM_MSG_HEADER_LEN);

        let decoded = GetDotBackupBlobRequest::decode(&buffer).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn get_dot_backup_blob_response_round_trips() {
        let mut test_blob = [0u8; DOT_BLOB_SIZE];
        for (i, b) in test_blob.iter_mut().enumerate() {
            *b = (i & 0xff) as u8;
        }

        let resp = GetDotBackupBlobResponse::new(VdmCompletionCode::Success as u32, &test_blob);
        assert!(resp.header.hdr.is_response());
        let completion_code = resp.header.completion_code;
        assert_eq!(completion_code, VdmCompletionCode::Success as u32);
        assert_eq!(resp.blob, test_blob);

        let mut buffer = [0u8; 256];
        let size = resp.encode(&mut buffer).unwrap();
        let header_size = core::mem::size_of::<GetDotBackupBlobResponseHeader>();
        assert_eq!(size, header_size + DOT_BLOB_SIZE);

        let decoded = GetDotBackupBlobResponse::decode(&buffer).unwrap();
        assert_eq!(resp, decoded);
    }

    #[test]
    fn get_dot_backup_blob_error_response_zeroes_blob() {
        let resp = GetDotBackupBlobResponse::error(VdmCompletionCode::GeneralError as u32);
        let completion_code = resp.header.completion_code;
        assert_eq!(completion_code, VdmCompletionCode::GeneralError as u32);
        assert_eq!(resp.blob, [0u8; DOT_BLOB_SIZE]);
    }
}
