// Licensed under the Apache-2.0 license

//! Clear Log command (0x09)
//!
//! Clears log entries on the target device.

use crate::protocol::{VdmCommand, VdmMsgHeader};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Clear Log Request.
///
/// Request Payload:
/// - Bytes 0:3 - log_type (u32): Type of log to clear
///   - 0x00 = Debug Log
///   - 0x01 = Attestation Log
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct ClearLogRequest {
    /// VDM message header.
    pub hdr: VdmMsgHeader,
    /// Type of log to clear.
    pub log_type: u32,
}

impl ClearLogRequest {
    /// Create a new Clear Log request.
    pub fn new(log_type: u32) -> Self {
        ClearLogRequest {
            hdr: VdmMsgHeader::new_request(VdmCommand::ClearLog.into()),
            log_type,
        }
    }
}

impl Default for ClearLogRequest {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Clear Log Response.
///
/// Response Payload:
/// - Bytes 0:3 - completion_code (u32): Command completion status
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct ClearLogResponse {
    /// VDM message header.
    pub hdr: VdmMsgHeader,
    /// Command completion status.
    pub completion_code: u32,
}

impl ClearLogResponse {
    /// Create a new Clear Log response.
    pub fn new(completion_code: u32) -> Self {
        ClearLogResponse {
            hdr: VdmMsgHeader::new_response(VdmCommand::ClearLog.into()),
            completion_code,
        }
    }
}

impl Default for ClearLogResponse {
    fn default() -> Self {
        ClearLogResponse {
            hdr: VdmMsgHeader::new_response(VdmCommand::ClearLog.into()),
            completion_code: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::VdmCodec;
    use crate::protocol::{VdmCompletionCode, VDM_MSG_HEADER_LEN};

    #[test]
    fn test_clear_log_request() {
        let req = ClearLogRequest::new(0);
        assert!(req.hdr.is_request());
        let command_code = req.hdr.command_code;
        let log_type = req.log_type;
        assert_eq!(command_code, VdmCommand::ClearLog as u8);
        assert_eq!(log_type, 0);

        let mut buffer = [0u8; 64];
        let size = req.encode(&mut buffer).unwrap();
        assert_eq!(size, VDM_MSG_HEADER_LEN + 4);

        let decoded = ClearLogRequest::decode(&buffer).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_clear_log_response() {
        let resp = ClearLogResponse::new(VdmCompletionCode::Success as u32);
        assert!(resp.hdr.is_response());
        let completion_code = resp.completion_code;
        assert_eq!(completion_code, 0);

        let mut buffer = [0u8; 64];
        let size = resp.encode(&mut buffer).unwrap();
        assert_eq!(size, VDM_MSG_HEADER_LEN + 4);

        let decoded = ClearLogResponse::decode(&buffer).unwrap();
        assert_eq!(resp, decoded);
    }
}
