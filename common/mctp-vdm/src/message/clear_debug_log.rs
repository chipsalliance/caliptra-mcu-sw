// Licensed under the Apache-2.0 license

use crate::protocol::{VdmCommand, VdmMsgHeader};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Clear Debug Log Request — header only.
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct ClearDebugLogRequest {
    pub hdr: VdmMsgHeader,
}

impl ClearDebugLogRequest {
    pub fn new() -> Self {
        Self {
            hdr: VdmMsgHeader::new_request(VdmCommand::ClearDebugLog.into()),
        }
    }
}

impl Default for ClearDebugLogRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// Clear Debug Log Response.
///
/// Response Payload:
/// - Bytes 0:3 - completion_code (u32)
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct ClearDebugLogResponse {
    pub hdr: VdmMsgHeader,
    pub completion_code: u32,
}

impl ClearDebugLogResponse {
    pub fn new(completion_code: u32) -> Self {
        Self {
            hdr: VdmMsgHeader::new_response(VdmCommand::ClearDebugLog.into()),
            completion_code,
        }
    }
}

impl Default for ClearDebugLogResponse {
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::VdmCodec;
    use crate::protocol::{VdmCompletionCode, VDM_MSG_HEADER_LEN};

    #[test]
    fn test_request_roundtrip() {
        let req = ClearDebugLogRequest::new();
        assert!(req.hdr.is_request());
        let cmd = req.hdr.command_code;
        assert_eq!(cmd, VdmCommand::ClearDebugLog as u8);

        let mut buf = [0u8; 16];
        let n = req.encode(&mut buf).unwrap();
        assert_eq!(n, VDM_MSG_HEADER_LEN);

        let decoded = ClearDebugLogRequest::decode(&buf).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_response_roundtrip() {
        let resp = ClearDebugLogResponse::new(VdmCompletionCode::Success as u32);
        assert!(resp.hdr.is_response());
        let cc = resp.completion_code;
        assert_eq!(cc, VdmCompletionCode::Success as u32);

        let mut buf = [0u8; 64];
        let n = resp.encode(&mut buf).unwrap();
        assert_eq!(n, VDM_MSG_HEADER_LEN + 4);

        let decoded = ClearDebugLogResponse::decode(&buf).unwrap();
        assert_eq!(resp, decoded);
    }
}
