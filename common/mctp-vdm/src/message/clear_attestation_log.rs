// Licensed under the Apache-2.0 license

use crate::protocol::{VdmCommand, VdmMsgHeader};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Clear Attestation Log Request — header only.
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct ClearAttestationLogRequest {
    pub hdr: VdmMsgHeader,
}

impl ClearAttestationLogRequest {
    pub fn new() -> Self {
        Self {
            hdr: VdmMsgHeader::new_request(VdmCommand::ClearAttestationLog.into()),
        }
    }
}

impl Default for ClearAttestationLogRequest {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct ClearAttestationLogResponse {
    pub hdr: VdmMsgHeader,
    pub completion_code: u32,
}

impl ClearAttestationLogResponse {
    pub fn new(completion_code: u32) -> Self {
        Self {
            hdr: VdmMsgHeader::new_response(VdmCommand::ClearAttestationLog.into()),
            completion_code,
        }
    }
}

impl Default for ClearAttestationLogResponse {
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
        let req = ClearAttestationLogRequest::new();
        assert!(req.hdr.is_request());
        let cmd = req.hdr.command_code;
        assert_eq!(cmd, VdmCommand::ClearAttestationLog as u8);

        let mut buf = [0u8; 16];
        let n = req.encode(&mut buf).unwrap();
        assert_eq!(n, VDM_MSG_HEADER_LEN);

        let decoded = ClearAttestationLogRequest::decode(&buf).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_response_roundtrip() {
        let resp = ClearAttestationLogResponse::new(VdmCompletionCode::Success as u32);
        let mut buf = [0u8; 64];
        let n = resp.encode(&mut buf).unwrap();
        assert_eq!(n, VDM_MSG_HEADER_LEN + 4);

        let decoded = ClearAttestationLogResponse::decode(&buf).unwrap();
        assert_eq!(resp, decoded);
    }
}
