// Licensed under the Apache-2.0 license

use crate::codec::{PldmCodec, PldmCodecError};
use crate::error::PldmError;
use crate::protocol::base::{
    InstanceId, PldmMsgHeader, PldmMsgType, PldmSupportedType, PLDM_MSG_HEADER_LEN,
};
use crate::protocol::firmware_update::FwUpdateCmd;
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VerifyResult {
    VerifySuccess = 0x00,
    VerifyErrorVerificationFailure = 0x01,
    VerifyErrorVersionMismatch = 0x02,
    VerifyFailedFdSecurityChecks = 0x03,
    VerifyErrorImageIncomplete = 0x04,
    VendorDefined,
}

impl TryFrom<u8> for VerifyResult {
    type Error = PldmError;

    fn try_from(value: u8) -> Result<Self, PldmError> {
        match value {
            0x00 => Ok(VerifyResult::VerifySuccess),
            0x01 => Ok(VerifyResult::VerifyErrorVerificationFailure),
            0x02 => Ok(VerifyResult::VerifyErrorVersionMismatch),
            0x03 => Ok(VerifyResult::VerifyFailedFdSecurityChecks),
            0x04 => Ok(VerifyResult::VerifyErrorImageIncomplete),
            0x90..=0xaf => Ok(VerifyResult::VendorDefined),
            _ => Err(PldmError::InvalidVerifyResult),
        }
    }
}

#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, PartialEq)]
#[repr(C, packed)]
pub struct VerifyCompleteRequest {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub verify_result: u8,
}

impl VerifyCompleteRequest {
    pub fn new(
        instance_id: InstanceId,
        msg_type: PldmMsgType,
        verify_result: VerifyResult,
    ) -> Self {
        VerifyCompleteRequest {
            hdr: PldmMsgHeader::new(
                instance_id,
                msg_type,
                PldmSupportedType::FwUpdate,
                FwUpdateCmd::VerifyComplete as u8,
            ),
            verify_result: verify_result as u8,
        }
    }
}

impl PldmCodec for VerifyCompleteRequest {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, PldmCodecError> {
        let bytes = core::mem::size_of::<VerifyCompleteRequest>();
        if buffer.len() < bytes {
            return Err(PldmCodecError::BufferTooShort);
        };
        let offset = 0;
        self.write_to(&mut buffer[offset..offset + bytes]).unwrap();
        Ok(bytes)
    }

    fn decode(buffer: &[u8]) -> Result<Self, PldmCodecError> {
        let bytes = core::mem::size_of::<VerifyCompleteRequest>();
        if buffer.len() < bytes {
            return Err(PldmCodecError::BufferTooShort);
        };
        Ok(VerifyCompleteRequest::read_from_bytes(&buffer[0..bytes]).unwrap())
    }
}

#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, PartialEq)]
#[repr(C, packed)]
pub struct VerifyCompleteResponse {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub completion_code: u8,
}

impl VerifyCompleteResponse {
    pub fn new(instance_id: InstanceId, completion_code: u8) -> VerifyCompleteResponse {
        VerifyCompleteResponse {
            hdr: PldmMsgHeader::new(
                instance_id,
                PldmMsgType::Response,
                PldmSupportedType::FwUpdate,
                FwUpdateCmd::VerifyComplete as u8,
            ),
            completion_code,
        }
    }
}

impl PldmCodec for VerifyCompleteResponse {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, PldmCodecError> {
        let bytes = core::mem::size_of::<VerifyCompleteResponse>();
        if buffer.len() < bytes {
            return Err(PldmCodecError::BufferTooShort);
        }
        let offset = 0;
        self.write_to(&mut buffer[offset..offset + bytes]).unwrap();
        Ok(bytes)
    }

    fn decode(buffer: &[u8]) -> Result<Self, PldmCodecError> {
        let bytes = core::mem::size_of::<VerifyCompleteResponse>();
        if buffer.len() < bytes {
            return Err(PldmCodecError::BufferTooShort);
        }

        let offset = 0;
        Ok(VerifyCompleteResponse::read_from_bytes(&buffer[offset..offset + bytes]).unwrap())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_verify_complete_request() {
        let request =
            VerifyCompleteRequest::new(0x01, PldmMsgType::Request, VerifyResult::VerifySuccess);
        let mut buffer = [0u8; core::mem::size_of::<VerifyCompleteRequest>()];
        request.encode(&mut buffer).unwrap();
        let decoded_request = VerifyCompleteRequest::decode(&buffer).unwrap();
        assert_eq!(request, decoded_request);
    }

    #[test]
    fn test_verify_complete_response() {
        let response = VerifyCompleteResponse::new(0x01, 0x00);
        let mut buffer = [0u8; core::mem::size_of::<VerifyCompleteResponse>()];
        response.encode(&mut buffer).unwrap();
        let decoded_response = VerifyCompleteResponse::decode(&buffer).unwrap();
        assert_eq!(response, decoded_response);
    }
}
