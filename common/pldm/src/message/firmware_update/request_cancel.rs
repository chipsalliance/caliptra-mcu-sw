// Licensed under the Apache-2.0 license

use crate::codec::{PldmCodec, PldmCodecError};
use crate::error::PldmError;
use crate::protocol::base::{
    InstanceId, PldmMsgHeader, PldmMsgType, PldmSupportedType, PLDM_MSG_HEADER_LEN,
};
use crate::protocol::firmware_update::FwUpdateCmd;
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[repr(u8)]
pub enum NonFunctioningComponentIndication {
    ComponentsFunctioning = 0,
    ComponentsNotFunctioning = 1,
}

impl TryFrom<u8> for NonFunctioningComponentIndication {
    type Error = PldmError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(NonFunctioningComponentIndication::ComponentsFunctioning),
            1 => Ok(NonFunctioningComponentIndication::ComponentsNotFunctioning),
            _ => Err(PldmError::InvalidData),
        }
    }
}

#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct CancelUpdateComponentRequest {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
}

impl CancelUpdateComponentRequest {
    pub fn new(instance_id: InstanceId, msg_type: PldmMsgType) -> Self {
        CancelUpdateComponentRequest {
            hdr: PldmMsgHeader::new(
                instance_id,
                msg_type,
                PldmSupportedType::FwUpdate,
                FwUpdateCmd::CancelUpdateComponent as u8,
            ),
        }
    }
}

impl PldmCodec for CancelUpdateComponentRequest {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, PldmCodecError> {
        let bytes = core::mem::size_of::<CancelUpdateComponentRequest>();
        if buffer.len() < bytes {
            return Err(PldmCodecError::BufferTooShort);
        }

        let offset = 0;
        self.write_to(&mut buffer[offset..offset + bytes]).unwrap();
        Ok(bytes)
    }

    fn decode(buffer: &[u8]) -> Result<Self, PldmCodecError> {
        let bytes = core::mem::size_of::<CancelUpdateComponentRequest>();
        if buffer.len() < bytes {
            return Err(PldmCodecError::BufferTooShort);
        }

        let offset = 0;
        Ok(CancelUpdateComponentRequest::read_from_bytes(&buffer[offset..offset + bytes]).unwrap())
    }
}

#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct CancelUpdateComponentResponse {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub completion_code: u8,
}

impl CancelUpdateComponentResponse {
    pub fn new(instance_id: InstanceId, completion_code: u8) -> CancelUpdateComponentResponse {
        CancelUpdateComponentResponse {
            hdr: PldmMsgHeader::new(
                instance_id,
                PldmMsgType::Response,
                PldmSupportedType::FwUpdate,
                FwUpdateCmd::CancelUpdateComponent as u8,
            ),
            completion_code,
        }
    }
}

impl PldmCodec for CancelUpdateComponentResponse {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, PldmCodecError> {
        let bytes = core::mem::size_of::<CancelUpdateComponentResponse>();
        if buffer.len() < bytes {
            return Err(PldmCodecError::BufferTooShort);
        }

        let offset = 0;
        self.write_to(&mut buffer[offset..offset + bytes]).unwrap();
        Ok(bytes)
    }

    fn decode(buffer: &[u8]) -> Result<Self, PldmCodecError> {
        let bytes = core::mem::size_of::<CancelUpdateComponentResponse>();
        if buffer.len() < bytes {
            return Err(PldmCodecError::BufferTooShort);
        }

        let offset = 0;
        Ok(
            CancelUpdateComponentResponse::read_from_bytes(&buffer[offset..offset + bytes])
                .unwrap(),
        )
    }
}

#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, PartialEq)]
#[repr(C, packed)]
pub struct CancelUpdateRequest {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
}

impl CancelUpdateRequest {
    pub fn new(instance_id: InstanceId, msg_type: PldmMsgType) -> Self {
        CancelUpdateRequest {
            hdr: PldmMsgHeader::new(
                instance_id,
                msg_type,
                PldmSupportedType::FwUpdate,
                FwUpdateCmd::CancelUpdate as u8,
            ),
        }
    }
}

impl PldmCodec for CancelUpdateRequest {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, PldmCodecError> {
        let bytes = core::mem::size_of::<CancelUpdateRequest>();
        if buffer.len() < bytes {
            return Err(PldmCodecError::BufferTooShort);
        }

        let offset = 0;
        self.write_to(&mut buffer[offset..offset + bytes]).unwrap();
        Ok(bytes)
    }

    fn decode(buffer: &[u8]) -> Result<Self, PldmCodecError> {
        let bytes = core::mem::size_of::<CancelUpdateRequest>();
        if buffer.len() < bytes {
            return Err(PldmCodecError::BufferTooShort);
        }

        let offset = 0;
        Ok(CancelUpdateRequest::read_from_bytes(&buffer[offset..offset + bytes]).unwrap())
    }
}

#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable)]
pub struct NonFunctioningComponentBitmap(u64);

impl NonFunctioningComponentBitmap {
    pub fn new(value: u64) -> Self {
        NonFunctioningComponentBitmap(value)
    }

    pub fn value(&self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, PartialEq)]
#[repr(C, packed)]
pub struct CancelUpdateResponse {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub completion_code: u8,
    pub non_functioning_component_indication: u8,
    pub non_functioning_component_bitmap: u64,
}

impl CancelUpdateResponse {
    pub fn new(
        instance_id: InstanceId,
        completion_code: u8,
        non_functioning_component_indication: NonFunctioningComponentIndication,
        non_functioning_component_bitmap: NonFunctioningComponentBitmap,
    ) -> CancelUpdateResponse {
        CancelUpdateResponse {
            hdr: PldmMsgHeader::new(
                instance_id,
                PldmMsgType::Response,
                PldmSupportedType::FwUpdate,
                FwUpdateCmd::CancelUpdate as u8,
            ),
            completion_code,
            non_functioning_component_indication: non_functioning_component_indication as u8,
            non_functioning_component_bitmap: non_functioning_component_bitmap.value(),
        }
    }
}

impl PldmCodec for CancelUpdateResponse {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, PldmCodecError> {
        let bytes = core::mem::size_of::<CancelUpdateResponse>();
        if buffer.len() < bytes {
            return Err(PldmCodecError::BufferTooShort);
        }

        let offset = 0;
        self.write_to(&mut buffer[offset..offset + bytes]).unwrap();
        Ok(bytes)
    }

    fn decode(buffer: &[u8]) -> Result<Self, PldmCodecError> {
        let bytes = core::mem::size_of::<CancelUpdateResponse>();
        if buffer.len() < bytes {
            return Err(PldmCodecError::BufferTooShort);
        }

        let offset = 0;
        Ok(CancelUpdateResponse::read_from_bytes(&buffer[offset..offset + bytes]).unwrap())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_cancel_update_request() {
        let cancel_update_request = CancelUpdateRequest::new(0x01, PldmMsgType::Request);
        let mut buffer = [0u8; core::mem::size_of::<CancelUpdateRequest>()];
        cancel_update_request.encode(&mut buffer).unwrap();
        let decoded_request = CancelUpdateRequest::decode(&buffer).unwrap();
        assert_eq!(cancel_update_request, decoded_request);
    }

    #[test]
    fn test_cancel_update_response() {
        let response = CancelUpdateResponse::new(
            0x01,
            0x00,
            NonFunctioningComponentIndication::ComponentsFunctioning,
            NonFunctioningComponentBitmap::new(0x00),
        );
        let mut buffer = [0u8; core::mem::size_of::<CancelUpdateResponse>()];
        response.encode(&mut buffer).unwrap();
        let decoded_response = CancelUpdateResponse::decode(&buffer).unwrap();
        assert_eq!(response, decoded_response);
    }
}
