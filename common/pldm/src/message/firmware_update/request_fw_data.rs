// Licensed under the Apache-2.0 license

use crate::codec::{PldmCodec, PldmCodecError};
use crate::protocol::base::{
    InstanceId, PldmMsgHeader, PldmMsgType, PldmSupportedType, PLDM_MSG_HEADER_LEN,
};
use crate::protocol::firmware_update::FwUpdateCmd;
use crate::util::mctp_transport::{MAX_MCTP_PLDM_MSG_SIZE, MCTP_PLDM_MSG_HDR_LEN};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Maximum firmware data bytes in a single RequestFirmwareData response.
/// Derived from: MAX_MCTP_PLDM_MSG_SIZE - MCTP_PLDM_MSG_HDR_LEN(1) - sizeof(ResponseFixed: hdr(3) + completion_code(1))
pub const MAX_PLDM_FW_DATA_SIZE: usize =
    MAX_MCTP_PLDM_MSG_SIZE - MCTP_PLDM_MSG_HDR_LEN - PLDM_MSG_HEADER_LEN - 1;

#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, PartialEq)]
#[repr(C, packed)]
pub struct RequestFirmwareDataRequest {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub offset: u32,
    pub length: u32,
}

impl RequestFirmwareDataRequest {
    pub fn new(
        instance_id: InstanceId,
        msg_type: PldmMsgType,
        offset: u32,
        length: u32,
    ) -> RequestFirmwareDataRequest {
        let hdr = PldmMsgHeader::new(
            instance_id,
            msg_type,
            PldmSupportedType::FwUpdate,
            FwUpdateCmd::RequestFirmwareData as u8,
        );
        RequestFirmwareDataRequest {
            hdr,
            offset,
            length,
        }
    }
}

#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, PartialEq)]
#[repr(C, packed)]
pub struct RequestFirmwareDataResponseFixed {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub completion_code: u8,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct RequestFirmwareDataResponse<'a> {
    pub fixed: RequestFirmwareDataResponseFixed,
    pub data: &'a [u8],
}

impl RequestFirmwareDataResponse<'_> {
    pub fn new(
        instance_id: InstanceId,
        completion_code: u8,
        data: &[u8],
    ) -> RequestFirmwareDataResponse {
        let fixed = RequestFirmwareDataResponseFixed {
            hdr: PldmMsgHeader::new(
                instance_id,
                PldmMsgType::Response,
                PldmSupportedType::FwUpdate,
                FwUpdateCmd::RequestFirmwareData as u8,
            ),
            completion_code,
        };
        RequestFirmwareDataResponse { fixed, data }
    }

    pub fn codec_size_in_bytes(&self) -> usize {
        let mut bytes = core::mem::size_of::<RequestFirmwareDataResponseFixed>();
        bytes += self.data.len();
        bytes
    }
}

impl PldmCodec for RequestFirmwareDataResponse<'_> {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, PldmCodecError> {
        if buffer.len() < self.codec_size_in_bytes() {
            return Err(PldmCodecError::BufferTooShort);
        }

        let mut offset = 0;
        let bytes = core::mem::size_of::<RequestFirmwareDataResponseFixed>();
        self.fixed
            .write_to(&mut buffer[offset..offset + bytes])
            .unwrap();
        offset += bytes;

        let data_len = self.data.len();
        if data_len > MAX_PLDM_FW_DATA_SIZE {
            return Err(PldmCodecError::BufferTooShort);
        }
        buffer[offset..offset + data_len].copy_from_slice(self.data);
        Ok(bytes + data_len)
    }

    // Decoding is implemented for this struct. The caller should use the `length` field in the request to read the image portion data from the buffer.
    fn decode(_buffer: &[u8]) -> Result<Self, PldmCodecError> {
        Err(PldmCodecError::Unsupported)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_request_firmware_data_request() {
        let request = RequestFirmwareDataRequest::new(1, PldmMsgType::Request, 0, 64);
        let mut buffer = [0u8; 1024];
        let bytes = request.encode(&mut buffer).unwrap();
        let decoded_request = RequestFirmwareDataRequest::decode(&buffer[..bytes]).unwrap();
        assert_eq!(request, decoded_request);
    }

    #[test]
    fn test_request_firmware_data_response() {
        let data = [0u8; 512];
        let response = RequestFirmwareDataResponse::new(1, 0, &data);
        let mut buffer = [0u8; 1024];
        let bytes = response.encode(&mut buffer).unwrap();
        let decoded_response = RequestFirmwareDataResponse::decode(&buffer[..bytes]);
        assert!(decoded_response.is_err());
    }
}
