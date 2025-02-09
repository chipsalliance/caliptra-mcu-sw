// Licensed under the Apache-2.0 license

use crate::codec::{PldmCodec, PldmCodecError};
use crate::protocol::base::{
    InstanceId, PldmMsgHeader, PldmMsgType, PldmSupportedType, TransferRespFlag,
    PLDM_MSG_HEADER_LEN,
};
use crate::protocol::firmware_update::{
    ComponentClassification, ComponentResponse, ComponentResponseCode, FwUpdateCmd,
    PldmFirmwareString, PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN,
};
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(C)]
pub struct PassComponentTableRequest {
    pub fixed: PassComponentTableRequestFixed,
    pub comp_ver_str: [u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN],
}

#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Immutable, PartialEq)]
#[repr(C, packed)]
pub struct PassComponentTableRequestFixed {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub transfer_flag: u8,
    pub comp_classification: u16,
    pub comp_identifier: u16,
    pub comp_classification_index: u8,
    pub comp_comparison_stamp: u32,
    pub comp_ver_str_type: u8,
    pub comp_ver_str_len: u8,
}

#[allow(clippy::too_many_arguments)]
impl PassComponentTableRequest {
    pub fn new(
        instance_id: InstanceId,
        msg_type: PldmMsgType,
        transfer_flag: TransferRespFlag,
        comp_classification: ComponentClassification,
        comp_identifier: u16,
        comp_classification_index: u8,
        comp_comparison_stamp: u32,
        comp_version_string: &PldmFirmwareString,
    ) -> PassComponentTableRequest {
        PassComponentTableRequest {
            fixed: PassComponentTableRequestFixed {
                hdr: PldmMsgHeader::new(
                    instance_id,
                    msg_type,
                    PldmSupportedType::FwUpdate,
                    FwUpdateCmd::PassComponentTable as u8,
                ),
                transfer_flag: transfer_flag as u8,
                comp_classification: comp_classification as u16,
                comp_identifier,
                comp_classification_index,
                comp_comparison_stamp,
                comp_ver_str_type: comp_version_string.str_type,
                comp_ver_str_len: comp_version_string.str_len,
            },
            comp_ver_str: {
                let mut arr = [0u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN];
                let len = comp_version_string.str_data.len();
                arr[..len].copy_from_slice(&comp_version_string.str_data);
                arr
            },
        }
    }

    pub fn codec_size_in_bytes(&self) -> usize {
        let mut bytes = core::mem::size_of::<PassComponentTableRequestFixed>();
        bytes += self.fixed.comp_ver_str_len as usize;
        bytes
    }
}

impl PldmCodec for PassComponentTableRequest {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, PldmCodecError> {
        if buffer.len() < self.codec_size_in_bytes() {
            return Err(PldmCodecError::BufferTooShort);
        }

        let mut offset = 0;
        self.fixed
            .write_to(
                &mut buffer
                    [offset..offset + core::mem::size_of::<PassComponentTableRequestFixed>()],
            )
            .unwrap();
        offset += core::mem::size_of::<PassComponentTableRequestFixed>();

        let str_len = self.fixed.comp_ver_str_len as usize;
        buffer[offset..offset + str_len].copy_from_slice(&self.comp_ver_str[..str_len]);
        Ok(offset + str_len)
    }

    fn decode(buffer: &[u8]) -> Result<Self, PldmCodecError> {
        let mut offset = 0;
        let fixed = PassComponentTableRequestFixed::read_from_bytes(
            buffer
                .get(offset..offset + core::mem::size_of::<PassComponentTableRequestFixed>())
                .ok_or(PldmCodecError::BufferTooShort)?,
        )
        .unwrap();
        offset += core::mem::size_of::<PassComponentTableRequestFixed>();

        let str_len = fixed.comp_ver_str_len as usize;
        let mut comp_ver_str = [0u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN];
        comp_ver_str[..str_len].copy_from_slice(
            &buffer
                .get(offset..offset + str_len)
                .ok_or(PldmCodecError::BufferTooShort)?[..str_len],
        );

        Ok(PassComponentTableRequest {
            fixed,
            comp_ver_str,
        })
    }
}
#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, PartialEq)]
#[repr(C, packed)]
pub struct PassComponentTableResponse {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub completion_code: u8,
    pub comp_resp: u8,
    pub comp_resp_code: u8,
}

impl PassComponentTableResponse {
    pub fn new(
        instance_id: InstanceId,
        completion_code: u8,
        comp_resp: ComponentResponse,
        comp_resp_code: ComponentResponseCode,
    ) -> PassComponentTableResponse {
        PassComponentTableResponse {
            hdr: PldmMsgHeader::new(
                instance_id,
                PldmMsgType::Response,
                PldmSupportedType::FwUpdate,
                FwUpdateCmd::PassComponentTable as u8,
            ),
            completion_code,
            comp_resp: comp_resp as u8,
            comp_resp_code: comp_resp_code as u8,
        }
    }
}

impl PldmCodec for PassComponentTableResponse {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, PldmCodecError> {
        let bytes = core::mem::size_of::<PassComponentTableResponse>();
        if buffer.len() < bytes {
            return Err(PldmCodecError::BufferTooShort);
        }
        let offset = 0;
        self.write_to(&mut buffer[offset..offset + bytes]).unwrap();
        Ok(bytes)
    }

    fn decode(buffer: &[u8]) -> Result<Self, PldmCodecError> {
        let bytes = core::mem::size_of::<PassComponentTableResponse>();
        if buffer.len() < bytes {
            return Err(PldmCodecError::BufferTooShort);
        }
        let offset = 0;
        Ok(PassComponentTableResponse::read_from_bytes(&buffer[offset..offset + bytes]).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pass_component_table_request() {
        let request = PassComponentTableRequest::new(
            1,
            PldmMsgType::Request,
            TransferRespFlag::StartAndEnd,
            ComponentClassification::Firmware,
            2,
            3,
            4,
            &PldmFirmwareString::new("UTF-8", "bmc-fw-1.2.0").unwrap(),
        );

        let mut buffer = [0u8; 1024];
        let encoded_size = request.encode(&mut buffer).unwrap();
        let decoded_request = PassComponentTableRequest::decode(&buffer[..encoded_size]).unwrap();
        assert_eq!(request, decoded_request);
    }

    #[test]
    fn test_pass_component_table_response() {
        let response = PassComponentTableResponse::new(
            0,
            0,
            ComponentResponse::CompCanBeUpdated,
            ComponentResponseCode::CompCanBeUpdated,
        );

        let mut buffer = [0u8; 1024];
        let encoded_size = response.encode(&mut buffer).unwrap();
        let decoded_response = PassComponentTableResponse::decode(&buffer[..encoded_size]).unwrap();
        assert_eq!(response, decoded_response);
    }
}
