// Licensed under the Apache-2.0 license

use crate::codec::{PldmCodec, PldmCodecError};
use crate::protocol::base::{
    InstanceId, PldmMsgHeader, PldmMsgType, PldmSupportedType, PLDM_MSG_HEADER_LEN,
};
use crate::protocol::firmware_update::{
    ComponentClassification, ComponentCompatibilityResponse, ComponentCompatibilityResponseCode,
    FwUpdateCmd, PldmFirmwareString, UpdateOptionFlags, PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN,
};
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, PartialEq)]
#[repr(C, packed)]
pub struct UpdateComponentRequestFixed {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub comp_classification: u16,
    pub comp_identifier: u16,
    pub comp_classification_index: u8,
    pub comp_comparison_stamp: u32,
    pub comp_image_size: u32,
    pub update_option_flags: u32,
    pub comp_ver_str_type: u8,
    pub comp_ver_str_len: u8,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct UpdateComponentRequest {
    pub fixed: UpdateComponentRequestFixed,
    pub comp_ver_str: [u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN],
}

#[allow(clippy::too_many_arguments)]
impl UpdateComponentRequest {
    pub fn new(
        instance_id: InstanceId,
        msg_type: PldmMsgType,
        comp_classification: ComponentClassification,
        comp_identifier: u16,
        comp_classification_index: u8,
        comp_comparison_stamp: u32,
        comp_image_size: u32,
        update_option_flags: UpdateOptionFlags,
        comp_version_string: &PldmFirmwareString,
    ) -> UpdateComponentRequest {
        UpdateComponentRequest {
            fixed: UpdateComponentRequestFixed {
                hdr: PldmMsgHeader::new(
                    instance_id,
                    msg_type,
                    PldmSupportedType::FwUpdate,
                    FwUpdateCmd::UpdateComponent as u8,
                ),
                comp_classification: comp_classification as u16,
                comp_identifier,
                comp_classification_index,
                comp_comparison_stamp,
                comp_image_size,
                update_option_flags: update_option_flags.0,
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

    fn codec_size_in_bytes(&self) -> usize {
        let mut bytes = 0;
        bytes += core::mem::size_of::<UpdateComponentRequestFixed>();
        bytes += self.fixed.comp_ver_str_len as usize;
        bytes
    }
}

impl PldmCodec for UpdateComponentRequest {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, PldmCodecError> {
        if buffer.len() < self.codec_size_in_bytes() {
            return Err(PldmCodecError::BufferTooShort);
        }

        let mut offset = 0;
        let bytes = core::mem::size_of::<UpdateComponentRequestFixed>();
        self.fixed
            .write_to(&mut buffer[offset..offset + bytes])
            .unwrap();
        offset += bytes;

        let str_len = self.fixed.comp_ver_str_len as usize;
        buffer[offset..offset + str_len].copy_from_slice(&self.comp_ver_str[..str_len]);
        Ok(offset + str_len)
    }

    fn decode(buffer: &[u8]) -> Result<Self, PldmCodecError> {
        let mut offset = 0;
        let bytes = core::mem::size_of::<UpdateComponentRequestFixed>();
        let fixed = UpdateComponentRequestFixed::read_from_bytes(
            buffer
                .get(offset..offset + bytes)
                .ok_or(PldmCodecError::BufferTooShort)?,
        )
        .unwrap();
        offset += bytes;

        let comp_ver_str = {
            let mut arr = [0u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN];
            let str_len = fixed.comp_ver_str_len as usize;
            arr[..str_len].copy_from_slice(&buffer[offset..offset + str_len]);
            arr
        };
        Ok(UpdateComponentRequest {
            fixed,
            comp_ver_str,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct UpdateComponentResponse {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub completion_code: u8,
    pub comp_compatibility_resp: u8,
    pub comp_compatibility_resp_code: u8,
    pub update_option_flags_enabled: u32,
    pub time_before_req_fw_data: u16,
    pub get_comp_opaque_data_max_transfer_size: Option<u32>,
}

impl UpdateComponentResponse {
    pub fn new(
        instance_id: InstanceId,
        completion_code: u8,
        comp_compatibility_resp: ComponentCompatibilityResponse,
        comp_compatibility_resp_code: ComponentCompatibilityResponseCode,
        update_option_flags_enabled: UpdateOptionFlags,
        time_before_req_fw_data: u16,
        get_comp_opaque_data_max_transfer_size: Option<u32>,
    ) -> UpdateComponentResponse {
        UpdateComponentResponse {
            hdr: PldmMsgHeader::new(
                instance_id,
                PldmMsgType::Response,
                PldmSupportedType::FwUpdate,
                FwUpdateCmd::UpdateComponent as u8,
            ),
            completion_code,
            comp_compatibility_resp: comp_compatibility_resp as u8,
            comp_compatibility_resp_code: comp_compatibility_resp_code as u8,
            update_option_flags_enabled: update_option_flags_enabled.0,
            time_before_req_fw_data,
            get_comp_opaque_data_max_transfer_size,
        }
    }

    fn codec_size_in_bytes(&self) -> usize {
        let mut bytes = PLDM_MSG_HEADER_LEN
            + core::mem::size_of::<u8>() * 3
            + core::mem::size_of::<u32>()
            + core::mem::size_of::<u16>();
        if self.get_comp_opaque_data_max_transfer_size.is_some() {
            bytes += core::mem::size_of::<u32>();
        }
        bytes
    }
}

impl PldmCodec for UpdateComponentResponse {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, PldmCodecError> {
        if buffer.len() < self.codec_size_in_bytes() {
            return Err(PldmCodecError::BufferTooShort);
        }

        let mut offset = 0;
        self.hdr
            .write_to(&mut buffer[offset..offset + PLDM_MSG_HEADER_LEN])
            .unwrap();
        offset += PLDM_MSG_HEADER_LEN;

        self.completion_code
            .write_to(&mut buffer[offset..offset + core::mem::size_of::<u8>()])
            .unwrap();
        offset += core::mem::size_of::<u8>();

        self.comp_compatibility_resp
            .write_to(&mut buffer[offset..offset + core::mem::size_of::<u8>()])
            .unwrap();
        offset += core::mem::size_of::<u8>();

        self.comp_compatibility_resp_code
            .write_to(&mut buffer[offset..offset + core::mem::size_of::<u8>()])
            .unwrap();
        offset += core::mem::size_of::<u8>();

        self.update_option_flags_enabled
            .write_to(&mut buffer[offset..offset + core::mem::size_of::<u32>()])
            .unwrap();
        offset += core::mem::size_of::<u32>();

        self.time_before_req_fw_data
            .write_to(&mut buffer[offset..offset + core::mem::size_of::<u16>()])
            .unwrap();
        offset += core::mem::size_of::<u16>();

        if let Some(size) = self.get_comp_opaque_data_max_transfer_size {
            size.write_to(&mut buffer[offset..offset + core::mem::size_of::<u32>()])
                .unwrap();
            offset += core::mem::size_of::<u32>();
        }

        Ok(offset)
    }

    fn decode(buffer: &[u8]) -> Result<Self, PldmCodecError> {
        let mut offset = 0;
        let hdr = PldmMsgHeader::read_from_bytes(
            buffer
                .get(offset..offset + PLDM_MSG_HEADER_LEN)
                .ok_or(PldmCodecError::BufferTooShort)?,
        )
        .unwrap();
        offset += PLDM_MSG_HEADER_LEN;

        let completion_code = u8::read_from_bytes(
            buffer
                .get(offset..offset + core::mem::size_of::<u8>())
                .ok_or(PldmCodecError::BufferTooShort)?,
        )
        .unwrap();
        offset += core::mem::size_of::<u8>();

        let comp_compatibility_resp = u8::read_from_bytes(
            buffer
                .get(offset..offset + core::mem::size_of::<u8>())
                .ok_or(PldmCodecError::BufferTooShort)?,
        )
        .unwrap();
        offset += core::mem::size_of::<u8>();

        let comp_compatibility_resp_code = u8::read_from_bytes(
            buffer
                .get(offset..offset + core::mem::size_of::<u8>())
                .ok_or(PldmCodecError::BufferTooShort)?,
        )
        .unwrap();
        offset += core::mem::size_of::<u8>();

        let update_option_flags_enabled = u32::read_from_bytes(
            buffer
                .get(offset..offset + core::mem::size_of::<u32>())
                .ok_or(PldmCodecError::BufferTooShort)?,
        )
        .unwrap();
        offset += core::mem::size_of::<u32>();

        let time_before_req_fw_data = u16::read_from_bytes(
            buffer
                .get(offset..offset + core::mem::size_of::<u16>())
                .ok_or(PldmCodecError::BufferTooShort)?,
        )
        .unwrap();
        offset += core::mem::size_of::<u16>();

        let update_option_flags = UpdateOptionFlags(update_option_flags_enabled);

        let get_comp_opaque_data_max_transfer_size = if update_option_flags.component_opaque_data()
        {
            Some(
                u32::read_from_bytes(
                    buffer
                        .get(offset..offset + core::mem::size_of::<u32>())
                        .ok_or(PldmCodecError::BufferTooShort)?,
                )
                .unwrap(),
            )
        } else {
            None
        };

        Ok(UpdateComponentResponse {
            hdr,
            completion_code,
            comp_compatibility_resp,
            comp_compatibility_resp_code,
            update_option_flags_enabled,
            time_before_req_fw_data,
            get_comp_opaque_data_max_transfer_size,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_update_component_request() {
        let request = UpdateComponentRequest::new(
            0,
            PldmMsgType::Request,
            ComponentClassification::Firmware,
            0x0001,
            0x01,
            0x00000001,
            0x00000001,
            UpdateOptionFlags(0x00000002),
            &PldmFirmwareString::new("UTF-8", "mcu-fw-1.2.0").unwrap(),
        );
        let mut buffer = [0u8; 512];
        let bytes = request.encode(&mut buffer).unwrap();
        assert_eq!(bytes, request.codec_size_in_bytes());
        let decoded_request = UpdateComponentRequest::decode(&buffer[..bytes]).unwrap();
        assert_eq!(request, decoded_request);
    }

    #[test]
    fn test_update_component_response() {
        let response = UpdateComponentResponse::new(
            0,
            0x00,
            ComponentCompatibilityResponse::CompCanBeUpdated,
            ComponentCompatibilityResponseCode::NoResponseCode,
            UpdateOptionFlags(0x00000002),
            0x0001,
            Some(0x00000100),
        );
        let mut buffer = [0u8; 512];
        let bytes = response.encode(&mut buffer).unwrap();
        assert_eq!(bytes, response.codec_size_in_bytes());
        let decoded_response = UpdateComponentResponse::decode(&buffer[..bytes]).unwrap();
        assert_eq!(response, decoded_response);
    }
}
