// Licensed under the Apache-2.0 license

use crate::codec::{PldmCodec, PldmCodecError};
use crate::protocol::base::{
    InstanceId, PldmMsgHeader, PldmMsgType, PldmSupportedType, PLDM_MSG_HEADER_LEN,
};
use crate::protocol::firmware_update::{
    FwUpdateCmd, PldmFirmwareString, PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN,
};
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(C)]
pub struct RequestUpdateRequest {
    pub fixed: RequestUpdateRequestFixed,
    pub comp_image_set_ver_str: [u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN],
}

#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Immutable, PartialEq)]
#[repr(C, packed)]
pub struct RequestUpdateRequestFixed {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub max_transfer_size: u32,
    pub num_of_comp: u16,
    pub max_outstanding_transfer_req: u8,
    pub pkg_data_len: u16,
    pub comp_image_set_ver_str_type: u8,
    pub comp_image_set_ver_str_len: u8,
}
pub const REQUEST_UPDATE_REQUEST_FIXED_HEADER_LEN: usize = 14;
const _: () = assert!(
    core::mem::size_of::<RequestUpdateRequestFixed>() == REQUEST_UPDATE_REQUEST_FIXED_HEADER_LEN
);

impl RequestUpdateRequest {
    pub fn new(
        instance_id: InstanceId,
        msg_type: PldmMsgType,
        max_transfer_size: u32,
        num_of_comp: u16,
        max_outstanding_transfer_req: u8,
        pkg_data_len: u16,
        comp_image_set_version_string: &PldmFirmwareString,
    ) -> Self {
        RequestUpdateRequest {
            fixed: RequestUpdateRequestFixed {
                hdr: PldmMsgHeader::new(
                    instance_id,
                    msg_type,
                    PldmSupportedType::FwUpdate,
                    FwUpdateCmd::RequestUpdate as u8,
                ),
                max_transfer_size,
                num_of_comp,
                max_outstanding_transfer_req,
                pkg_data_len,
                comp_image_set_ver_str_type: comp_image_set_version_string.str_type,
                comp_image_set_ver_str_len: comp_image_set_version_string.str_len,
            },
            comp_image_set_ver_str: {
                let mut arr = [0u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN];
                let len = comp_image_set_version_string.str_data.len();
                arr[..len].copy_from_slice(&comp_image_set_version_string.str_data);
                arr
            },
        }
    }

    pub fn get_comp_image_set_ver_str(&self) -> PldmFirmwareString {
        PldmFirmwareString {
            str_type: self.fixed.comp_image_set_ver_str_type,
            str_len: self.fixed.comp_image_set_ver_str_len,
            str_data: {
                let mut arr = [0u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN];
                arr.copy_from_slice(
                    &self.comp_image_set_ver_str[..self.fixed.comp_image_set_ver_str_len as usize],
                );
                arr
            },
        }
    }

    pub fn codec_size_in_bytes(&self) -> usize {
        let mut bytes = core::mem::size_of::<RequestUpdateRequestFixed>();
        bytes += self.fixed.comp_image_set_ver_str_len as usize;
        bytes
    }
}

impl PldmCodec for RequestUpdateRequest {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, PldmCodecError> {
        if buffer.len() < self.codec_size_in_bytes() {
            return Err(PldmCodecError::BufferTooShort);
        }

        let mut offset = 0;
        self.fixed
            .write_to(
                &mut buffer[offset..offset + core::mem::size_of::<RequestUpdateRequestFixed>()],
            )
            .unwrap();
        offset += core::mem::size_of::<RequestUpdateRequestFixed>();

        let str_len = self.fixed.comp_image_set_ver_str_len as usize;
        buffer[offset..offset + str_len].copy_from_slice(&self.comp_image_set_ver_str[..str_len]);
        Ok(offset + str_len)
    }

    fn decode(buffer: &[u8]) -> Result<Self, PldmCodecError> {
        let mut offset = 0;
        let fixed = RequestUpdateRequestFixed::read_from_bytes(
            buffer
                .get(offset..offset + core::mem::size_of::<RequestUpdateRequestFixed>())
                .ok_or(PldmCodecError::BufferTooShort)?,
        )
        .unwrap();
        offset += core::mem::size_of::<RequestUpdateRequestFixed>();

        let str_len = fixed.comp_image_set_ver_str_len as usize;
        let mut comp_image_set_ver_str = [0u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN];
        comp_image_set_ver_str[..str_len].copy_from_slice(
            &buffer
                .get(offset..offset + str_len)
                .ok_or(PldmCodecError::BufferTooShort)?[..str_len],
        );

        Ok(RequestUpdateRequest {
            fixed,
            comp_image_set_ver_str,
        })
    }
}

#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Immutable, PartialEq, Default)]
#[repr(C, packed)]
pub struct RequestUpdateResponseFixed {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub completion_code: u8,
    pub fd_meta_data_len: u16,
    pub fd_will_send_pkg_data_cmd: u8,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct RequestUpdateResponse {
    pub fixed: RequestUpdateResponseFixed,
    // This field is only present if FDWillSendGetPackageDataCommand is set to 0x02.
    pub get_pkg_data_max_transfer_size: Option<u32>,
}

impl RequestUpdateResponse {
    pub fn new(
        instance_id: InstanceId,
        completion_code: u8,
        fd_meta_data_len: u16,
        fd_will_send_pkg_data_cmd: u8,
        get_pkg_data_max_transfer_size: Option<u32>,
    ) -> RequestUpdateResponse {
        RequestUpdateResponse {
            fixed: RequestUpdateResponseFixed {
                hdr: PldmMsgHeader::new(
                    instance_id,
                    PldmMsgType::Response,
                    PldmSupportedType::FwUpdate,
                    FwUpdateCmd::RequestUpdate as u8,
                ),
                completion_code,
                fd_meta_data_len,
                fd_will_send_pkg_data_cmd,
            },
            get_pkg_data_max_transfer_size,
        }
    }

    pub fn codec_size_in_bytes(&self) -> usize {
        let mut bytes = core::mem::size_of::<RequestUpdateResponseFixed>();
        if self.fixed.fd_will_send_pkg_data_cmd == 0x02 {
            bytes += core::mem::size_of::<u32>();
        }
        bytes
    }
}

impl PldmCodec for RequestUpdateResponse {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, PldmCodecError> {
        if buffer.len() < self.codec_size_in_bytes() {
            return Err(PldmCodecError::BufferTooShort);
        }

        let mut offset = 0;
        self.fixed
            .write_to(
                &mut buffer[offset..offset + core::mem::size_of::<RequestUpdateResponseFixed>()],
            )
            .unwrap();
        offset += core::mem::size_of::<RequestUpdateResponseFixed>();

        if let Some(size) = self.get_pkg_data_max_transfer_size {
            size.write_to(&mut buffer[offset..offset + core::mem::size_of::<u32>()])
                .unwrap();
            offset += core::mem::size_of::<u32>();
        }

        Ok(offset)
    }

    fn decode(buffer: &[u8]) -> Result<Self, PldmCodecError> {
        let mut offset = 0;
        let fixed = RequestUpdateResponseFixed::read_from_bytes(
            buffer
                .get(offset..offset + core::mem::size_of::<RequestUpdateResponseFixed>())
                .ok_or(PldmCodecError::BufferTooShort)?,
        )
        .unwrap();
        offset += core::mem::size_of::<RequestUpdateResponseFixed>();

        let get_pkg_data_max_transfer_size = if fixed.fd_will_send_pkg_data_cmd == 0x02 {
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

        Ok(RequestUpdateResponse {
            fixed,
            get_pkg_data_max_transfer_size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::firmware_update::PldmFirmwareString;

    #[test]
    fn test_request_update_request() {
        let request = RequestUpdateRequest::new(
            0,
            PldmMsgType::Request,
            512,
            2,
            1,
            256,
            &PldmFirmwareString::new("ASCII", "mcu-1.0.0").unwrap(),
        );

        let mut buffer = [0u8; 512];
        let encoded_size = request.encode(&mut buffer).unwrap();
        assert_eq!(encoded_size, request.codec_size_in_bytes());

        let decoded_request = RequestUpdateRequest::decode(&buffer[..encoded_size]).unwrap();
        assert_eq!(request, decoded_request);
    }

    #[test]
    fn test_request_update_response() {
        let response = RequestUpdateResponse::new(1, 0, 128, 0x02, Some(2048));

        let mut buffer = [0u8; 512];
        let encoded_size = response.encode(&mut buffer).unwrap();
        assert_eq!(encoded_size, response.codec_size_in_bytes());

        let decoded_response = RequestUpdateResponse::decode(&buffer[..encoded_size]).unwrap();
        assert_eq!(response, decoded_response);
    }
}
