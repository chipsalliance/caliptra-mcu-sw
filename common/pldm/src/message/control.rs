// Licensed under the Apache-2.0 license

use crate::error::PldmError;
use crate::protocol::base::{
    InstanceId, PldmControlCmd, PldmMsgHeader, PldmMsgType, PldmSupportedType,
    TransferOperationFlag, TransferRespFlag, PLDM_MSG_HEADER_LEN,
};
use crate::protocol::version::{PldmVersion, ProtocolVersionStr, Ver32};
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const PLDM_CMDS_BITMAP_LEN: usize = 32;
pub const PLDM_TYPES_BITMAP_LEN: usize = 8;

#[repr(C, packed)]
#[derive(Debug, FromBytes, IntoBytes, Immutable, PartialEq, Clone)]
pub struct GetTidRequest {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
}

impl GetTidRequest {
    pub fn new(instance_id: InstanceId, message_type: PldmMsgType) -> Self {
        Self {
            hdr: PldmMsgHeader::new(
                instance_id,
                message_type,
                PldmSupportedType::Base,
                PldmControlCmd::GetTid as u8,
            ),
        }
    }
}

#[repr(C, packed)]
#[derive(Debug, PartialEq, FromBytes, IntoBytes, Immutable, Clone)]
pub struct GetTidResponse {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub completion_code: u8,
    pub tid: u8,
}

impl GetTidResponse {
    pub fn new(instance_id: InstanceId, tid: u8, completion_code: u8) -> Self {
        Self {
            hdr: PldmMsgHeader::new(
                instance_id,
                PldmMsgType::Response,
                PldmSupportedType::Base,
                PldmControlCmd::GetTid as u8,
            ),
            completion_code,
            tid,
        }
    }
}

#[derive(Debug, FromBytes, IntoBytes, Immutable, PartialEq, Clone)]
#[repr(C, packed)]
pub struct SetTidRequest {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub tid: u8,
}
impl SetTidRequest {
    pub fn new(instance_id: InstanceId, message_type: PldmMsgType, tid: u8) -> Self {
        Self {
            hdr: PldmMsgHeader::new(
                instance_id,
                message_type,
                PldmSupportedType::Base,
                PldmControlCmd::SetTid as u8,
            ),
            tid,
        }
    }
}

#[derive(Debug, FromBytes, IntoBytes, Immutable, PartialEq, Clone)]
#[repr(C, packed)]
pub struct SetTidResponse {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub completion_code: u8,
}

impl SetTidResponse {
    pub fn new(instance_id: InstanceId, ompletion_code: u8) -> Self {
        SetTidResponse {
            hdr: PldmMsgHeader::new(
                instance_id,
                PldmMsgType::Response,
                PldmSupportedType::Base,
                PldmControlCmd::SetTid as u8,
            ),
            completion_code: ompletion_code,
        }
    }
}

#[repr(C, packed)]
#[derive(Debug, FromBytes, IntoBytes, Immutable, PartialEq, Clone)]
pub struct GetPldmCommandsRequest {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub pldm_type: u8,
    pub protocol_version: Ver32,
}

impl GetPldmCommandsRequest {
    pub fn new(
        instance_id: InstanceId,
        message_type: PldmMsgType,
        pldm_type: u8,
        version_str: ProtocolVersionStr,
    ) -> Self {
        Self {
            hdr: PldmMsgHeader::new(
                instance_id,
                message_type,
                PldmSupportedType::Base,
                PldmControlCmd::GetPldmCommands as u8,
            ),
            pldm_type,
            protocol_version: PldmVersion::try_from(version_str)
                .unwrap()
                .bcd_encode_to_ver32(),
        }
    }
}

#[derive(Debug, FromBytes, IntoBytes, Immutable, PartialEq, Clone)]
#[repr(C, packed)]
pub struct GetPldmCommandsResponse {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub completion_code: u8,
    pub supported_cmds: [u8; PLDM_CMDS_BITMAP_LEN],
}

impl GetPldmCommandsResponse {
    pub fn new(instance_id: InstanceId, completion_code: u8, supported_cmds: &[u8]) -> Self {
        Self {
            hdr: PldmMsgHeader::new(
                instance_id,
                PldmMsgType::Response,
                PldmSupportedType::Base,
                PldmControlCmd::GetPldmCommands as u8,
            ),
            completion_code,
            supported_cmds: construct_bitmap::<PLDM_CMDS_BITMAP_LEN>(supported_cmds),
        }
    }
}

#[derive(Debug, FromBytes, IntoBytes, Immutable, PartialEq, Clone)]
#[repr(C, packed)]
pub struct GetPldmTypeRequest {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
}

impl GetPldmTypeRequest {
    pub fn new(instance_id: InstanceId, message_type: PldmMsgType) -> Self {
        Self {
            hdr: PldmMsgHeader::new(
                instance_id,
                message_type,
                PldmSupportedType::Base,
                PldmControlCmd::GetPldmTypes as u8,
            ),
        }
    }
}

fn construct_bitmap<const N: usize>(items: &[u8]) -> [u8; N] {
    let mut bitmap = [0u8; N];
    for &item in items.iter().take(N * 8) {
        let byte_index = (item / 8) as usize;
        let bit_index = (item % 8) as usize;
        bitmap[byte_index] |= 1 << bit_index;
    }
    bitmap
}

pub fn is_bit_set(bitmap: &[u8], item: u8) -> bool {
    let byte_index = (item / 8) as usize;
    let bit_index = (item % 8) as usize;
    bitmap[byte_index] & (1 << bit_index) != 0
}

#[derive(Debug, FromBytes, IntoBytes, Immutable, PartialEq, Clone)]
#[repr(C, packed)]
pub struct GetPldmTypeResponse {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub completion_code: u8,
    pub pldm_types: [u8; PLDM_TYPES_BITMAP_LEN],
}

impl GetPldmTypeResponse {
    pub fn new(instance_id: InstanceId, completion_code: u8, supported_types: &[u8]) -> Self {
        Self {
            hdr: PldmMsgHeader::new(
                instance_id,
                PldmMsgType::Response,
                PldmSupportedType::Base,
                PldmControlCmd::GetPldmTypes as u8,
            ),
            completion_code,
            pldm_types: construct_bitmap::<PLDM_TYPES_BITMAP_LEN>(supported_types),
        }
    }
}

#[derive(Debug, FromBytes, IntoBytes, Immutable, PartialEq, Clone)]
#[repr(C, packed)]
pub struct GetPldmVersionRequest {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub data_transfer_handle: u32,
    pub transfer_op_flag: u8,
    pub pldm_type: u8,
}

impl GetPldmVersionRequest {
    pub fn new(
        instance_id: InstanceId,
        message_type: PldmMsgType,
        data_transfer_handle: u32,
        transfer_op_flag: TransferOperationFlag,
        pldm_type: PldmSupportedType,
    ) -> Self {
        Self {
            hdr: PldmMsgHeader::new(
                instance_id,
                message_type,
                PldmSupportedType::Base,
                PldmControlCmd::GetPldmVersion as u8,
            ),
            data_transfer_handle,
            transfer_op_flag: transfer_op_flag as u8,
            pldm_type: pldm_type as u8,
        }
    }
}

#[derive(Debug, FromBytes, IntoBytes, Immutable, PartialEq, Clone)]
#[repr(C, packed)]
pub struct GetPldmVersionResponse {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub completion_code: u8,
    pub next_transfer_handle: u32, // next portion of PLDM version data transfer
    pub transfer_rsp_flag: u8,     // PLDM GetVersion transfer flag
    pub version_data: Ver32, // PLDM GetVersion version field. Support only 1 version field. Version data is version and checksum
}

impl GetPldmVersionResponse {
    pub fn new(
        instance_id: InstanceId,
        completion_code: u8,
        next_transfer_handle: u32,
        transfer_rsp_flag: TransferRespFlag,
        version_str: ProtocolVersionStr,
    ) -> Result<Self, PldmError> {
        Ok(Self {
            hdr: PldmMsgHeader::new(
                instance_id,
                PldmMsgType::Response,
                PldmSupportedType::Base,
                PldmControlCmd::GetPldmVersion as u8,
            ),
            completion_code,
            next_transfer_handle,
            transfer_rsp_flag: transfer_rsp_flag as u8,
            version_data: PldmVersion::try_from(version_str)
                .map_err(|_| PldmError::InvalidProtocolVersion)?
                .bcd_encode_to_ver32(),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::codec::{PldmCodec, PldmCodecError};

    #[test]
    fn test_get_tid_request() {
        let request = GetTidRequest::new(0x01, PldmMsgType::Request);
        let mut buffer = [0u8; core::mem::size_of::<GetTidRequest>()];
        request.encode(&mut buffer).unwrap();
        let decoded_request = GetTidRequest::decode(&buffer).unwrap();
        assert_eq!(request, decoded_request);
    }

    #[test]
    fn test_get_tid_response() {
        let response = GetTidResponse::new(0x01, 42, 0);
        let mut buffer = [0u8; core::mem::size_of::<GetTidResponse>()];
        response.encode(&mut buffer).unwrap();
        let decoded_response = GetTidResponse::decode(&buffer).unwrap();
        assert_eq!(response, decoded_response);
    }

    #[test]
    fn test_set_tid_request() {
        let request = SetTidRequest::new(0x01, PldmMsgType::Request, 42);
        let mut buffer = [0u8; core::mem::size_of::<SetTidRequest>()];
        request.encode(&mut buffer).unwrap();
        let decoded_request = SetTidRequest::decode(&buffer).unwrap();
        assert_eq!(request, decoded_request);
    }

    #[test]
    fn test_set_tid_response() {
        let response = SetTidResponse::new(0x01, 0);
        let mut buffer = [0u8; core::mem::size_of::<SetTidResponse>()];
        response.encode(&mut buffer).unwrap();
        let decoded_response = SetTidResponse::decode(&buffer).unwrap();
        assert_eq!(response, decoded_response);
    }

    #[test]
    fn test_get_pldm_commands_request() {
        let request = GetPldmCommandsRequest::new(0x01, PldmMsgType::Request, 1, "1.0.0");
        let mut buffer = [0u8; core::mem::size_of::<GetPldmCommandsRequest>()];
        request.encode(&mut buffer).unwrap();
        let decoded_request = GetPldmCommandsRequest::decode(&buffer).unwrap();
        assert_eq!(request, decoded_request);
    }

    #[test]
    fn test_get_pldm_commands_response() {
        let response = GetPldmCommandsResponse::new(0x01, 0, &[1, 2, 3]);
        let mut buffer = [0u8; core::mem::size_of::<GetPldmCommandsResponse>()];
        response.encode(&mut buffer).unwrap();
        let decoded_response = GetPldmCommandsResponse::decode(&buffer).unwrap();
        assert_eq!(response, decoded_response);
    }

    #[test]
    fn test_get_pldm_type_request() {
        let request = GetPldmTypeRequest::new(0x01, PldmMsgType::Request);
        let mut buffer = [0u8; core::mem::size_of::<GetPldmTypeRequest>()];
        request.encode(&mut buffer).unwrap();
        let decoded_request = GetPldmTypeRequest::decode(&buffer).unwrap();
        assert_eq!(request, decoded_request);
    }

    #[test]
    fn test_get_pldm_type_response() {
        let response = GetPldmTypeResponse::new(0x01, 0, &[0, 5]);
        // Check bit map
        let mut expected_bitmap = [0u8; PLDM_TYPES_BITMAP_LEN];
        expected_bitmap[0] = 0b00100001;
        assert_eq!(response.pldm_types, expected_bitmap);

        let mut buffer = [0u8; core::mem::size_of::<GetPldmTypeResponse>()];
        response.encode(&mut buffer).unwrap();
        let decoded_response = GetPldmTypeResponse::decode(&buffer).unwrap();
        assert_eq!(response, decoded_response);
    }

    #[test]
    fn test_get_pldm_version_request() {
        let request = GetPldmVersionRequest::new(
            0x01,
            PldmMsgType::Request,
            0,
            TransferOperationFlag::GetFirstPart,
            PldmSupportedType::Base,
        );
        let mut buffer = [0u8; core::mem::size_of::<GetPldmVersionRequest>()];
        request.encode(&mut buffer).unwrap();
        let decoded_request = GetPldmVersionRequest::decode(&buffer).unwrap();
        assert_eq!(request, decoded_request);
    }

    #[test]
    fn test_get_pldm_version_response() {
        let response =
            GetPldmVersionResponse::new(0x01, 0, 0, TransferRespFlag::StartAndEnd, "1.3.0")
                .unwrap();
        let mut buffer = [0u8; core::mem::size_of::<GetPldmVersionResponse>()];
        response.encode(&mut buffer).unwrap();
        let decoded_response = GetPldmVersionResponse::decode(&buffer).unwrap();
        assert_eq!(response, decoded_response);
    }

    #[test]
    fn test_buffer_too_short() {
        let buffer = [0u8; 2];
        let result = GetTidRequest::decode(&buffer);
        assert_eq!(result, Err(PldmCodecError::BufferTooShort));
    }
}
