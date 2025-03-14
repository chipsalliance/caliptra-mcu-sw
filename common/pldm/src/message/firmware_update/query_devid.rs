// Licensed under the Apache-2.0 license

use crate::codec::{PldmCodec, PldmCodecError};
use crate::error::PldmError;
use crate::protocol::base::{
    InstanceId, PldmMsgHeader, PldmMsgType, PldmSupportedType, PLDM_MSG_HEADER_LEN,
};
use crate::protocol::firmware_update::{Descriptor, FwUpdateCmd};
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const ADDITIONAL_DESCRIPTORS_MAX_COUNT: usize = 4; // Arbitrary limit for static storage

#[derive(Debug, Clone, FromBytes, IntoBytes, PartialEq, Immutable)]
#[repr(C, packed)]
pub struct QueryDeviceIdentifiersRequest {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
}

impl QueryDeviceIdentifiersRequest {
    pub fn new(instance_id: InstanceId, message_type: PldmMsgType) -> Self {
        QueryDeviceIdentifiersRequest {
            hdr: PldmMsgHeader::new(
                instance_id,
                message_type,
                PldmSupportedType::FwUpdate,
                FwUpdateCmd::QueryDeviceIdentifiers as u8,
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
#[repr(C)]
pub struct QueryDeviceIdentifiersResponse {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub completion_code: u8,
    pub device_identifiers_len: u32,
    pub descriptor_count: u8,
    pub initial_descriptor: Descriptor,
    pub additional_descriptors: Option<[Descriptor; ADDITIONAL_DESCRIPTORS_MAX_COUNT]>,
}

impl QueryDeviceIdentifiersResponse {
    pub fn new(
        instance_id: InstanceId,
        completion_code: u8,
        initial_descriptor: &Descriptor,
        additional_descriptors: Option<&[Descriptor]>,
    ) -> Result<Self, PldmError> {
        let descriptor_count =
            1 + additional_descriptors.map_or(0, |descriptors| descriptors.len());
        if descriptor_count > ADDITIONAL_DESCRIPTORS_MAX_COUNT + 1 {
            return Err(PldmError::InvalidDescriptorCount);
        }

        Ok(QueryDeviceIdentifiersResponse {
            hdr: PldmMsgHeader::new(
                instance_id,
                PldmMsgType::Response,
                PldmSupportedType::FwUpdate,
                FwUpdateCmd::QueryDeviceIdentifiers as u8,
            ),
            completion_code,
            device_identifiers_len: {
                let mut len = initial_descriptor.codec_size_in_bytes();
                if let Some(additional) = additional_descriptors {
                    for descriptor in additional.iter() {
                        len += descriptor.codec_size_in_bytes();
                    }
                }
                len as u32
            },
            descriptor_count: descriptor_count as u8,
            initial_descriptor: *initial_descriptor,
            additional_descriptors: if descriptor_count > 1 {
                if let Some(additional) = additional_descriptors {
                    let mut descriptors =
                        [Descriptor::new_empty(); ADDITIONAL_DESCRIPTORS_MAX_COUNT];
                    descriptors[..additional.len()].copy_from_slice(additional);
                    Some(descriptors)
                } else {
                    None
                }
            } else {
                None
            },
        })
    }

    pub fn codec_size_in_bytes(&self) -> usize {
        let mut size = PLDM_MSG_HEADER_LEN
            + core::mem::size_of::<u8>()
            + core::mem::size_of::<u32>()
            + core::mem::size_of::<u8>();
        size += self.initial_descriptor.codec_size_in_bytes();

        if let Some(additional_descriptors) = &self.additional_descriptors {
            for descriptor in additional_descriptors
                .iter()
                .take(self.descriptor_count as usize - 1)
            {
                size += descriptor.codec_size_in_bytes();
            }
        }
        size
    }
}

impl PldmCodec for QueryDeviceIdentifiersResponse {
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

        self.device_identifiers_len
            .write_to(&mut buffer[offset..offset + core::mem::size_of::<u32>()])
            .unwrap();
        offset += core::mem::size_of::<u32>();

        self.descriptor_count
            .write_to(&mut buffer[offset..offset + core::mem::size_of::<u8>()])
            .unwrap();
        offset += core::mem::size_of::<u8>();

        let bytes = self.initial_descriptor.encode(&mut buffer[offset..])?;
        offset += bytes;

        if let Some(additional_descriptors) = &self.additional_descriptors {
            for descriptor in additional_descriptors
                .iter()
                .take(self.descriptor_count as usize - 1)
            {
                let bytes = descriptor.encode(&mut buffer[offset..])?;
                offset += bytes;
            }
        }
        Ok(offset)
    }

    fn decode(buffer: &[u8]) -> Result<Self, PldmCodecError> {
        let mut offset = 0;

        let hdr = PldmMsgHeader::<[u8; PLDM_MSG_HEADER_LEN]>::read_from_bytes(
            buffer
                .get(offset..offset + PLDM_MSG_HEADER_LEN)
                .ok_or(PldmCodecError::BufferTooShort)?,
        )
        .unwrap();
        offset += PLDM_MSG_HEADER_LEN;

        let completion_code = u8::read_from_bytes(
            buffer
                .get(offset..offset + 1)
                .ok_or(PldmCodecError::BufferTooShort)?,
        )
        .unwrap();
        offset += 1;

        let device_identifiers_len = u32::read_from_bytes(
            buffer
                .get(offset..offset + 4)
                .ok_or(PldmCodecError::BufferTooShort)?,
        )
        .unwrap();
        offset += 4;

        let descriptor_count = u8::read_from_bytes(
            buffer
                .get(offset..offset + 1)
                .ok_or(PldmCodecError::BufferTooShort)?,
        )
        .unwrap();
        offset += 1;

        let initial_descriptor = Descriptor::decode(&buffer[offset..])?;
        offset += Descriptor::codec_size_in_bytes(&initial_descriptor);

        let additional_descriptors = if descriptor_count > 1 {
            let mut descriptors = [Descriptor::new_empty(); ADDITIONAL_DESCRIPTORS_MAX_COUNT];
            let count = descriptor_count as usize - 1;
            for descriptor in descriptors.iter_mut().take(count) {
                *descriptor = Descriptor::decode(&buffer[offset..])?;
                offset += Descriptor::codec_size_in_bytes(descriptor);
            }
            Some(descriptors)
        } else {
            None
        };

        Ok(QueryDeviceIdentifiersResponse {
            hdr,
            completion_code,
            device_identifiers_len,
            descriptor_count,
            initial_descriptor,
            additional_descriptors,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::protocol::firmware_update::{Descriptor, DescriptorType};

    #[test]
    fn test_query_device_identifiers_resp() {
        let instance_id = 0;
        let completion_code = 0;

        let test_uid = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let initial_descriptor = Descriptor::new(DescriptorType::Uuid, &test_uid).unwrap();
        let additional_descriptor = Descriptor::new(DescriptorType::Uuid, &test_uid).unwrap();

        let resp = QueryDeviceIdentifiersResponse::new(
            instance_id,
            completion_code,
            &initial_descriptor,
            Some(&[additional_descriptor]),
        )
        .unwrap();

        assert_eq!(resp.descriptor_count, 2);
        assert_eq!(
            resp.device_identifiers_len,
            (initial_descriptor.codec_size_in_bytes() + additional_descriptor.codec_size_in_bytes())
                as u32
        );

        let mut buffer: [u8; 256] = [0; 256];
        let resp_len = resp.encode(&mut buffer).unwrap();
        assert_eq!(resp_len, resp.codec_size_in_bytes());

        let resp_decoded = QueryDeviceIdentifiersResponse::decode(&buffer).unwrap();
        assert_eq!(resp, resp_decoded);
    }
}
