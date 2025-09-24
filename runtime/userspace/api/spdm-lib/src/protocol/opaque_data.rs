// Licensed under the Apache-2.0 license

use crate::codec::{
    decode_u8_slice, encode_u8_slice, Codec, CodecError, CodecResult, CommonCodec, MessageBuf,
};
use crate::protocol::*;
use constant_time_eq::constant_time_eq;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub(crate) const OPAQUE_DATA_LEN_MAX_SIZE: usize = 1024; // Maximum size for opaque data
const MAX_OPAQUE_ELEMENT_DATA_LEN: usize = 256; // Maximum size for opaque element data. Adjust as needed.

#[derive(Debug, PartialEq)]
pub enum OpaqueDataError {
    InvalidStandardsBodyId,
    InvalidVendorIdLength,
    UnalignedOpaqueData,
    InvalidFormat,
    Codec(CodecError),
}

pub type OpaqueDataResult<T> = Result<T, OpaqueDataError>;

pub(crate) struct OpaqueData {
    pub len: u16,
    pub data: [u8; OPAQUE_DATA_LEN_MAX_SIZE],
}

impl Default for OpaqueData {
    fn default() -> Self {
        OpaqueData {
            len: 0,
            data: [0; OPAQUE_DATA_LEN_MAX_SIZE],
        }
    }
}

impl Codec for OpaqueData {
    fn encode(&self, buf: &mut MessageBuf<'_>) -> CodecResult<usize> {
        let mut len = self.len.encode(buf)?;
        if self.len > 0 {
            len += encode_u8_slice(&self.data[..self.len as usize], buf)?;
        }
        Ok(len)
    }

    fn decode(buf: &mut MessageBuf<'_>) -> CodecResult<Self> {
        let len = u16::decode(buf)?;
        if len > OPAQUE_DATA_LEN_MAX_SIZE as u16 {
            return Err(CodecError::BufferOverflow);
        }

        let mut data = [0u8; OPAQUE_DATA_LEN_MAX_SIZE];
        if len > 0 {
            decode_u8_slice(buf, &mut data[..len as usize])?;
        }
        Ok(OpaqueData { len, data })
    }
}

impl OpaqueData {
    pub fn validate_general_opaque_data_format(&mut self) -> OpaqueDataResult<()> {
        if self.len & 0x3 != 0 {
            Err(OpaqueDataError::UnalignedOpaqueData)?;
        }

        let opaque_data_slice = &mut self.data[..self.len as usize];
        let mut opaque_data_buf = MessageBuf::from(opaque_data_slice);

        let opaque_data_hdr =
            GeneralOpaqueDataHdr::decode(&mut opaque_data_buf).map_err(OpaqueDataError::Codec)?;
        if opaque_data_hdr.total_elements == 0 {
            Err(OpaqueDataError::InvalidFormat)?;
        }

        let opaque_element_list_size = opaque_data_buf.data_len();

        let mut total_elements_size = 0;

        for _ in 0..opaque_data_hdr.total_elements {
            total_elements_size += Self::validate_opaque_element(&mut opaque_data_buf)?;
            if total_elements_size > opaque_element_list_size {
                Err(OpaqueDataError::InvalidFormat)?;
            }
        }

        Ok(())
    }

    fn validate_opaque_element(buf: &mut MessageBuf<'_>) -> OpaqueDataResult<usize> {
        let opaque_element_hdr = OpaqueElementHdr::decode(buf).map_err(OpaqueDataError::Codec)?;
        let stds_body_id = opaque_element_hdr.standards_body_id as u16;
        let standards_body_id: StandardsBodyId = stds_body_id
            .try_into()
            .map_err(|_| OpaqueDataError::InvalidStandardsBodyId)?;
        let expected_vendor_id_len = standards_body_id
            .vendor_id_len()
            .map_err(|_| OpaqueDataError::InvalidStandardsBodyId)?;
        opaque_element_hdr.validate(standards_body_id, expected_vendor_id_len)?;
        let element_len = opaque_element_hdr.len();

        let mut opaque_element_data = [0u8; MAX_OPAQUE_ELEMENT_DATA_LEN];
        decode_u8_slice(buf, &mut opaque_element_data[..element_len])
            .map_err(OpaqueDataError::Codec)?;

        let padding_len = (4 - (element_len % 4)) % 4;
        if padding_len > 0 {
            let mut padding_bytes = [0u8; 3];
            let exp_padding_bytes = [0u8; 3];

            decode_u8_slice(buf, &mut padding_bytes[..padding_len])
                .map_err(OpaqueDataError::Codec)?;
            if !constant_time_eq(
                &padding_bytes[..padding_len],
                &exp_padding_bytes[..padding_len],
            ) {
                Err(OpaqueDataError::InvalidFormat)?;
            }
        }
        Ok(element_len + padding_len)
    }
}

#[derive(FromBytes, IntoBytes, Immutable, Debug)]
#[repr(C)]
pub struct GeneralOpaqueDataHdr {
    pub total_elements: u8,
    pub reserved: [u8; 3],
}

impl CommonCodec for GeneralOpaqueDataHdr {}

impl GeneralOpaqueDataHdr {
    pub fn new(total_elements: u8) -> Self {
        GeneralOpaqueDataHdr {
            total_elements,
            reserved: [0; 3],
        }
    }
}

#[derive(Debug)]
pub struct OpaqueElementHdr {
    standards_body_id: u8,
    vendor_id_len: u8,
    vendor_id: Option<[u8; MAX_SPDM_VENDOR_ID_LEN as usize]>,
    opaque_element_data_len: u16,
}

impl Codec for OpaqueElementHdr {
    fn encode(&self, buf: &mut MessageBuf<'_>) -> CodecResult<usize> {
        let mut len = self.standards_body_id.encode(buf)?;
        len += self.vendor_id_len.encode(buf)?;
        if let Some(vendor_id) = &self.vendor_id {
            len += encode_u8_slice(vendor_id, buf)?;
        }
        len += self.opaque_element_data_len.encode(buf)?;
        Ok(len)
    }

    fn decode(buf: &mut MessageBuf<'_>) -> CodecResult<Self> {
        let standards_body_id = u8::decode(buf)?;
        let vendor_id_len = u8::decode(buf)?;

        let vendor_id = if vendor_id_len > 0 {
            let mut vendor_id_data = [0; MAX_SPDM_VENDOR_ID_LEN as usize];
            decode_u8_slice(buf, &mut vendor_id_data[..vendor_id_len as usize])?;
            Some(vendor_id_data)
        } else {
            None
        };

        let opaque_element_data_len = u16::decode(buf)?;

        Ok(OpaqueElementHdr {
            standards_body_id,
            vendor_id_len,
            vendor_id,
            opaque_element_data_len,
        })
    }
}

impl OpaqueElementHdr {
    pub fn new(
        standards_body_id: u8,
        vendor_id_len: u8,
        vendor_id: Option<[u8; MAX_SPDM_VENDOR_ID_LEN as usize]>,
        opaque_element_data_len: u16,
    ) -> Self {
        OpaqueElementHdr {
            standards_body_id,
            vendor_id_len,
            vendor_id,
            opaque_element_data_len,
        }
    }

    pub fn validate(
        &self,
        exp_standards_body_id: StandardsBodyId,
        exp_vendor_id_len: u8,
    ) -> OpaqueDataResult<()> {
        let std_body_id = self.standards_body_id as u16;
        let standards_body_id: StandardsBodyId = std_body_id
            .try_into()
            .map_err(|_| OpaqueDataError::InvalidStandardsBodyId)?;

        if standards_body_id != exp_standards_body_id {
            Err(OpaqueDataError::InvalidStandardsBodyId)?;
        }

        if self.vendor_id_len != exp_vendor_id_len {
            Err(OpaqueDataError::InvalidVendorIdLength)?;
        }

        if self.vendor_id_len > 0 && self.vendor_id.is_none() {
            Err(OpaqueDataError::InvalidFormat)?;
        }

        Ok(())
    }

    pub fn len(&self) -> usize {
        let mut len = 1 + 1 + 2; // standards_body_id + vendor_id_len + opaque_element_data_len
        if self.vendor_id.is_some() {
            len += self.vendor_id_len as usize;
        }
        len
    }
}
