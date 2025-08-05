// Licensed under the Apache-2.0 license

use bitfield::bitfield;
use kernel::ErrorCode;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const DOE_DATA_OBJECT_HEADER_LEN_DW: usize = 2; // 8 bytes, 2 dwords
pub const DOE_DISCOVERY_REQ_RESP_LEN_DW: usize = 1; // 4 bytes, 1 dword
pub const DOE_DISCOVERY_DATA_OBJECT_LEN_DW: usize =
    DOE_DATA_OBJECT_HEADER_LEN_DW + DOE_DISCOVERY_REQ_RESP_LEN_DW; // 3 dwords
pub const DOE_DISCOVERY_DATA_OBJECT_LEN: usize = DOE_DISCOVERY_DATA_OBJECT_LEN_DW * 4; // 12 bytes
pub const NUM_DATA_OBJECT_PROTOCOL_TYPES: usize = DataObjectType::SecureSpdm as usize + 1; // DoeDiscovery, Spdm, SecureSpdm
const LENGTH_MASK: u32 = (1 << LENGTH_FIELD_BITS) - 1;
const PCISIG_DOE_VENDOR_ID: u16 = 0x0001;
const LENGTH_FIELD_BITS: u32 = 18;

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
pub enum DataObjectType {
    DoeDiscovery = 0x00,
    Spdm = 0x01,
    SecureSpdm = 0x02,
    Unsupported,
}

impl From<u8> for DataObjectType {
    fn from(value: u8) -> Self {
        match value {
            0x00 => DataObjectType::DoeDiscovery,
            0x01 => DataObjectType::Spdm,
            0x02 => DataObjectType::SecureSpdm,
            _ => DataObjectType::Unsupported,
        }
    }
}

#[derive(FromBytes, IntoBytes, Immutable, PartialEq)]
pub struct DoeDataObjectHeader {
    pub vendor_id: u16,
    pub data_object_type: u8,
    pub reserved_1: u8,
    pub length: u32, // only 17:0 bits are used, 18:31 are reserved
}

impl DoeDataObjectHeader {
    pub fn new(length: u32) -> Self {
        Self {
            vendor_id: PCISIG_DOE_VENDOR_ID,
            data_object_type: DataObjectType::DoeDiscovery as u8,
            reserved_1: 0,
            length,
        }
    }

    pub fn decode(data: &[u32]) -> Result<Self, ErrorCode> {
        // Check if we have enough u32 words (struct is 8 bytes = 2 u32 words)
        if data.len() < DOE_DATA_OBJECT_HEADER_LEN_DW {
            return Err(ErrorCode::SIZE);
        }

        // Extract fields manually from u32 data
        // Assuming little-endian byte order
        let word0 = data[0];
        let word1 = data[1];

        let vendor_id = (word0 & 0xFFFF) as u16;
        let data_object_type = ((word0 >> 16) & 0xFF) as u8;
        let reserved_1 = ((word0 >> 24) & 0xFF) as u8;
        let length = word1 & LENGTH_MASK;

        Ok(Self {
            vendor_id,
            data_object_type,
            reserved_1,
            length,
        })
    }

    pub fn encode(&self, buf: &mut [u32]) -> Result<(), ErrorCode> {
        if buf.len() < DOE_DATA_OBJECT_HEADER_LEN_DW {
            return Err(ErrorCode::SIZE);
        }

        let word0 = (self.vendor_id as u32)
            | ((self.data_object_type as u32) << 16)
            | ((self.reserved_1 as u32) << 24);
        let word1 = (self.length) & LENGTH_MASK;

        buf[0] = word0;
        buf[1] = word1;
        Ok(())
    }

    pub fn data_object_type(&self) -> DataObjectType {
        DataObjectType::from(self.data_object_type)
    }

    pub fn validate(&self, received_len_dw: u32) -> bool {
        // Validate vendor ID
        if self.vendor_id != PCISIG_DOE_VENDOR_ID {
            return false;
        }

        // Validate data object type
        if self.data_object_type() == DataObjectType::Unsupported {
            return false;
        }

        // Validate reserved fields
        if self.reserved_1 != 0 {
            return false;
        }

        // If the length field doesn't match the data size received, silently discard the object
        if self.length < DOE_DISCOVERY_DATA_OBJECT_LEN_DW as u32 || received_len_dw != self.length {
            return false;
        }

        true
    }
}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable, PartialEq)]
    #[repr(C)]
    pub struct DoeDiscoveryRequest(u32);
    impl Debug;
    pub u8, index, _: 7, 0;
    u32, reserved_1, _: 31, 8;
}

impl DoeDiscoveryRequest {
    pub fn decode(data: u32) -> Self {
        Self(data)
    }
}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable, PartialEq)]
    #[repr(C)]
    pub struct DoeDiscoveryResponse(u32);
    impl Debug;
    pub u16, vendor_id, set_vendor_id: 15, 0;
    pub u8, data_object_protocol, set_data_object_protocol: 23, 16;
    pub u8, next_index, set_next_index: 31, 24;
}

impl DoeDiscoveryResponse {
    pub fn new(data_object_protocol: u8, next_index: u8) -> Self {
        let mut response = Self(0);
        response.set_vendor_id(PCISIG_DOE_VENDOR_ID);
        response.set_data_object_protocol(data_object_protocol);
        response.set_next_index(next_index);
        response
    }

    pub fn encode(&self, buf: &mut [u32]) -> Result<(), ErrorCode> {
        if buf.len() < DOE_DISCOVERY_REQ_RESP_LEN_DW {
            return Err(ErrorCode::SIZE);
        }

        buf[0] = self.0;
        Ok(())
    }
}
