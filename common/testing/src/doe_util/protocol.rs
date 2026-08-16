// Licensed under the Apache-2.0 license

use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub const DOE_DATA_OBJECT_HEADER_LEN: usize = 8; // 8 bytes, 2 dwords
pub const DOE_DISCOVERY_REQ_RESP_LEN: usize = 4; // 4 bytes, 1 dword
const PCISIG_DOE_VENDOR_ID: u16 = 0x0001;
const LENGTH_FIELD_BITS: u32 = 18;
const LENGTH_MASK: u32 = (1 << LENGTH_FIELD_BITS) - 1;

/// Vendor ID reported in a DOE Discovery Response when there is no Data Object
/// Protocol associated with the requested index.
pub const UNSUPPORTED_VENDOR_ID: u16 = 0xFFFF;

/// DOE Discovery Version used when the DOE Extended Capability Version is 01h.
pub const DOE_DISCOVERY_VERSION_LEGACY: u8 = 0x00;

/// DOE Discovery Version required when the DOE Extended Capability Version is
/// 02h or greater.
pub const DOE_DISCOVERY_VERSION_2: u8 = 0x02;

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
pub enum DataObjectType {
    DoeDiscovery = 0,
    DoeSpdm = 1,
    DoeSecureSpdm = 2,
    Unsupported,
}

bitfield! {
    #[repr(C)]
    #[derive(Clone, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq)]
    pub struct DoeHeader([u8]);
    impl Debug;
    pub u16, vendor_id, set_vendor_id: 15, 0;
    pub u8, data_object_type, set_data_object_type: 23, 16;
    u8, reserved_1, _: 31, 24;
    u32, length, set_length: 49, 32;
    u16, reserved2, _ : 63, 50;
}

impl From<u8> for DataObjectType {
    fn from(value: u8) -> Self {
        match value {
            0x00 => DataObjectType::DoeDiscovery,
            0x01 => DataObjectType::DoeSpdm,
            0x02 => DataObjectType::DoeSecureSpdm,
            _ => DataObjectType::Unsupported,
        }
    }
}

impl Default for DoeHeader<[u8; DOE_DATA_OBJECT_HEADER_LEN]> {
    fn default() -> Self {
        Self([0; DOE_DATA_OBJECT_HEADER_LEN])
    }
}

impl DoeHeader<[u8; DOE_DATA_OBJECT_HEADER_LEN]> {
    pub fn new(object_id: DataObjectType, length: u32) -> Self {
        let len_dw = length / 4; // Convert bytes to dwords
        let mut header = Self::default();
        header.set_vendor_id(PCISIG_DOE_VENDOR_ID);
        header.set_data_object_type(object_id as u8);
        header.set_length(len_dw & LENGTH_MASK);
        header
    }
}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable, PartialEq)]
    #[repr(C)]
    pub struct DoeDiscoveryRequest([u8]);
    impl Debug;
    pub u8, index, set_index: 7, 0;
    pub u8, version, set_version: 15, 8;
    u16, reserved_1, _: 31, 16;
}

impl Default for DoeDiscoveryRequest<[u8; DOE_DISCOVERY_REQ_RESP_LEN]> {
    fn default() -> Self {
        Self([0; DOE_DISCOVERY_REQ_RESP_LEN])
    }
}

impl DoeDiscoveryRequest<[u8; DOE_DISCOVERY_REQ_RESP_LEN]> {
    pub fn new(index: u8) -> Self {
        Self::new_with_version(index, DOE_DISCOVERY_VERSION_LEGACY)
    }

    pub fn new_with_version(index: u8, version: u8) -> Self {
        let mut req = Self::default();
        req.set_index(index);
        req.set_version(version);
        req
    }
}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable, PartialEq)]
    #[repr(C)]
    pub struct DoeDiscoveryResponse([u8]);
    impl Debug;
    pub u16, vendor_id, set_vendor_id: 15, 0;
    pub u8, data_object_protocol, set_data_object_protocol: 23, 16;
    pub u8, next_index, set_next_index: 31, 24;
}

impl Default for DoeDiscoveryResponse<[u8; DOE_DISCOVERY_REQ_RESP_LEN]> {
    fn default() -> Self {
        Self([0; DOE_DISCOVERY_REQ_RESP_LEN])
    }
}

impl DoeDiscoveryResponse<[u8; DOE_DISCOVERY_REQ_RESP_LEN]> {
    pub fn new(data_object_protocol: u8, next_index: u8) -> Self {
        let mut response = Self::default();
        response.set_vendor_id(PCISIG_DOE_VENDOR_ID);
        response.set_data_object_protocol(data_object_protocol);
        response.set_next_index(next_index);
        response
    }

    /// Response expected when the requested index is out of range or the DOE
    /// Discovery Version is not supported.
    pub fn unsupported() -> Self {
        let mut response = Self::default();
        response.set_vendor_id(UNSUPPORTED_VENDOR_ID);
        response
    }
}
