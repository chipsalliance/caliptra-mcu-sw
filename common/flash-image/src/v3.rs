// Licensed under the Apache-2.0 license

use crate::{calculate_checksum, FlashHeader, FlashImageVersion, ImageHeader, MAX_FILENAME_LEN};
use core::mem::offset_of;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct FlashHeaderV3 {
    pub version: u16,
    pub image_count: u16,
    pub image_headers_offset: u32,
    pub header_checksum: u32,
}

impl FlashHeaderV3 {
    pub fn new(image_count: u16) -> Self {
        let mut header = Self {
            version: FlashImageVersion::V3 as u16,
            image_count,
            image_headers_offset: core::mem::size_of::<Self>() as u32,
            header_checksum: 0,
        };
        header.header_checksum =
            calculate_checksum(&header.as_bytes()[..offset_of!(Self, header_checksum)]);
        header
    }

    pub fn verify(&self) -> bool {
        self.version == FlashImageVersion::V3 as u16
            && self.image_count != 0
            && self.image_headers_offset >= core::mem::size_of::<Self>() as u32
            && calculate_checksum(&self.as_bytes()[..offset_of!(Self, header_checksum)])
                == self.header_checksum
    }
}

impl From<FlashHeaderV3> for FlashHeader {
    fn from(header: FlashHeaderV3) -> Self {
        Self {
            version: header.version,
            image_count: header.image_count,
            image_headers_offset: header.image_headers_offset,
        }
    }
}

#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, Clone, Copy, Immutable, KnownLayout)]
pub struct ImageHeaderV3 {
    pub identifier: u32,
    pub offset: u32,
    pub size: u32,
    pub filename: [u8; MAX_FILENAME_LEN],
    pub image_checksum: u32,
    pub image_header_checksum: u32,
}

impl ImageHeaderV3 {
    pub fn verify(&self) -> bool {
        calculate_checksum(&self.as_bytes()[..offset_of!(Self, image_header_checksum)])
            == self.image_header_checksum
    }
}

impl From<ImageHeaderV3> for ImageHeader {
    fn from(header: ImageHeaderV3) -> Self {
        Self {
            identifier: header.identifier,
            offset: header.offset,
            size: header.size,
            image_checksum: header.image_checksum,
        }
    }
}
