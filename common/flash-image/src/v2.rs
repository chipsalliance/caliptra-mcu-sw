// Licensed under the Apache-2.0 license

use crate::{calculate_checksum, FlashHeader, FlashImageVersion};
use core::mem::offset_of;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct FlashHeaderV2 {
    pub version: u16,
    pub image_count: u16,
    pub image_headers_offset: u32,
    pub header_checksum: u32,
}

impl FlashHeaderV2 {
    pub fn new(image_count: u16) -> Self {
        let mut header = Self {
            version: FlashImageVersion::V2 as u16,
            image_count,
            image_headers_offset: core::mem::size_of::<Self>() as u32,
            header_checksum: 0,
        };
        header.header_checksum =
            calculate_checksum(&header.as_bytes()[..offset_of!(Self, header_checksum)]);
        header
    }

    pub fn verify(&self) -> bool {
        self.version == FlashImageVersion::V2 as u16
            && self.image_count != 0
            && self.image_headers_offset >= core::mem::size_of::<Self>() as u32
            && calculate_checksum(&self.as_bytes()[..offset_of!(Self, header_checksum)])
                == self.header_checksum
    }
}

impl From<FlashHeaderV2> for FlashHeader {
    fn from(header: FlashHeaderV2) -> Self {
        Self {
            version: header.version,
            image_count: header.image_count,
            image_headers_offset: header.image_headers_offset,
        }
    }
}
