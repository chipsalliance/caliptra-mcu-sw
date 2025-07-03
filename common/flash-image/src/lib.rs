// Licensed under the Apache-2.0 license
#![no_std]

use zerocopy::{byteorder::U32, FromBytes, Immutable, IntoBytes, KnownLayout};

pub const FLASH_IMAGE_MAGIC_NUMBER: u32 = u32::from_be_bytes(*b"FLSH");
pub const HEADER_VERSION: u16 = 0x0001;

#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct FlashHeader {
    pub magic: U32<zerocopy::byteorder::BigEndian>,
    pub version: u16,
    pub image_count: u16,
    pub image_headers_offset: u32,
    pub header_crc32: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, Clone, Copy, Immutable, KnownLayout)]
pub struct ImageHeader {
    pub identifier: u32,
    pub offset: u32,
    pub size: u32,
    pub image_checksum: u32,
    pub image_header_checksum: u32,
}
