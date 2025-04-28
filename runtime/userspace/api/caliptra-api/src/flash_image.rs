// Licensed under the Apache-2.0 license

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct FlashHeader {
    pub magic: u32,
    pub version: u16,
    pub image_count: u16,
}

#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct FlashChecksums {
    pub header_crc32: u32,
    pub payload_crc32: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, Clone, Copy, Immutable, KnownLayout)]
pub struct ImageHeader {
    pub identifier: u32,
    pub offset: u32,
    pub size: u32,
}
