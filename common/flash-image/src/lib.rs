// Licensed under the Apache-2.0 license
#![no_std]

use core::mem::offset_of;

use zerocopy::{byteorder::U32, FromBytes, Immutable, IntoBytes, KnownLayout};

pub const CALIPTRA_FMC_RT_IDENTIFIER: u32 = 0x00000000;
pub const SOC_MANIFEST_IDENTIFIER: u32 = 0x00000001;
pub const MCU_RT_IDENTIFIER: u32 = 0x00000002;
pub const SOC_IMAGES_BASE_IDENTIFIER: u32 = 0x00001000;

pub const FLASH_IMAGE_MAGIC_NUMBER: u32 = u32::from_be_bytes(*b"FLSH");
pub const HEADER_VERSION: u16 = 0x0001;

#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct FlashHeader {
    pub magic: U32<zerocopy::byteorder::BigEndian>,
    pub version: u16,
    pub image_count: u16,
    pub image_headers_offset: u32,
    pub header_checksum: u32,
}

impl FlashHeader {
    pub fn verify(&self) -> bool {
        if self.magic.get() != FLASH_IMAGE_MAGIC_NUMBER {
            return false;
        }
        if self.version != HEADER_VERSION {
            return false;
        }
        if self.image_count == 0 {
            return false;
        }
        if self.image_headers_offset < core::mem::size_of::<FlashHeader>() as u32 {
            return false;
        }

        0u32.wrapping_sub(
            self.as_bytes()[..offset_of!(FlashHeader, header_checksum)]
                .iter()
                .fold(0u32, |acc, &byte| acc.wrapping_add(byte as u32)),
        ) == self.header_checksum
    }
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

impl ImageHeader {
    pub fn verify(&self) -> bool {
        0u32.wrapping_sub(
            self.as_bytes()[..offset_of!(ImageHeader, image_header_checksum)]
                .iter()
                .fold(0u32, |acc, &byte| acc.wrapping_add(byte as u32)),
        ) == self.image_header_checksum
    }
}
