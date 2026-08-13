// Licensed under the Apache-2.0 license
#![no_std]

use core::mem::offset_of;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub const CALIPTRA_FMC_RT_IDENTIFIER: u32 = 0x00000000;
pub const SOC_MANIFEST_IDENTIFIER: u32 = 0x00000001;
pub const MCU_RT_IDENTIFIER: u32 = 0x00000002;
pub const SOC_IMAGES_BASE_IDENTIFIER: u32 = 0x00001000;
pub const MAX_FILENAME_LEN: usize = 64;

pub const HEADER_VERSION: u16 = 0x0003;

#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct FlashHeader {
    pub version: u16,
    pub image_count: u16,
    pub image_headers_offset: u32,
    pub header_checksum: u32,
}

impl FlashHeader {
    pub fn verify(&self) -> bool {
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
    pub filename: [u8; MAX_FILENAME_LEN],
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

#[cfg(test)]
mod tests {
    use super::*;

    fn flash_header(version: u16) -> FlashHeader {
        let mut header = FlashHeader {
            version,
            image_count: 1,
            image_headers_offset: core::mem::size_of::<FlashHeader>() as u32,
            header_checksum: 0,
        };
        header.header_checksum = 0u32.wrapping_sub(
            header.as_bytes()[..offset_of!(FlashHeader, header_checksum)]
                .iter()
                .fold(0u32, |acc, &byte| acc.wrapping_add(byte as u32)),
        );
        header
    }

    #[test]
    fn flash_header_verify_rejects_unsupported_version() {
        assert!(flash_header(HEADER_VERSION).verify());
        assert!(!flash_header(HEADER_VERSION - 1).verify());
    }
}
