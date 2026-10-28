// Licensed under the Apache-2.0 license
#![no_std]

use core::mem::offset_of;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

mod v1;
mod v2;
mod v3;

pub use v1::FlashHeaderV1;
pub use v2::FlashHeaderV2;
pub use v3::{FlashHeaderV3, ImageHeaderV3};

pub const CALIPTRA_FMC_RT_IDENTIFIER: u32 = 0x00000000;
pub const SOC_MANIFEST_IDENTIFIER: u32 = 0x00000001;
pub const MCU_RT_IDENTIFIER: u32 = 0x00000002;
pub const OWNER_AUTH_MANIFEST_IDENTIFIER: u32 = 0x00000003;
pub const V_AUTH_KEY_ID: u32 = 0x00000004;
pub const OWNER_MEASUREMENT_POLICY_IDENTIFIER: u32 = 0x00000005;
pub const O_AUTH_KEY_ID: u32 = 0x00000006;
pub const SOC_IMAGES_BASE_IDENTIFIER: u32 = 0x00001000;
/// Owner SoC images use identifiers `OWNER_SOC_IMAGES_BASE_IDENTIFIER..=u32::MAX`.
pub const OWNER_SOC_IMAGES_BASE_IDENTIFIER: u32 = 0x00010000;
pub const MAX_FILENAME_LEN: usize = 64;

pub const HEADER_VERSION: u16 = 0x0003;
pub const FLASH_IMAGE_MAGIC: [u8; 4] = *b"FLSH";
pub const MAX_FLASH_HEADER_SIZE: usize = core::mem::size_of::<FlashHeaderV1>();
pub const MAX_IMAGE_HEADER_SIZE: usize = core::mem::size_of::<ImageHeaderV3>();
pub const MIN_FLASH_IMAGE_SIZE: usize =
    core::mem::size_of::<FlashHeaderV2>() + core::mem::size_of::<ImageHeaderV1V2>();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlashImageError {
    UnsupportedVersion,
    Truncated,
    InvalidHeader,
    InvalidImageHeader,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum FlashImageVersion {
    V1 = 1,
    V2 = 2,
    #[default]
    V3 = 3,
}

impl TryFrom<u16> for FlashImageVersion {
    type Error = FlashImageError;

    fn try_from(version: u16) -> Result<Self, Self::Error> {
        match version {
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            3 => Ok(Self::V3),
            _ => Err(FlashImageError::UnsupportedVersion),
        }
    }
}

impl FlashImageVersion {
    pub const fn header_size(self) -> usize {
        match self {
            Self::V1 => core::mem::size_of::<FlashHeaderV1>(),
            Self::V2 => core::mem::size_of::<FlashHeaderV2>(),
            Self::V3 => core::mem::size_of::<FlashHeaderV3>(),
        }
    }

    pub const fn image_header_size(self) -> usize {
        match self {
            Self::V1 | Self::V2 => core::mem::size_of::<ImageHeaderV1V2>(),
            Self::V3 => core::mem::size_of::<ImageHeaderV3>(),
        }
    }

    /// Legacy ROMs do not report a version; the customer must select v1 or v2.
    pub fn supports_rom(self, rom_version: Option<u32>) -> bool {
        match rom_version {
            None => matches!(self, Self::V1 | Self::V2),
            Some(0x0201_0000) => self == Self::V2,
            // ROM 2.1.1 introduced the version handoff and requires v3 images.
            Some(0x0201_0001..=0x0201_ffff) => self == Self::V3,
            Some(_) => false,
        }
    }
}

pub fn calculate_checksum(data: &[u8]) -> u32 {
    0u32.wrapping_sub(
        data.iter()
            .fold(0u32, |sum, &byte| sum.wrapping_add(byte as u32)),
    )
}

/// Validated metadata, not a wire layout. Wire checksums are checked before conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlashHeader {
    pub version: u16,
    pub image_count: u16,
    pub image_headers_offset: u32,
}

impl FlashHeader {
    pub fn format(&self) -> Result<FlashImageVersion, FlashImageError> {
        self.version.try_into()
    }

    pub fn parse(data: &[u8]) -> Result<Self, FlashImageError> {
        macro_rules! decode {
            ($ty:ty) => {{
                let (header, _) =
                    <$ty>::read_from_prefix(data).map_err(|_| FlashImageError::Truncated)?;
                if !header.verify() {
                    return Err(FlashImageError::InvalidHeader);
                }
                Ok(header.into())
            }};
        }
        if data.starts_with(&FLASH_IMAGE_MAGIC) {
            return decode!(FlashHeaderV1);
        }
        let prefix = data.get(..2).ok_or(FlashImageError::Truncated)?;
        match u16::from_le_bytes([prefix[0], prefix[1]]) {
            2 => decode!(FlashHeaderV2),
            3 => decode!(FlashHeaderV3),
            _ => Err(FlashImageError::UnsupportedVersion),
        }
    }

    pub fn image_header_offset(&self, index: usize) -> Option<usize> {
        if index >= self.image_count as usize {
            return None;
        }
        let stride = self.format().ok()?.image_header_size();
        (self.image_headers_offset as usize).checked_add(index.checked_mul(stride)?)
    }

    pub fn table_end(&self) -> Option<usize> {
        let stride = self.format().ok()?.image_header_size();
        (self.image_headers_offset as usize)
            .checked_add((self.image_count as usize).checked_mul(stride)?)
    }
}

#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, Clone, Copy, Immutable, KnownLayout)]
pub struct ImageHeaderV1V2 {
    pub identifier: u32,
    pub offset: u32,
    pub size: u32,
    pub image_checksum: u32,
    pub image_header_checksum: u32,
}

impl ImageHeaderV1V2 {
    pub fn verify(&self) -> bool {
        calculate_checksum(&self.as_bytes()[..offset_of!(Self, image_header_checksum)])
            == self.image_header_checksum
    }
}

impl From<ImageHeaderV1V2> for ImageHeader {
    fn from(header: ImageHeaderV1V2) -> Self {
        Self {
            identifier: header.identifier,
            offset: header.offset,
            size: header.size,
            image_checksum: header.image_checksum,
        }
    }
}

/// Shared payload metadata; no filename or entry checksum is needed by firmware loaders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageHeader {
    pub identifier: u32,
    pub offset: u32,
    pub size: u32,
    pub image_checksum: u32,
}

impl ImageHeader {
    pub fn parse(data: &[u8], version: FlashImageVersion) -> Result<Self, FlashImageError> {
        macro_rules! decode {
            ($ty:ty) => {{
                let (header, _) =
                    <$ty>::read_from_prefix(data).map_err(|_| FlashImageError::Truncated)?;
                if !header.verify() {
                    return Err(FlashImageError::InvalidImageHeader);
                }
                Ok(header.into())
            }};
        }
        match version {
            FlashImageVersion::V1 | FlashImageVersion::V2 => decode!(ImageHeaderV1V2),
            FlashImageVersion::V3 => decode!(ImageHeaderV3),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_bytes(version: FlashImageVersion, count: u16) -> [u8; MAX_FLASH_HEADER_SIZE] {
        let mut bytes = [0; MAX_FLASH_HEADER_SIZE];
        let out = &mut bytes[..version.header_size()];
        match version {
            FlashImageVersion::V1 => out.copy_from_slice(FlashHeaderV1::new(count).as_bytes()),
            FlashImageVersion::V2 => out.copy_from_slice(FlashHeaderV2::new(count).as_bytes()),
            FlashImageVersion::V3 => out.copy_from_slice(FlashHeaderV3::new(count).as_bytes()),
        }
        bytes
    }

    #[test]
    fn flash_header_verify_rejects_unsupported_version() {
        let mut v1 = FlashHeaderV1::new(1);
        let mut v2 = FlashHeaderV2::new(1);
        let mut v3 = FlashHeaderV3::new(1);
        assert!(v1.verify() && v2.verify() && v3.verify());
        // Even with a valid checksum, each wire type accepts only its own version.
        v1.version = 2;
        v1.header_checksum = calculate_checksum(&v1.as_bytes()[..12]);
        v2.version = 3;
        v2.header_checksum = calculate_checksum(&v2.as_bytes()[..8]);
        v3.version = 2;
        v3.header_checksum = calculate_checksum(&v3.as_bytes()[..8]);
        assert!(!v1.verify() && !v2.verify() && !v3.verify());
        v1 = FlashHeaderV1::new(1);
        v1.magic = *b"BAD!";
        v1.header_checksum = calculate_checksum(&v1.as_bytes()[..12]);
        assert!(!v1.verify());
    }

    #[test]
    fn wire_layouts_and_checksums() {
        assert_eq!(size_of::<FlashHeaderV1>(), 16);
        assert_eq!(size_of::<FlashHeaderV2>(), 12);
        assert_eq!(size_of::<FlashHeaderV3>(), 12);
        assert_eq!(size_of::<ImageHeaderV1V2>(), 20);
        assert_eq!(size_of::<ImageHeaderV3>(), 84);
        assert_eq!(offset_of!(FlashHeaderV1, magic), 0);
        assert_eq!(offset_of!(FlashHeaderV1, version), 4);
        assert_eq!(offset_of!(FlashHeaderV1, header_checksum), 12);
        assert_eq!(offset_of!(FlashHeaderV2, header_checksum), 8);
        assert_eq!(offset_of!(FlashHeaderV3, header_checksum), 8);
        assert_eq!(offset_of!(ImageHeaderV1V2, image_checksum), 12);
        assert_eq!(offset_of!(ImageHeaderV3, filename), 12);
        assert_eq!(offset_of!(ImageHeaderV3, image_checksum), 76);
        for version in [
            FlashImageVersion::V1,
            FlashImageVersion::V2,
            FlashImageVersion::V3,
        ] {
            let bytes = header_bytes(version, 2);
            let size = version.header_size();
            let parsed = FlashHeader::parse(&bytes[..size]).unwrap();
            assert_eq!(parsed.version, version as u16);
            assert_eq!(
                parsed.image_header_offset(1),
                Some(size + version.image_header_size())
            );
            assert_eq!(
                parsed.table_end(),
                Some(size + 2 * version.image_header_size())
            );
            assert_eq!(parsed.image_header_offset(2), None);
            assert_eq!(
                calculate_checksum(&bytes[..size - 4]),
                u32::from_le_bytes(bytes[size - 4..size].try_into().unwrap())
            );
            for len in 0..size {
                assert!(FlashHeader::parse(&bytes[..len]).is_err());
            }
            for index in 0..size {
                let mut corrupt = bytes;
                corrupt[index] ^= 1;
                assert!(FlashHeader::parse(&corrupt[..size]).is_err());
            }

            let mut image = ImageHeaderV3 {
                identifier: 2,
                offset: 256,
                size: 128,
                filename: [b'x'; 64],
                image_checksum: 42,
                image_header_checksum: 0,
            };
            image.image_header_checksum = calculate_checksum(
                &image.as_bytes()[..offset_of!(ImageHeaderV3, image_header_checksum)],
            );
            let mut legacy = ImageHeaderV1V2 {
                identifier: image.identifier,
                offset: image.offset,
                size: image.size,
                image_checksum: image.image_checksum,
                image_header_checksum: 0,
            };
            legacy.image_header_checksum = calculate_checksum(
                &legacy.as_bytes()[..offset_of!(ImageHeaderV1V2, image_header_checksum)],
            );
            assert!(legacy.verify() && image.verify());
            let mut bytes = [0; MAX_IMAGE_HEADER_SIZE];
            let size = version.image_header_size();
            bytes[..size].copy_from_slice(if version == FlashImageVersion::V3 {
                image.as_bytes()
            } else {
                legacy.as_bytes()
            });
            let parsed = ImageHeader::parse(&bytes[..size], version).unwrap();
            assert_eq!(parsed.identifier, 2);
            assert_eq!(parsed.offset, 256);
            assert_eq!(parsed.size, 128);
            assert_eq!(parsed.image_checksum, 42);
            for len in 0..size {
                assert!(ImageHeader::parse(&bytes[..len], version).is_err());
            }
            for index in 0..size {
                let mut corrupt = bytes;
                corrupt[index] ^= 1;
                assert!(ImageHeader::parse(&corrupt[..size], version).is_err());
            }
        }
    }

    #[test]
    fn v1_requires_magic_and_matching_version() {
        let mut bytes = header_bytes(FlashImageVersion::V1, 1);
        assert!(FlashHeader::parse(&bytes[4..]).is_err());
        assert_eq!(&bytes[..4], b"FLSH");
        bytes[4] = 2;
        assert!(FlashHeader::parse(&bytes).is_err());
        bytes[4..].copy_from_slice(FlashHeaderV2::new(1).as_bytes());
        assert!(FlashHeader::parse(&bytes).is_err());
    }

    #[test]
    fn validates_header_bounds_and_preserves_table_offset() {
        let mut header = FlashHeaderV1::new(2);
        header.image_headers_offset = 64;
        header.header_checksum = calculate_checksum(&header.as_bytes()[..12]);
        let parsed = FlashHeader::parse(header.as_bytes()).unwrap();
        assert_eq!(parsed.image_header_offset(1), Some(84));
        assert_eq!(parsed.table_end(), Some(104));
        header.image_headers_offset = 12;
        header.header_checksum = calculate_checksum(&header.as_bytes()[..12]);
        assert!(!header.verify());
        let mut header = FlashHeaderV3::new(0);
        assert!(!header.verify());
        header.image_count = 1;
        header.image_headers_offset = 8;
        header.header_checksum = calculate_checksum(&header.as_bytes()[..8]);
        assert!(!header.verify());
    }

    #[test]
    fn decodes_legacy_wire_fixtures() {
        let v1 = [
            b'F', b'L', b'S', b'H', 1, 0, 1, 0, 16, 0, 0, 0, 0xc1, 0xfe, 0xff, 0xff,
        ];
        let header = FlashHeader::parse(&v1).unwrap();
        assert_eq!(header.version, 1);
        assert_eq!(header.image_header_offset(0), Some(16));
        let v2 = [2, 0, 1, 0, 12, 0, 0, 0, 0xf1, 0xff, 0xff, 0xff];
        let header = FlashHeader::parse(&v2).unwrap();
        assert_eq!(header.version, 2);
        assert_eq!(header.image_header_offset(0), Some(12));
        let entry = [
            2, 0, 0, 0, 36, 0, 0, 0, 4, 0, 0, 0, 0xf6, 0xff, 0xff, 0xff, 0xe3, 0xfb, 0xff, 0xff,
        ];
        let image = ImageHeader::parse(&entry, FlashImageVersion::V1).unwrap();
        assert_eq!(image.offset, 36);
        assert_eq!(image.image_checksum, calculate_checksum(&[1, 2, 3, 4]));
        assert!(ImageHeader::parse(&entry, FlashImageVersion::V2).is_ok());
    }

    #[test]
    fn rom_compatibility_policy() {
        for version in [
            FlashImageVersion::V1,
            FlashImageVersion::V2,
            FlashImageVersion::V3,
        ] {
            assert_eq!(version.supports_rom(None), version != FlashImageVersion::V3);
            assert_eq!(
                version.supports_rom(Some(0x0201_0000)),
                version == FlashImageVersion::V2
            );
            assert_eq!(
                version.supports_rom(Some(0x0201_0001)),
                version == FlashImageVersion::V3
            );
            assert_eq!(
                version.supports_rom(Some(0x0201_0002)),
                version == FlashImageVersion::V3
            );
            assert!(!version.supports_rom(Some(0)));
            assert!(!version.supports_rom(Some(0x0300_0000)));
        }
    }
}
