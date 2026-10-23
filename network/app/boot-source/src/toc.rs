// Licensed under the Apache-2.0 license

//! Table of Contents (TOC) management.
//!
//! Maps firmware IDs to filenames and metadata obtained from the
//! boot configuration file downloaded via TFTP.
//!
//! The TOC binary format reuses the flash image layout defined in the
//! `flash-image` crate: a [`FlashHeaderV3`] followed by [`ImageHeaderV3`]
//! entries.

use caliptra_mcu_flash_image::{FlashHeaderV3, ImageHeaderV3, MAX_FILENAME_LEN};
use zerocopy::FromBytes;

/// Maximum number of firmware images in the TOC.
pub const MAX_TOC_ENTRIES: usize = 8;

/// A single entry mapping a firmware ID to its TFTP filename and metadata.
#[derive(Clone)]
pub struct TocEntry {
    pub firmware_id: u8,
    pub filename: [u8; MAX_FILENAME_LEN],
    pub filename_len: usize,
    pub image_size: u32,
    pub image_checksum: u32,
}

impl Default for TocEntry {
    fn default() -> Self {
        Self {
            firmware_id: 0,
            filename: [0u8; MAX_FILENAME_LEN],
            filename_len: 0,
            image_size: 0,
            image_checksum: 0,
        }
    }
}

/// Fixed-capacity table of firmware image entries.
pub struct Toc {
    entries: [TocEntry; MAX_TOC_ENTRIES],
    count: usize,
}

impl Default for Toc {
    fn default() -> Self {
        Self::new()
    }
}

impl Toc {
    pub const fn new() -> Self {
        Self {
            entries: [const {
                TocEntry {
                    firmware_id: 0,
                    filename: [0u8; MAX_FILENAME_LEN],
                    filename_len: 0,
                    image_size: 0,
                    image_checksum: 0,
                }
            }; MAX_TOC_ENTRIES],
            count: 0,
        }
    }

    /// Add an entry to the TOC. Returns `false` if the table is full.
    pub fn add(
        &mut self,
        firmware_id: u8,
        filename: &[u8],
        image_size: u32,
        image_checksum: u32,
    ) -> bool {
        if self.count >= MAX_TOC_ENTRIES || filename.is_empty() {
            return false;
        }
        let fname_len = filename.len().min(MAX_FILENAME_LEN - 1);
        let entry = &mut self.entries[self.count];
        entry.firmware_id = firmware_id;
        entry.filename[..fname_len].copy_from_slice(&filename[..fname_len]);
        entry.filename[fname_len] = 0;
        entry.filename_len = fname_len;
        entry.image_size = image_size;
        entry.image_checksum = image_checksum;
        self.count += 1;
        true
    }

    /// Look up an entry by firmware ID.
    pub fn find(&self, firmware_id: u8) -> Option<&TocEntry> {
        self.entries[..self.count]
            .iter()
            .find(|e| e.firmware_id == firmware_id)
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.count = 0;
    }

    pub fn count(&self) -> usize {
        self.count
    }

    /// Parse a raw TOC buffer in flash-image format and populate the table.
    ///
    /// The buffer must contain a valid [`FlashHeaderV3`] followed by
    /// [`ImageHeaderV3`] entries.  Each image header's `identifier` is
    /// mapped to `firmware_id` (truncated to `u8`) and its `filename`
    /// field provides the TFTP path.
    ///
    /// Returns `true` if parsing succeeded.
    pub fn parse(&mut self, data: &[u8]) -> bool {
        self.count = 0;

        let header_size = core::mem::size_of::<FlashHeaderV3>();
        let image_header_size = core::mem::size_of::<ImageHeaderV3>();

        if data.len() < header_size {
            return false;
        }

        let header = match FlashHeaderV3::ref_from_bytes(&data[..header_size]) {
            Ok(h) => h,
            Err(_) => return false,
        };

        // Network boot requires the filenames introduced in v3.
        if !header.verify() {
            return false;
        }

        let count = header.image_count as usize;
        let base = header.image_headers_offset as usize;

        for i in 0..count {
            if self.count >= MAX_TOC_ENTRIES {
                break;
            }
            let offset = base + i * image_header_size;
            let end = offset + image_header_size;
            if end > data.len() {
                return false;
            }

            let img_hdr = match ImageHeaderV3::ref_from_bytes(&data[offset..end]) {
                Ok(h) => h,
                Err(_) => return false,
            };

            if !img_hdr.verify() {
                return false;
            }

            // Determine filename length (up to first NUL or max).
            let fname_len = img_hdr
                .filename
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(img_hdr.filename.len());

            let entry = &mut self.entries[self.count];
            entry.firmware_id = img_hdr.identifier as u8;
            entry.filename[..fname_len].copy_from_slice(&img_hdr.filename[..fname_len]);
            if fname_len < MAX_FILENAME_LEN {
                entry.filename[fname_len] = 0;
            }
            entry.filename_len = fname_len;
            entry.image_size = img_hdr.size;
            entry.image_checksum = img_hdr.image_checksum;
            self.count += 1;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_mcu_flash_image::{
        calculate_checksum, FlashHeaderV1, FlashHeaderV2, FlashImageVersion,
    };
    use zerocopy::IntoBytes;

    #[test]
    fn network_toc_requires_v3_filenames() {
        for version in [
            FlashImageVersion::V1,
            FlashImageVersion::V2,
            FlashImageVersion::V3,
        ] {
            let mut bytes = [0; 128];
            let out = &mut bytes[..version.header_size()];
            match version {
                FlashImageVersion::V1 => out.copy_from_slice(FlashHeaderV1::new(1).as_bytes()),
                FlashImageVersion::V2 => out.copy_from_slice(FlashHeaderV2::new(1).as_bytes()),
                FlashImageVersion::V3 => out.copy_from_slice(FlashHeaderV3::new(1).as_bytes()),
            }
            let mut toc = Toc::new();
            if version != FlashImageVersion::V3 {
                assert!(!toc.parse(&bytes));
                continue;
            }
            let mut image = ImageHeaderV3 {
                identifier: 2,
                offset: 128,
                size: 4,
                filename: [0; MAX_FILENAME_LEN],
                image_checksum: 0,
                image_header_checksum: 0,
            };
            image.filename[..7].copy_from_slice(b"mcu.bin");
            image.image_header_checksum = calculate_checksum(&image.as_bytes()[..80]);
            bytes[12..96].copy_from_slice(image.as_bytes());
            assert!(toc.parse(&bytes));
            assert_eq!(toc.find(2).unwrap().filename_len, 7);
        }
    }
}
