// Licensed under the Apache-2.0 license

//! This modules implements the ImageProvider trait for the flash based image load.

use crate::{flash_partition::FlashPartition, recovery::ImageProvider};
use caliptra_mcu_flash_image::{
    FlashHeaderV3, ImageHeaderV3, CALIPTRA_FMC_RT_IDENTIFIER, MCU_RT_IDENTIFIER,
    SOC_MANIFEST_IDENTIFIER,
};
use zerocopy::FromBytes;

/// An image provider over the flash driver.  It provides a mechanism for retrieving an image to the
/// i3c bypass recovery logic.
pub struct FlashImageProvider<'a> {
    /// The driver to load the flash with.
    flash_driver: &'a mut FlashPartition<'a>,

    /// The offset within the flash partition the image starts at.
    flash_offset: usize,

    /// The size of the image.
    image_size: usize,

    /// The current offset within the image which has been loaded.  This is used to keep track of
    /// what location to return within the flash storage.
    current_offset: usize,
}

impl<'a> FlashImageProvider<'a> {
    /// Create a new FlashImageProvider.
    pub fn new(flash_driver: &'a mut FlashPartition<'a>) -> Self {
        Self {
            flash_driver,
            flash_offset: 0,
            image_size: 0,
            current_offset: 0,
        }
    }
}

impl ImageProvider for FlashImageProvider<'_> {
    fn image_ready(&mut self, image_index: u32) -> Result<usize, ()> {
        const HEADER_SIZE: usize = core::mem::size_of::<FlashHeaderV3>();
        const IMAGE_HEADER_SIZE: usize = core::mem::size_of::<ImageHeaderV3>();
        let mut buf = [0u8; IMAGE_HEADER_SIZE];

        let image_id = recovery_img_index_to_image_id(image_index)?;

        // Read the flash header
        self.flash_driver
            .read(0, &mut buf[..HEADER_SIZE])
            .map_err(|_| ())?;

        let flash_header = FlashHeaderV3::read_from_bytes(&buf[..HEADER_SIZE]).map_err(|_| {
            caliptra_mcu_romtime::println!("[mcu-rom] Invalid flash header");
        })?;
        if !flash_header.verify() {
            caliptra_mcu_romtime::println!(
                "[mcu-rom] Invalid or unsupported flash header version {}",
                flash_header.version
            );
            return Err(());
        }

        let image_count = flash_header.image_count as usize;
        let table_offset = flash_header.image_headers_offset as usize;
        let table_end = image_count
            .checked_mul(IMAGE_HEADER_SIZE)
            .and_then(|size| table_offset.checked_add(size))
            .filter(|end| *end <= self.flash_driver.len())
            .ok_or_else(|| {
                caliptra_mcu_romtime::println!("[mcu-rom] Flash image table exceeds partition");
            })?;

        for i in 0..image_count {
            // Read the image header
            let offset = table_offset + i * IMAGE_HEADER_SIZE;
            self.flash_driver.read(offset, &mut buf).map_err(|_| ())?;
            let image_header = ImageHeaderV3::read_from_bytes(&buf).map_err(|_| {
                caliptra_mcu_romtime::println!("[mcu-rom] Invalid flash image entry");
            })?;
            if !image_header.verify() {
                caliptra_mcu_romtime::println!("[mcu-rom] Invalid flash image entry checksum");
                return Err(());
            }

            if image_header.identifier == image_id {
                let image_offset = image_header.offset as usize;
                let image_size = image_header.size as usize;
                image_offset
                    .checked_add(image_size)
                    .filter(|end| image_offset >= table_end && *end <= self.flash_driver.len())
                    .ok_or_else(|| {
                        caliptra_mcu_romtime::println!(
                            "[mcu-rom] Flash image payload outside partition"
                        );
                    })?;
                self.flash_offset = image_offset;
                self.image_size = image_size;
                self.current_offset = 0;
                return Ok(self.image_size);
            }
        }

        Err(())
    }

    fn next_bytes(&mut self, data: &mut [u8]) -> Result<(), ()> {
        let data_to_retrieve = data.len().min(self.image_size - self.current_offset);
        self.flash_driver
            .read(
                self.flash_offset + self.current_offset,
                data.get_mut(..data_to_retrieve).ok_or(())?,
            )
            .map_err(|_| ())?;

        self.current_offset += data_to_retrieve;
        Ok(())
    }

    fn bytes_loaded(&self) -> usize {
        self.current_offset
    }
}

fn recovery_img_index_to_image_id(recovery_image_index: u32) -> Result<u32, ()> {
    // Convert the recovery image index to the image ID
    match recovery_image_index {
        0 => Ok(CALIPTRA_FMC_RT_IDENTIFIER),
        1 => Ok(SOC_MANIFEST_IDENTIFIER),
        2 => Ok(MCU_RT_IDENTIFIER),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flash::hil::{FlashDrvError, FlashStorage};
    use caliptra_mcu_flash_image::{
        calculate_checksum, FlashHeaderV1, FlashHeaderV2, FlashImageVersion,
    };
    use core::mem::offset_of;
    use zerocopy::IntoBytes;

    struct Storage([u8; 256]);

    impl FlashStorage for Storage {
        fn read(&self, buffer: &mut [u8], address: usize) -> Result<(), FlashDrvError> {
            let bytes = self
                .0
                .get(address..address + buffer.len())
                .ok_or(FlashDrvError::SIZE)?;
            buffer.copy_from_slice(bytes);
            Ok(())
        }

        fn write(&self, _: &[u8], _: usize) -> Result<(), FlashDrvError> {
            Err(FlashDrvError::NOSUPPORT)
        }

        fn erase(&self, _: usize, _: usize) -> Result<(), FlashDrvError> {
            Err(FlashDrvError::NOSUPPORT)
        }

        fn capacity(&self) -> usize {
            self.0.len()
        }
    }

    fn storage_with_v3_image(
        image_count: u16,
        table_offset: u32,
        image_offset: u32,
        image_size: u32,
    ) -> Storage {
        let mut storage = Storage([0; 256]);
        let mut header = FlashHeaderV3::new(image_count);
        header.image_headers_offset = table_offset;
        header.header_checksum =
            calculate_checksum(&header.as_bytes()[..offset_of!(FlashHeaderV3, header_checksum)]);
        assert!(header.verify());
        storage.0[..size_of::<FlashHeaderV3>()].copy_from_slice(header.as_bytes());
        let mut image = ImageHeaderV3 {
            identifier: MCU_RT_IDENTIFIER,
            offset: image_offset,
            size: image_size,
            filename: [0; 64],
            image_checksum: 0,
            image_header_checksum: 0,
        };
        image.image_header_checksum = calculate_checksum(
            &image.as_bytes()[..offset_of!(ImageHeaderV3, image_header_checksum)],
        );
        assert!(image.verify());
        let offset = table_offset as usize;
        if offset <= storage.0.len() - size_of::<ImageHeaderV3>() {
            storage.0[offset..offset + size_of::<ImageHeaderV3>()]
                .copy_from_slice(image.as_bytes());
        }
        storage
    }

    #[test]
    fn rom_rejects_complete_table_outside_partition() {
        for (image_count, table_offset, partition_len) in [
            (3, 12, 256),
            (2, 12, 176),
            (1, 200, 256),
            (1, u32::MAX - 3, 256),
            (u16::MAX, 12, 256),
        ] {
            let storage = storage_with_v3_image(image_count, table_offset, 192, 4);
            let mut partition = FlashPartition::new(&storage, "test", 0, partition_len).unwrap();
            let mut provider = FlashImageProvider::new(&mut partition);
            assert!(provider.image_ready(2).is_err());
        }
    }

    #[test]
    fn rom_rejects_payload_outside_partition_or_overlapping_table() {
        for (image_offset, image_size) in [(95, 4), (192, 65), (u32::MAX - 3, 8), (192, u32::MAX)] {
            let storage = storage_with_v3_image(1, 12, image_offset, image_size);
            let mut partition = FlashPartition::new(&storage, "test", 0, 256).unwrap();
            let mut provider = FlashImageProvider::new(&mut partition);
            assert!(provider.image_ready(2).is_err());
        }
    }

    #[test]
    fn rom_accepts_payload_at_table_and_partition_boundaries() {
        for (table_offset, image_offset, partition_len) in [(12, 96, 100), (168, 252, 256)] {
            let storage = storage_with_v3_image(1, table_offset, image_offset, 4);
            let mut partition = FlashPartition::new(&storage, "test", 0, partition_len).unwrap();
            let mut provider = FlashImageProvider::new(&mut partition);
            assert_eq!(provider.image_ready(2), Ok(4));
            let mut bytes = [0xff; 8];
            provider.next_bytes(&mut bytes).unwrap();
            assert_eq!(provider.bytes_loaded(), 4);
            assert_eq!(bytes, [0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
        }
    }

    #[test]
    fn rom_accepts_only_v3() {
        for version in [
            FlashImageVersion::V1,
            FlashImageVersion::V2,
            FlashImageVersion::V3,
        ] {
            let mut storage = Storage([0; 256]);
            let out = &mut storage.0[..version.header_size()];
            match version {
                FlashImageVersion::V1 => out.copy_from_slice(FlashHeaderV1::new(2).as_bytes()),
                FlashImageVersion::V2 => out.copy_from_slice(FlashHeaderV2::new(2).as_bytes()),
                FlashImageVersion::V3 => out.copy_from_slice(FlashHeaderV3::new(2).as_bytes()),
            }
            if version != FlashImageVersion::V3 {
                let mut partition = FlashPartition::new(&storage, "test", 0, 256).unwrap();
                let mut provider = FlashImageProvider::new(&mut partition);
                assert!(provider.image_ready(2).is_err());
                continue;
            }
            for index in 0..2 {
                let mut image = ImageHeaderV3 {
                    identifier: if index == 0 {
                        CALIPTRA_FMC_RT_IDENTIFIER
                    } else {
                        MCU_RT_IDENTIFIER
                    },
                    offset: 192 + index as u32 * 4,
                    size: 4,
                    filename: [0; 64],
                    image_checksum: calculate_checksum(&[1, 2, 3, 4]),
                    image_header_checksum: 0,
                };
                image.image_header_checksum = calculate_checksum(&image.as_bytes()[..80]);
                let offset = version.header_size() + index * version.image_header_size();
                storage.0[offset..offset + size_of::<ImageHeaderV3>()]
                    .copy_from_slice(image.as_bytes());
            }
            storage.0[196..200].copy_from_slice(&[1, 2, 3, 4]);
            let mut partition = FlashPartition::new(&storage, "test", 0, 256).unwrap();
            let mut provider = FlashImageProvider::new(&mut partition);
            assert_eq!(provider.image_ready(2), Ok(4));
            let mut bytes = [0; 4];
            provider.next_bytes(&mut bytes).unwrap();
            assert_eq!(bytes, [1, 2, 3, 4]);
        }
    }

    #[test]
    fn rom_rejects_corrupt_header() {
        let mut storage = Storage([0; 256]);
        storage.0[..size_of::<FlashHeaderV3>()].copy_from_slice(FlashHeaderV3::new(1).as_bytes());
        storage.0[8] ^= 1;
        let mut partition = FlashPartition::new(&storage, "test", 0, 256).unwrap();
        let mut provider = FlashImageProvider::new(&mut partition);
        assert!(provider.image_ready(2).is_err());
    }
}
