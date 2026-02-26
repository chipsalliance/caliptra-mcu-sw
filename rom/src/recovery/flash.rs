// Licensed under the Apache-2.0 license

//! This modules implements the ImageProvider trait for the flash based image load.

use zerocopy::FromBytes;

use crate::{flash_partition::FlashPartition, recovery::ImageProvider};
use flash_image::{
    FlashHeader, ImageHeader, CALIPTRA_FMC_RT_IDENTIFIER, MCU_RT_IDENTIFIER,
    SOC_MANIFEST_IDENTIFIER,
};

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
        // Get the maximum size between FlashHeader and ImageHeader
        // Use a buffer large enough for either header (FlashHeader or ImageHeader)
        const MAX_HEADER_SIZE: usize = {
            let flash_header_size = core::mem::size_of::<FlashHeader>();
            let image_header_size = core::mem::size_of::<ImageHeader>();
            if flash_header_size > image_header_size {
                flash_header_size
            } else {
                image_header_size
            }
        };
        let mut buf = [0u8; MAX_HEADER_SIZE];

        let image_id = recovery_img_index_to_image_id(image_index)?;

        // Read the flash header
        self.flash_driver
            .read(0, &mut buf[..core::mem::size_of::<FlashHeader>()])
            .map_err(|_| ())?;

        let flash_header =
            FlashHeader::ref_from_prefix(&buf[..core::mem::size_of::<FlashHeader>()])
                .map_err(|_| ())?
                .0;

        let image_count = flash_header.image_count;

        for i in 0..image_count as usize {
            // Read the image header
            let offset =
                core::mem::size_of::<FlashHeader>() + i * core::mem::size_of::<ImageHeader>();
            self.flash_driver
                .read(offset, &mut buf[..core::mem::size_of::<ImageHeader>()])
                .map_err(|_| ())?;
            let image_header =
                ImageHeader::ref_from_prefix(&buf[..core::mem::size_of::<ImageHeader>()])
                    .map_err(|_| ())?
                    .0;

            if image_header.identifier == image_id {
                // SAFETY: Since this will only run on a riscv32 processor u32 and usize are
                // identical.
                self.flash_offset = image_header.offset as usize;
                self.image_size = image_header.size as usize;
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
