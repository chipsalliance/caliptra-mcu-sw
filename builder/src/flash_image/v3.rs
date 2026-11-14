// Licensed under the Apache-2.0 license

use super::{calculate_checksum, encode_toc, FirmwareImage};
use caliptra_mcu_flash_image::{FlashHeaderV3, ImageHeaderV3};
use std::mem::offset_of;
use zerocopy::IntoBytes;

pub struct FlashImageV3<'a> {
    header: FlashHeaderV3,
    image_info: Vec<ImageHeaderV3>,
    images: &'a [FirmwareImage<'a>],
}

impl<'a> FlashImageV3<'a> {
    pub fn new(images: &'a [FirmwareImage<'a>], image_info: &[ImageHeaderV3]) -> Self {
        Self {
            header: FlashHeaderV3::new(image_info.len() as u16),
            image_info: image_info.to_vec(),
            images,
        }
    }

    pub(super) fn to_toc_bytes(&self) -> Vec<u8> {
        encode_toc(&self.header, &self.image_info)
    }

    pub(super) fn images(&self) -> &'a [FirmwareImage<'a>] {
        self.images
    }
}

pub fn generate_image_info(images: Vec<FirmwareImage>) -> Vec<ImageHeaderV3> {
    let mut info = Vec::new();
    let mut offset =
        (size_of::<FlashHeaderV3>() + size_of::<ImageHeaderV3>() * images.len()) as u32;
    for image in &images {
        let mut header = ImageHeaderV3 {
            identifier: image.identifier,
            offset,
            size: image.data.len() as u32,
            filename: image.filename,
            image_checksum: calculate_checksum(image.data),
            image_header_checksum: 0,
        };
        header.image_header_checksum = calculate_checksum(
            &header.as_bytes()[..offset_of!(ImageHeaderV3, image_header_checksum)],
        );
        info.push(header);
        offset += image.data.len() as u32;
    }
    info
}
