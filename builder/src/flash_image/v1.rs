// Licensed under the Apache-2.0 license

use super::{encode_toc, generate_legacy_image_info, FirmwareImage};
use caliptra_mcu_flash_image::{FlashHeaderV1, FlashImageVersion, ImageHeaderV1V2};

pub struct FlashImageV1<'a> {
    header: FlashHeaderV1,
    image_info: Vec<ImageHeaderV1V2>,
    images: &'a [FirmwareImage<'a>],
}

impl<'a> FlashImageV1<'a> {
    pub fn new(images: &'a [FirmwareImage<'a>]) -> Self {
        Self {
            header: FlashHeaderV1::new(images.len() as u16),
            image_info: generate_legacy_image_info(images, FlashImageVersion::V1),
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
