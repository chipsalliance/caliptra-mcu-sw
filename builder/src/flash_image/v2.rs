// Licensed under the Apache-2.0 license

use super::{encode_toc, generate_legacy_image_info, FirmwareImage};
use caliptra_mcu_flash_image::{FlashHeaderV2, FlashImageVersion, ImageHeaderV1V2};

pub struct FlashImageV2<'a> {
    header: FlashHeaderV2,
    image_info: Vec<ImageHeaderV1V2>,
    images: &'a [FirmwareImage<'a>],
}

impl<'a> FlashImageV2<'a> {
    pub fn new(images: &'a [FirmwareImage<'a>]) -> Self {
        Self {
            header: FlashHeaderV2::new(images.len() as u16),
            image_info: generate_legacy_image_info(images, FlashImageVersion::V2),
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
