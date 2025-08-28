use mcu_rom_common::ImageVerifier;
use flash_image::mcu::McuImageHeader;


pub struct McuImageVerifier;

impl ImageVerifier for McuImageVerifier {
    fn verify_header(&self, header: &McuImageHeader) -> bool {
        if header.svn > 50 {
            return true;
        }
        false
    }
}