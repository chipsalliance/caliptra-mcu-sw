use flash_image::mcu::McuImageHeader;



pub trait ImageVerifier {
    fn verify_header(&self, header: &McuImageHeader) -> bool;
}