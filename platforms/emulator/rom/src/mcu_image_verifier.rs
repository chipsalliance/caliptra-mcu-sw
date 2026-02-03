// Licensed under the Apache-2.0 license

use mcu_rom_common::ImageVerifier;
use romtime::otp::Otp;

pub struct McuImageVerifier;

impl ImageVerifier for McuImageVerifier {
    fn verify_header(&self, _header: &[u8], _otp: &Otp) -> bool {
        // TODO: make this unconditional and use proper fuses for it instead of test fuses
        #[cfg(any(feature = "test-mcu-svn-gt-fuse", feature = "test-mcu-svn-lt-fuse"))]
        {
            use mcu_image_header::McuImageHeader;
            use zerocopy::FromBytes;
            let Ok((header, _)) = McuImageHeader::ref_from_prefix(_header) else {
                romtime::println!("[mcu-rom] Invalid MCU image header");
                return false;
            };

            // Read vendor test partition first 16 bytes word by word
            let mut fuse_vendor_svn: u16 = 0;
            for word_idx in 0..4 {
                let Ok(word) = _otp.read_vendor_test_word(word_idx) else {
                    romtime::println!("[mcu-rom] Error reading vendor test fuse");
                    return false;
                };
                // Process each byte in the word
                for byte_idx in 0..4 {
                    let byte = ((word >> (byte_idx * 8)) & 0xFF) as u8;
                    // Count contiguous 1's in the byte
                    let mut count = 0;
                    for bit in 0..8 {
                        if byte & (1 << bit) != 0 {
                            count += 1;
                        } else {
                            break;
                        }
                    }
                    fuse_vendor_svn += count;
                }
            }

            if header.svn < fuse_vendor_svn {
                romtime::println!(
                    "[mcu-rom] Image SVN {} is less than fuse vendor test SVN {}",
                    header.svn,
                    fuse_vendor_svn
                );
                return false;
            }
        }
        true
    }
}
