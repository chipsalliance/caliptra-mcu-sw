// Licensed under the Apache-2.0 license

use mcu_rom_common::ImageVerifier;

use registers_generated::fuses::Fuses;

#[cfg(any(feature = "test-mcu-svn-gt-fuse", feature = "test-mcu-svn-lt-fuse"))]
use mcu_image_header::McuImageHeader;
#[cfg(any(feature = "test-mcu-svn-gt-fuse", feature = "test-mcu-svn-lt-fuse"))]
use zerocopy::FromBytes;
pub struct McuImageVerifier;

impl ImageVerifier for McuImageVerifier {
    fn verify_header(&self, _header: &[u8], _fuses: &Fuses) -> bool {
        // TODO: make this unconditional and use proper fuses for it instead of test fuses
        #[cfg(any(feature = "test-mcu-svn-gt-fuse", feature = "test-mcu-svn-lt-fuse"))]
        {
            let Ok((header, _)) = McuImageHeader::ref_from_prefix(_header) else {
                romtime::println!("[mcu-rom] Invalid MCU image header");
                return false;
            };

            let mut fuse_vendor_svn: u16 = 0;
            // Use the first 128 bits of vendor test partition as SVN
            for byte in _fuses.vendor_test_partition[..16].iter() {
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
