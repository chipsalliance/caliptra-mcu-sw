// Licensed under the Apache-2.0 license

use caliptra_mcu_flash_image::{
    FlashHeader, ImageHeader, MAX_FLASH_HEADER_SIZE, MAX_IMAGE_HEADER_SIZE,
};
use caliptra_mcu_libsyscall_caliptra::dma::AXIAddr;
use caliptra_mcu_libtock_platform::ErrorCode;

use caliptra_mcu_libsyscall_caliptra::flash::SpiFlash as FlashSyscall;

use super::dma_transfer::DmaTransfer;

const FLASH_HEADER_OFFSET: usize = 0;

pub async fn flash_read_header(
    flash: &FlashSyscall,
    header: &mut [u8; MAX_FLASH_HEADER_SIZE],
) -> Result<(), ErrorCode> {
    flash
        .read(FLASH_HEADER_OFFSET, MAX_FLASH_HEADER_SIZE, header)
        .await?;
    Ok(())
}

pub async fn flash_read_toc(
    flash: &FlashSyscall,
    header: &[u8; MAX_FLASH_HEADER_SIZE],
    component_id: u32,
) -> Result<(u32, u32), ErrorCode> {
    let header = FlashHeader::parse(header).map_err(|_| ErrorCode::Invalid)?;
    let version = header.format().map_err(|_| ErrorCode::Invalid)?;
    for index in 0..header.image_count as usize {
        let flash_offset = header.image_header_offset(index).ok_or(ErrorCode::Size)?;
        let buffer = &mut [0u8; MAX_IMAGE_HEADER_SIZE];
        flash
            .read(
                flash_offset,
                version.image_header_size(),
                &mut buffer[..version.image_header_size()],
            )
            .await?;
        let image_header = ImageHeader::parse(buffer, version).map_err(|_| ErrorCode::Invalid)?;
        if image_header.identifier == component_id {
            return Ok((image_header.offset, image_header.size));
        }
    }

    Err(ErrorCode::Fail)
}

pub async fn flash_load_image(
    dma_transfer: &impl DmaTransfer,
    load_address: AXIAddr,
    offset: usize,
    img_size: usize,
) -> Result<(), ErrorCode> {
    let max_xfer = dma_transfer.max_transfer_size();
    let mut remaining_size = img_size;
    let mut current_offset = offset;
    let mut current_address = load_address;

    while remaining_size > 0 {
        let transfer_size = remaining_size.min(max_xfer);
        dma_transfer
            .transfer(current_offset, current_address, transfer_size)
            .await?;
        remaining_size -= transfer_size;
        current_offset += transfer_size;
        current_address += transfer_size as u64;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use caliptra_mcu_flash_image::{
        calculate_checksum, FlashHeaderV1, FlashHeaderV2, FlashHeaderV3, FlashImageVersion,
        ImageHeaderV1V2, ImageHeaderV3,
    };
    use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
    use caliptra_mcu_libtock_platform::Syscalls;
    use caliptra_mcu_libtock_unittest::fake;
    use core::future::Future;
    use core::task::{Context, Poll, Waker};
    use std::rc::Rc;
    use zerocopy::IntoBytes;

    fn run<T>(future: impl Future<Output = T>) -> T {
        let mut future = core::pin::pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        for _ in 0..32 {
            if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
                return value;
            }
            DefaultSyscalls::yield_no_wait();
        }
        panic!("Flash read did not complete");
    }

    #[test]
    fn runtime_reads_all_flash_formats() {
        for version in [
            FlashImageVersion::V1,
            FlashImageVersion::V2,
            FlashImageVersion::V3,
        ] {
            let kernel = fake::Kernel::new();
            let driver = Rc::new(fake::FakeFlashDriver::new());
            let mut bytes = std::vec![0; 256];
            let out = &mut bytes[..version.header_size()];
            match version {
                FlashImageVersion::V1 => out.copy_from_slice(FlashHeaderV1::new(2).as_bytes()),
                FlashImageVersion::V2 => out.copy_from_slice(FlashHeaderV2::new(2).as_bytes()),
                FlashImageVersion::V3 => out.copy_from_slice(FlashHeaderV3::new(2).as_bytes()),
            }
            for index in 0..2 {
                let mut image = ImageHeaderV3 {
                    identifier: index as u32,
                    offset: 192 + index as u32 * 4,
                    size: 4,
                    filename: [b'x'; 64],
                    image_checksum: calculate_checksum(&[1, 2, 3, 4]),
                    image_header_checksum: 0,
                };
                image.image_header_checksum = calculate_checksum(&image.as_bytes()[..80]);
                let mut legacy = ImageHeaderV1V2 {
                    identifier: image.identifier,
                    offset: image.offset,
                    size: image.size,
                    image_checksum: image.image_checksum,
                    image_header_checksum: 0,
                };
                legacy.image_header_checksum = calculate_checksum(&legacy.as_bytes()[..16]);
                let offset = version.header_size() + index * version.image_header_size();
                bytes[offset..offset + version.image_header_size()].copy_from_slice(
                    if version == FlashImageVersion::V3 {
                        image.as_bytes()
                    } else {
                        legacy.as_bytes()
                    },
                );
            }
            driver.set_flash_content(bytes);
            kernel.add_driver(&driver);
            let flash = FlashSyscall::new(0x8000_0006);
            let mut header = [0; MAX_FLASH_HEADER_SIZE];
            run(flash_read_header(&flash, &mut header)).unwrap();
            assert_eq!(run(flash_read_toc(&flash, &header, 1)), Ok((196, 4)));
            assert!(run(flash_read_toc(&flash, &header, 9)).is_err());
        }
    }
}
