// Licensed under the Apache-2.0 license

use caliptra_mcu_flash_image::{FlashHeader, ImageHeader};
use caliptra_mcu_libsyscall_caliptra::dma::AXIAddr;
use caliptra_mcu_libtock_platform::ErrorCode;
use zerocopy::FromBytes;

use caliptra_mcu_libsyscall_caliptra::flash::SpiFlash as FlashSyscall;

use super::dma_transfer::DmaTransfer;

const FLASH_HEADER_OFFSET: usize = 0;

pub async fn flash_read_header(
    flash: &FlashSyscall,
    header: &mut [u8; core::mem::size_of::<FlashHeader>()],
) -> Result<(), ErrorCode> {
    flash
        .read(
            FLASH_HEADER_OFFSET,
            core::mem::size_of::<FlashHeader>(),
            header,
        )
        .await?;
    Ok(())
}

pub async fn flash_read_toc(
    flash: &FlashSyscall,
    header: &[u8; core::mem::size_of::<FlashHeader>()],
    component_id: u32,
) -> Result<(u32, u32), ErrorCode> {
    let (header, _) = FlashHeader::ref_from_prefix(header).map_err(|_| ErrorCode::Fail)?;
    for index in 0..header.image_count as usize {
        let flash_offset =
            core::mem::size_of::<FlashHeader>() + index * core::mem::size_of::<ImageHeader>();
        let buffer = &mut [0u8; core::mem::size_of::<ImageHeader>()];
        flash
            .read(flash_offset, core::mem::size_of::<ImageHeader>(), buffer)
            .await?;
        let (image_header, _) =
            ImageHeader::ref_from_prefix(buffer).map_err(|_| ErrorCode::Fail)?;
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
