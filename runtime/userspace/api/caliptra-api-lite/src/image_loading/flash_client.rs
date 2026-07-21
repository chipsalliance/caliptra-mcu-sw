// Licensed under the Apache-2.0 license

use core::mem::size_of;

use caliptra_mcu_flash_image::{FlashHeader, ImageHeader};
use caliptra_mcu_libsyscall_caliptra::dma::AXIAddr;
use caliptra_mcu_libsyscall_caliptra::flash::SpiFlash as FlashSyscall;
use mcu_error::McuResult;
use zerocopy::FromBytes;

use super::DmaTransfer;
use crate::errors::image_loading as image_errors;
use crate::ApiAlloc;

const FLASH_HEADER_OFFSET: usize = 0;

pub async fn flash_read_header(
    flash: &FlashSyscall,
    header: &mut [u8; size_of::<FlashHeader>()],
) -> McuResult<()> {
    flash
        .read(FLASH_HEADER_OFFSET, size_of::<FlashHeader>(), header)
        .await?;
    Ok(())
}

pub async fn flash_read_toc(
    flash: &FlashSyscall,
    header: &[u8; size_of::<FlashHeader>()],
    component_id: u32,
) -> McuResult<(u32, u32)> {
    let (header, _) =
        FlashHeader::ref_from_prefix(header).map_err(|_| image_errors::INVALID_FLASH_HEADER)?;
    for index in 0..header.image_count as usize {
        let entry_offset = index
            .checked_mul(size_of::<ImageHeader>())
            .ok_or(image_errors::IMAGE_OFFSET_OVERFLOW)?;
        let flash_offset = size_of::<FlashHeader>()
            .checked_add(entry_offset)
            .ok_or(image_errors::IMAGE_OFFSET_OVERFLOW)?;
        let mut buffer = [0u8; size_of::<ImageHeader>()];
        flash
            .read(flash_offset, size_of::<ImageHeader>(), &mut buffer)
            .await?;
        let (image_header, _) = ImageHeader::ref_from_prefix(&buffer)
            .map_err(|_| image_errors::INVALID_IMAGE_HEADER)?;
        if image_header.identifier == component_id {
            return Ok((image_header.offset, image_header.size));
        }
    }

    Err(image_errors::IMAGE_NOT_FOUND)
}

pub async fn flash_load_image<A: ApiAlloc>(
    dma_transfer: &impl DmaTransfer,
    alloc: &A,
    load_address: AXIAddr,
    offset: usize,
    img_size: usize,
) -> McuResult<()> {
    let max_xfer = dma_transfer.max_transfer_size();
    if max_xfer == 0 {
        return Err(image_errors::DMA_TRANSFER_SIZE_ZERO);
    }

    let mut remaining_size = img_size;
    let mut current_offset = offset;
    let mut current_address = load_address;

    while remaining_size > 0 {
        let transfer_size = remaining_size.min(max_xfer);
        dma_transfer
            .transfer(alloc, current_offset, current_address, transfer_size)
            .await?;
        remaining_size -= transfer_size;
        current_offset = current_offset
            .checked_add(transfer_size)
            .ok_or(image_errors::IMAGE_OFFSET_OVERFLOW)?;
        current_address = current_address
            .checked_add(transfer_size as u64)
            .ok_or(image_errors::IMAGE_OFFSET_OVERFLOW)?;
    }

    Ok(())
}
