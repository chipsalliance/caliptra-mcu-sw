// Licensed under the Apache-2.0 license

use flash_image::{FlashHeader, ImageHeader};
use libsyscall_caliptra::dma::{AXIAddr, DMAMapping, DMASource, DMATransaction, DMA as DMASyscall};
use libtock_platform::ErrorCode;
use zerocopy::FromBytes;

use libsyscall_caliptra::flash::SpiFlash as FlashSyscall;

/// This is the size of the buffer used for DMA transfers.
const MAX_DMA_TRANSFER_SIZE: usize = 128;

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
    flash: &FlashSyscall,
    load_address: AXIAddr,
    offset: usize,
    img_size: usize,
    dma_mapping: &impl DMAMapping,
) -> Result<(), ErrorCode> {
    let dma_syscall: DMASyscall = DMASyscall::new();
    let mut remaining_size = img_size;
    let mut current_offset = offset;
    let mut current_address = load_address;

    while remaining_size > 0 {
        let transfer_size = remaining_size.min(MAX_DMA_TRANSFER_SIZE);
        let mut buffer = [0; MAX_DMA_TRANSFER_SIZE];
        flash
            .read(current_offset, transfer_size, &mut buffer)
            .await?;

        let source_address = dma_mapping.mcu_sram_to_mcu_axi(buffer.as_ptr() as u32)?;
        let transaction = DMATransaction {
            byte_count: transfer_size,
            source: DMASource::Address(source_address),
            dest_addr: current_address,
        };
        dma_syscall.xfer(&transaction).await?;
        remaining_size -= transfer_size;
        current_offset += transfer_size;
        current_address += transfer_size as u64;
    }

    Ok(())
}
