// Licensed under the Apache-2.0 license

use core::fmt::Write;
use libsyscall_caliptra::dma::{DMASource, DMATransaction, DMA as DMASyscall};
use romtime::{println, test_exit};

const MCU_SRAM_HI_OFFSET: u64 = 0x1000_0000;
const EXTERNAL_SRAM_HI_OFFSET: u64 = 0x2000_0000;
const TEST_EXTERNAL_SRAM_DEST_ADDRESS: u32 = 0x0000_0000;

fn local_ram_to_axi_address(addr: u32) -> u64 {
    // Convert a local address to an AXI address
    (MCU_SRAM_HI_OFFSET << 32) | (addr as u64)
}

fn external_ram_to_axi_address(addr: u32) -> u64 {
    // Convert a local address to an AXI address
    (EXTERNAL_SRAM_HI_OFFSET << 32) | (addr as u64)
}

#[allow(unused)]
pub(crate) async fn test_dma_xfer_local_to_local() {
    println!("Starting test_dma_xfer_local_to_local");

    let dma_syscall: DMASyscall = DMASyscall::new();

    let source_buffer = [0xABu8; 16];
    let mut dest_buffer = [0u8; 16];

    let source_address = local_ram_to_axi_address(&source_buffer as *const _ as u32);
    let dest_address = local_ram_to_axi_address(&dest_buffer as *const _ as u32);

    let transaction = DMATransaction {
        byte_count: source_buffer.len(),
        source: DMASource::Address(source_address),
        dest_addr: dest_address,
    };

    dma_syscall.xfer(&transaction).await.unwrap();

    if source_buffer == dest_buffer {
        println!("Test test_dma_xfer_local_to_local passed");
    } else {
        println!("Test test_dma_xfer_local_to_local failed");
        test_exit(1);
    }
}

#[allow(unused)]
pub(crate) async fn test_dma_xfer_local_to_external() {
    println!("Starting test_dma_xfer_local_to_external");

    let dma_syscall: DMASyscall = DMASyscall::new();

    let source_buffer = [0xABu8; 16];
    let mut dest_buffer = [0u8; 16];
    let source_address = local_ram_to_axi_address(&source_buffer as *const _ as u32);
    let dest_address = external_ram_to_axi_address(TEST_EXTERNAL_SRAM_DEST_ADDRESS);

    // Transfer from local RAM to external RAM
    let transaction = DMATransaction {
        byte_count: source_buffer.len(),
        source: DMASource::Address(source_address),
        dest_addr: dest_address,
    };
    dma_syscall.xfer(&transaction).await.unwrap();

    // Transfer from external RAM back to another local RAM buffer
    let transaction = DMATransaction {
        byte_count: dest_buffer.len(),
        source: DMASource::Address(dest_address),
        dest_addr: local_ram_to_axi_address(&dest_buffer as *const _ as u32),
    };
    dma_syscall.xfer(&transaction).await.unwrap();

    if source_buffer == dest_buffer {
        println!("Test test_dma_xfer_local_to_external passed");
    } else {
        println!("Test test_dma_xfer_local_to_external failed");
        test_exit(1);
    }
}
