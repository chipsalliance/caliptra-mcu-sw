// Licensed under the Apache-2.0 license

use core::fmt::Write;
use libsyscall_caliptra::dma::{DMASource, DMATransaction, DMA as DMASyscall};
use libsyscall_caliptra::system::System;
use libsyscall_caliptra::DefaultSyscalls;
use libtock_console::Console;
use mcu_config_emulator::EMULATOR_MEMORY_MAP;

const TEST_EXTERNAL_SRAM_DEST_ADDRESS: u32 = EMULATOR_MEMORY_MAP.staging_sram_offset;
fn local_ram_to_axi_address(addr: u32) -> u64 {
    // Convert a local address to an AXI address
    addr as u64
}

fn external_ram_to_axi_address(addr: u32) -> u64 {
    addr as u64
}

#[allow(unused)]
pub(crate) async fn test_dma_xfer_local_to_local() {
    writeln!(
        Console::<DefaultSyscalls>::writer(),
        "Starting test_dma_xfer_local_to_local"
    );

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
        writeln!(
            Console::<DefaultSyscalls>::writer(),
            "Test test_dma_xfer_local_to_local passed"
        );
    } else {
        writeln!(
            Console::<DefaultSyscalls>::writer(),
            "Test test_dma_xfer_local_to_local failed"
        );
        System::exit(1);
    }
}

#[allow(unused)]
pub(crate) async fn test_dma_xfer_local_to_external() {
    writeln!(
        Console::<DefaultSyscalls>::writer(),
        "Starting test_dma_xfer_local_to_external"
    );

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
        writeln!(
            Console::<DefaultSyscalls>::writer(),
            "Test test_dma_xfer_local_to_external passed"
        );
    } else {
        writeln!(
            Console::<DefaultSyscalls>::writer(),
            "Test test_dma_xfer_local_to_external failed"
        );
        System::exit(1);
    }
}
