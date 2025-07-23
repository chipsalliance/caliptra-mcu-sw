// Licensed under the Apache-2.0 license
mod config;

extern crate alloc;

use crate::EXECUTOR;
use core::fmt::Write;
use libapi_caliptra::firmware_update::{FirmwareUpdater, PldmFirmwareDeviceParams};
use libsyscall_caliptra::DefaultSyscalls;
use libtock_console::Console;

use alloc::boxed::Box;
use async_trait::async_trait;
use core::fmt::Debug;
use libapi_caliptra::firmware_update::StagingMemory;
use libsyscall_caliptra::dma::{DMASource, DMATransaction, DMA as DMASyscall};
use libtock_platform::ErrorCode;
use mcu_config_emulator::dma::mcu_sram_to_axi_address;

const DMA_TRANSFER_SIZE: usize = 512;
const DEVICE_EXTERNAL_SRAM_BASE: u64 = 0x2000_0000_0000_0000;

#[embassy_executor::task]
pub async fn firmware_update_task() {
    match firmware_update().await {
        Ok(_) => romtime::test_exit(0),
        Err(_) => romtime::test_exit(1),
    }
}

#[allow(dead_code)]
async fn firmware_update() -> Result<(), ErrorCode> {
    let mut console_writer = Console::<DefaultSyscalls>::writer();
    writeln!(console_writer, "fw_upd task").unwrap();
    let fw_params = PldmFirmwareDeviceParams {
        descriptors: &config::fw_update_consts::DESCRIPTOR.get()[..],
        fw_params: config::fw_update_consts::FIRMWARE_PARAMS.get(),
    };
    let mut updater: FirmwareUpdater =
        FirmwareUpdater::new(STAGING_MEMORY.get(), &fw_params, EXECUTOR.get().spawner());
    updater.start().await?;

    Ok(())
}

pub static STAGING_MEMORY: embassy_sync::lazy_lock::LazyLock<ExternalRAM> =
    embassy_sync::lazy_lock::LazyLock::new(|| ExternalRAM::new());

pub struct ExternalRAM {
    dma_syscall: DMASyscall,
}

impl ExternalRAM {
    pub fn new() -> Self {
        ExternalRAM {
            dma_syscall: DMASyscall::new(),
        }
    }
}

#[async_trait]
impl StagingMemory for ExternalRAM {
    async fn write(&self, offset: usize, data: &[u8]) -> Result<(), ErrorCode> {
        let mut current_offset = offset;
        while current_offset < offset + data.len() {
            let transfer_size = (offset + data.len() - current_offset).min(DMA_TRANSFER_SIZE);
            let source_address = mcu_sram_to_axi_address(data.as_ptr() as u32);
            let transaction = DMATransaction {
                byte_count: transfer_size,
                source: DMASource::Address(source_address),
                dest_addr: DEVICE_EXTERNAL_SRAM_BASE + current_offset as u64,
            };
            self.dma_syscall.xfer(&transaction).await?;
            current_offset += transfer_size;
        }

        Ok(())
    }

    async fn read(&self, offset: usize, data: &mut [u8]) -> Result<(), ErrorCode> {
        let dest_address = mcu_sram_to_axi_address(data.as_mut_ptr() as u32);
        let transaction: DMATransaction<'_> = DMATransaction {
            byte_count: data.len(),
            source: DMASource::Address(DEVICE_EXTERNAL_SRAM_BASE + offset as u64),
            dest_addr: dest_address,
        };
        self.dma_syscall.xfer(&transaction).await
    }

    fn size(&self) -> usize {
        // Return the size of the staging memory. Replace with actual value if needed.
        1024 * 1024 // 1 MiB as an example
    }
}

impl Debug for ExternalRAM {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Ok(())
    }
}
