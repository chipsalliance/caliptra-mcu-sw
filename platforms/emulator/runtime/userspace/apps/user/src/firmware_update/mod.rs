// Licensed under the Apache-2.0 license
mod config;

extern crate alloc;
use core::fmt::Write;
use libsyscall_caliptra::dma::DMAMapping;
use libsyscall_caliptra::mci::{mci_reg::RESET_REASON, Mci as MciSyscall};
use libsyscall_caliptra::DefaultSyscalls;
use libtock_console::Console;

#[cfg(any(
    feature = "test-firmware-update-streaming",
    feature = "test-firmware-update-flash"
))]
use crate::EXECUTOR;

#[cfg(any(
    feature = "test-firmware-update-streaming",
    feature = "test-firmware-update-flash"
))]
use libapi_caliptra::firmware_update::{FirmwareUpdater, PldmFirmwareDeviceParams};

use libtock_platform::ErrorCode;
const RESET_REASON_FW_HITLESS_UPD_RESET_MASK: u32 = 0x1;

#[allow(dead_code)]
pub async fn firmware_update<D: DMAMapping>(dma_mapping: &D) -> Result<(), ErrorCode> {
    let mut console_writer = Console::<DefaultSyscalls>::writer();
    let reset_reason = get_reset_reason()?;

    if reset_reason & RESET_REASON_FW_HITLESS_UPD_RESET_MASK
        == RESET_REASON_FW_HITLESS_UPD_RESET_MASK
    {
        // Device rebooted due to firmware update, skip firmware update
        return Ok(());
    }
    writeln!(console_writer, "[FW Upd] Start").unwrap();
    #[cfg(feature = "test-firmware-update-streaming")]
    {
        let fw_params = PldmFirmwareDeviceParams {
            descriptors: &config::fw_update_consts::DESCRIPTOR.get()[..],
            fw_params: config::fw_update_consts::FIRMWARE_PARAMS.get(),
        };
        let mut updater = FirmwareUpdater::new(
            external_memory::STAGING_MEMORY.get(),
            &fw_params,
            dma_mapping,
            EXECUTOR.get().spawner(),
        );
        updater.start().await?;
    }

    #[cfg(feature = "test-firmware-update-flash")]
    {
        let fw_params = PldmFirmwareDeviceParams {
            descriptors: &config::fw_update_consts::DESCRIPTOR.get()[..],
            fw_params: config::fw_update_consts::FIRMWARE_PARAMS.get(),
        };
        let mut staging_memory = flash_memory::ExternalFlash::new().await?;
        let staging_memory: &'static flash_memory::ExternalFlash =
            unsafe { core::mem::transmute(&mut staging_memory) };
        let mut updater = FirmwareUpdater::new(
            staging_memory,
            &fw_params,
            dma_mapping,
            EXECUTOR.get().spawner(),
        );
        updater.start().await?;
    }

    Ok(())
}

fn get_reset_reason() -> Result<u32, ErrorCode> {
    let mci = MciSyscall::<DefaultSyscalls>::new();
    let reason = mci.read(RESET_REASON, 0)?;
    Ok(reason)
}

#[cfg(feature = "test-firmware-update-streaming")]
mod external_memory {
    extern crate alloc;
    use alloc::boxed::Box;
    use async_trait::async_trait;
    use core::fmt::Debug;
    use libapi_caliptra::firmware_update::StagingMemory;
    use libsyscall_caliptra::dma::{DMAMapping, DMASource, DMATransaction, DMA as DMASyscall};
    use libtock_platform::ErrorCode;

    use crate::image_loader::EMULATED_DMA_MAPPING;

    const DMA_TRANSFER_SIZE: usize = 512;
    const DEVICE_EXTERNAL_SRAM_BASE: u64 = 0xB00C0000;

    pub static STAGING_MEMORY: embassy_sync::lazy_lock::LazyLock<ExternalRAM> =
        embassy_sync::lazy_lock::LazyLock::new(|| ExternalRAM::new(&EMULATED_DMA_MAPPING));

    pub struct ExternalRAM {
        dma_syscall: DMASyscall,
        dma_mapping: &'static dyn DMAMapping,
    }

    impl ExternalRAM {
        pub fn new(dma_mapping: &'static dyn DMAMapping) -> Self {
            ExternalRAM {
                dma_syscall: DMASyscall::new(),
                dma_mapping,
            }
        }
    }

    #[async_trait]
    impl StagingMemory for ExternalRAM {
        async fn write(&self, offset: usize, data: &[u8]) -> Result<(), ErrorCode> {
            let mut current_offset = offset;
            while current_offset < offset + data.len() {
                let transfer_size = (offset + data.len() - current_offset).min(DMA_TRANSFER_SIZE);
                let source_address = self.dma_mapping.mcu_sram_to_mcu_axi(data.as_ptr() as u32)?;
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
            let dest_address = self
                .dma_mapping
                .mcu_sram_to_mcu_axi(data.as_mut_ptr() as u32)?;
            let transaction: DMATransaction<'_> = DMATransaction {
                byte_count: data.len(),
                source: DMASource::Address(DEVICE_EXTERNAL_SRAM_BASE + offset as u64),
                dest_addr: dest_address,
            };
            self.dma_syscall.xfer(&transaction).await
        }

        async fn image_valid(&self, img_sz: usize) -> Result<(), ErrorCode> {
            Ok(())
        }

        fn size(&self) -> usize {
            // Return the size of the staging memory. Replace with actual value if needed.
            256 * 1024 // 256 KiB as an example
        }
    }

    impl Debug for ExternalRAM {
        fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            Ok(())
        }
    }
}

#[cfg(feature = "test-firmware-update-flash")]
mod flash_memory {
    extern crate alloc;
    use alloc::boxed::Box;
    use async_trait::async_trait;
    use core::fmt::Debug;
    use libapi_caliptra::firmware_update::StagingMemory;
    use libapi_emulated_caliptra::image_loading::flash_boot_cfg::FlashBootConfig;
    use libsyscall_caliptra::{
        flash::{FlashCapacity, SpiFlash as FlashSyscall},
        DefaultSyscalls,
    };
    use libtock_platform::ErrorCode;
    use mcu_config::boot::{BootConfigAsync, PartitionId, PartitionStatus};
    use mcu_config_emulator::flash::STAGING_PARTITION;

    use core::fmt::Write;
    use libtock_console::Console;

    pub struct ExternalFlash {
        flash_syscall: FlashSyscall,
    }

    impl ExternalFlash {
        pub async fn new() -> Result<Self, ErrorCode> {
            Ok(ExternalFlash {
                flash_syscall: FlashSyscall::new(STAGING_PARTITION.driver_num),
            })
        }
    }

    #[async_trait]
    impl StagingMemory for ExternalFlash {
        async fn write(&self, offset: usize, data: &[u8]) -> Result<(), ErrorCode> {
            self.flash_syscall.write(offset, data.len(), data).await
        }

        async fn read(&self, offset: usize, data: &mut [u8]) -> Result<(), ErrorCode> {
            self.flash_syscall.read(offset, data.len(), data).await
        }

        async fn image_valid(&self, img_sz: usize) -> Result<(), ErrorCode> {
            // Copy image to the inactive partition
            let mut boot_config = FlashBootConfig::new();
            let inactive_partition_id = boot_config
                .get_inactive_partition()
                .await
                .map_err(|_| ErrorCode::Fail)?;
            let inactive_partition = boot_config
                .get_partition_from_id(inactive_partition_id)
                .map_err(|_| ErrorCode::Fail)?;

            writeln!(
                Console::<DefaultSyscalls>::writer(),
                "[FW Upd] Copying image from staging to inactive partition {:?} length {}",
                inactive_partition_id,
                img_sz
            )
            .unwrap();
            // Mark inactive partittion as invalid
            boot_config
                .set_partition_status(inactive_partition_id, PartitionStatus::Invalid)
                .await
                .map_err(|_| ErrorCode::Fail)?;

            // Copy the image from staging partition to inactive partition
            let mut buffer: [u8; 256] = [0; 256];
            let mut bytes_copied = 0;
            let inactive_flash_syscall =
                FlashSyscall::<DefaultSyscalls>::new(inactive_partition.driver_num);
            while bytes_copied < img_sz {
                let chunk_size = (img_sz - bytes_copied).min(buffer.len());
                self.flash_syscall
                    .read(bytes_copied, chunk_size, &mut buffer[..chunk_size])
                    .await?;
                inactive_flash_syscall
                    .write(bytes_copied, chunk_size, &buffer[..chunk_size])
                    .await?;
                bytes_copied += chunk_size;
            }

            // Mark inactive partition as valid
            boot_config
                .set_partition_status(inactive_partition_id, PartitionStatus::Valid)
                .await
                .map_err(|_| ErrorCode::Fail)?;
            Ok(())
        }

        fn size(&self) -> usize {
            self.flash_syscall
                .get_capacity()
                .unwrap_or(FlashCapacity(0))
                .0 as usize
        }
    }

    impl Debug for ExternalFlash {
        fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            Ok(())
        }
    }
}
