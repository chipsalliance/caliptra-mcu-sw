// Licensed under the Apache-2.0 license

extern crate alloc;
use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_mcu_config_emulator::flash::{IMAGE_A_PARTITION, STAGING_PARTITION};
use caliptra_mcu_libsyscall_caliptra::flash::SpiFlash as FlashSyscall;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_console::Console;
use caliptra_mcu_libtock_platform::ErrorCode;
use core::fmt::Write;

use caliptra_mcu_libapi_caliptra::firmware_update::StagingMemory;

pub static STAGING_MEMORY: embassy_sync::lazy_lock::LazyLock<SpiFlashStagingMemory> =
    embassy_sync::lazy_lock::LazyLock::new(SpiFlashStagingMemory::new);

/// A `StagingMemory` implementation backed by SPI flash.
///
/// PLDM firmware data is written directly to flash. This allows the
/// `FirmwareUpdater` to program a full flash image via the standard
/// PLDM firmware update flow.
///
/// Note: The Tock flash partition capsule handles offset mapping internally,
/// so all offsets used with the flash syscall are 0-based (partition-relative).
pub struct SpiFlashStagingMemory {
    flash: FlashSyscall,
    capacity: usize,
}

impl core::fmt::Debug for SpiFlashStagingMemory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SpiFlashStagingMemory")
            .field("capacity", &self.capacity)
            .finish()
    }
}

impl SpiFlashStagingMemory {
    pub fn new() -> Self {
        Self {
            flash: FlashSyscall::new(STAGING_PARTITION.driver_num),
            capacity: STAGING_PARTITION.size,
        }
    }

    /// Erase the flash region before starting the download.
    /// Must be called before `FirmwareUpdater::start()`.
    pub async fn erase(&self) -> Result<(), ErrorCode> {
        self.flash.erase(0, self.capacity).await
    }
}

#[async_trait]
impl StagingMemory for SpiFlashStagingMemory {
    async fn write(&self, offset: usize, data: &[u8]) -> Result<(), ErrorCode> {
        self.flash.write(offset, data.len(), data).await
    }

    async fn read(&self, offset: usize, data: &mut [u8]) -> Result<(), ErrorCode> {
        self.flash.read(offset, data.len(), data).await
    }

    async fn image_valid(&self, img_sz: usize) -> Result<(), ErrorCode> {
        // Compare the image in staging partition and Partition A
        // If they are not the same, then copy the image from staging partition to Partition A
        let part_a_flash = FlashSyscall::<DefaultSyscalls>::new(IMAGE_A_PARTITION.driver_num);

        let mut staging_buf: [u8; 1024] = [0; 1024];
        let mut part_a_buf: [u8; 1024] = [0; 1024];
        let mut offset = 0;
        let mut images_match = true;

        while offset < img_sz {
            let chunk_size = (img_sz - offset).min(staging_buf.len());
            self.flash
                .read(offset, chunk_size, &mut staging_buf[..chunk_size])
                .await?;
            part_a_flash
                .read(offset, chunk_size, &mut part_a_buf[..chunk_size])
                .await?;
            if staging_buf[..chunk_size] != part_a_buf[..chunk_size] {
                images_match = false;
                break;
            }
            offset += chunk_size;
        }

        if images_match {
            crate::console_writeln!(
                Console::<DefaultSyscalls>::writer(),
                "[FW Upd] Staging matches Partition A, skipping copy"
            );
            return Ok(());
        }

        crate::console_writeln!(
            Console::<DefaultSyscalls>::writer(),
            "[FW Upd] Copying image from staging to Partition A, length {}",
            img_sz
        );

        // Erase Partition A before writing
        part_a_flash.erase(0, img_sz).await?;

        // Copy from staging to Partition A
        let mut bytes_copied = 0;
        while bytes_copied < img_sz {
            let chunk_size = (img_sz - bytes_copied).min(staging_buf.len());
            self.flash
                .read(bytes_copied, chunk_size, &mut staging_buf[..chunk_size])
                .await?;
            part_a_flash
                .write(bytes_copied, chunk_size, &staging_buf[..chunk_size])
                .await?;
            bytes_copied += chunk_size;
        }

        Ok(())
    }

    fn size(&self) -> usize {
        self.capacity
    }
}
