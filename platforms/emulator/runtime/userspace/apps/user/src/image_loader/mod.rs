// Licensed under the Apache-2.0 license

#[allow(unused)]
use libsyscall_caliptra::system::System;
#[allow(unused)]
use libtock_platform::ErrorCode;

#[allow(unused)]
use libapi_emulated_caliptra::image_loading::flash_boot_cfg::FlashBootConfig;
#[allow(unused)]
use mcu_config::boot::{BootConfigAsync, PartitionId, PartitionStatus};
#[allow(unused)]
use mcu_config::flash::FlashPartition;
#[allow(unused)]
use mcu_config_emulator::flash::{IMAGE_A_PARTITION, IMAGE_B_PARTITION};

use libsyscall_caliptra::dma::DMAMapping;
use user_app_common::IDENTITY_DMA_MAPPING;

#[embassy_executor::task]
pub async fn image_loading_task() {
    let spawner = crate::EXECUTOR.get().spawner();
    user_app_common::image_loader::image_loading_task_body(
        &IDENTITY_DMA_MAPPING,
        spawner,
        EmulatorHook,
    )
    .await;

    // After image loading, proceed to firmware update if enabled
    #[cfg(any(
        feature = "test-firmware-update-streaming",
        feature = "test-firmware-update-flash"
    ))]
    {
        let mbox_sram = libsyscall_caliptra::mbox_sram::MboxSram::<DefaultSyscalls>::new(
            libsyscall_caliptra::mbox_sram::DRIVER_NUM_MCU_MBOX1_SRAM,
        );
        if mbox_sram.acquire_lock().is_err() {
            mbox_sram.release_lock().unwrap();
            mbox_sram.acquire_lock().unwrap();
        }
        match crate::firmware_update::firmware_update(&IDENTITY_DMA_MAPPING).await {
            Ok(_) => System::exit(0),
            Err(_) => System::exit(1),
        }
    }
}

/// Emulator-specific hook: runs flash-based boot after the shared image loading.
struct EmulatorHook;

impl<D: DMAMapping> user_app_common::image_loader::AsyncPlatformHook<D> for EmulatorHook {
    #[allow(unused_variables)]
    async fn run(self, dma_mapping: &'static D) -> bool {
        #[cfg(any(
            feature = "test-flash-based-boot",
            feature = "test-firmware-update-flash",
        ))]
        {
            let mut boot_config = FlashBootConfig::new();
            if let Err(_) = user_app_common::image_loader::flash_based_boot(
                dma_mapping,
                &mut boot_config,
                |_cfg, partition_id| match partition_id {
                    PartitionId::A => Ok(IMAGE_A_PARTITION),
                    PartitionId::B => Ok(IMAGE_B_PARTITION),
                    _ => Err(ErrorCode::Fail),
                },
            )
            .await
            {
                System::exit(1);
            }
        }

        // When firmware update features are active, don't exit yet -
        // the caller will proceed to firmware_update.
        #[cfg(any(
            feature = "test-firmware-update-streaming",
            feature = "test-firmware-update-flash"
        ))]
        return true;

        #[cfg(not(any(
            feature = "test-firmware-update-streaming",
            feature = "test-firmware-update-flash"
        )))]
        false
    }
}
