// Licensed under the Apache-2.0 license

use libsyscall_caliptra::dma::{AXIAddr, DMAMapping};
use libsyscall_caliptra::mci::{mci_reg::RESET_REASON, Mci as MciSyscall};
#[allow(unused)]
use libsyscall_caliptra::system::System;
use libtock_platform::ErrorCode;

#[allow(unused)]
use libapi_emulated_caliptra::image_loading::flash_boot_cfg::FlashBootConfig;
#[allow(unused)]
use mcu_config::boot::{BootConfigAsync, PartitionId, PartitionStatus};
#[allow(unused)]
use mcu_config::flash::FlashPartition;
#[allow(unused)]
use mcu_config_emulator::flash::{IMAGE_A_PARTITION, IMAGE_B_PARTITION};

use libsyscall_caliptra::DefaultSyscalls;
use user_app_common::image_loader::RESET_REASON_FW_HITLESS_UPD_RESET_MASK;

pub struct EmulatedDMAMap {}
impl DMAMapping for EmulatedDMAMap {
    fn mcu_sram_to_mcu_axi(&self, addr: u32) -> Result<AXIAddr, ErrorCode> {
        Ok(addr as AXIAddr)
    }

    fn cptra_axi_to_mcu_axi(&self, addr: AXIAddr) -> Result<AXIAddr, ErrorCode> {
        Ok(addr as AXIAddr)
    }
}

#[allow(dead_code)]
pub static EMULATED_DMA_MAPPING: EmulatedDMAMap = EmulatedDMAMap {};

#[embassy_executor::task]
pub async fn image_loading_task() {
    let mbox_sram = libsyscall_caliptra::mbox_sram::MboxSram::<DefaultSyscalls>::new(
        libsyscall_caliptra::mbox_sram::DRIVER_NUM_MCU_MBOX1_SRAM,
    );
    let mci = MciSyscall::<DefaultSyscalls>::new();
    let reset_reason = mci.read(RESET_REASON, 0).unwrap();
    if reset_reason & RESET_REASON_FW_HITLESS_UPD_RESET_MASK
        == RESET_REASON_FW_HITLESS_UPD_RESET_MASK
    {
        // Device rebooted due to firmware update
        // MCU SRAM lock is acquired prior to rebooting the device
        // The lock is needed so that Caliptra can write the updated firmware from MCU MBOX SRAM to MCU SRAM
        // After the update reboot, lock is no longer needed, so release it here
        mbox_sram.release_lock().unwrap();
    }
    #[cfg(any(
        feature = "test-pldm-streaming-boot",
        feature = "test-flash-based-boot",
        feature = "test-pldm-discovery",
        feature = "test-pldm-fw-update",
        feature = "test-pldm-fw-update-e2e",
    ))]
    {
        // Release SRAM lock, in case previous session hasn't released it
        // If MCU is not the lock owner, then this should be no-op
        if mbox_sram.acquire_lock().is_err() {
            mbox_sram.release_lock().unwrap();
            mbox_sram.acquire_lock().unwrap();
        }
        let spawner = crate::EXECUTOR.get().spawner();
        match image_loading(&EMULATED_DMA_MAPPING, spawner).await {
            Ok(_) => {}
            Err(_) => System::exit(1),
        }
        mbox_sram.release_lock().unwrap();
        #[cfg(not(any(
            feature = "test-firmware-update-streaming",
            feature = "test-firmware-update-flash"
        )))]
        System::exit(0);
    }
    // After image loading, proceed to firmware update if enabled
    #[cfg(any(
        feature = "test-firmware-update-streaming",
        feature = "test-firmware-update-flash"
    ))]
    {
        if mbox_sram.acquire_lock().is_err() {
            mbox_sram.release_lock().unwrap();
            mbox_sram.acquire_lock().unwrap();
        }
        match crate::firmware_update::firmware_update(&EMULATED_DMA_MAPPING).await {
            Ok(_) => System::exit(0),
            Err(_) => System::exit(1),
        }
        // MBOX SRAM lock will be released after reboot
    }
}

/// Emulator-specific image loading that composes shared and platform-specific code.
#[allow(dead_code)]
#[allow(unused_variables)]
async fn image_loading<D: DMAMapping>(
    dma_mapping: &'static D,
    spawner: embassy_executor::Spawner,
) -> Result<(), ErrorCode> {
    // Use shared image loading for streaming boot and PLDM tests
    user_app_common::image_loader::image_loading(dma_mapping, spawner).await?;

    // Emulator-specific: flash-based boot
    #[cfg(any(
        feature = "test-flash-based-boot",
        feature = "test-firmware-update-flash",
    ))]
    {
        let mut boot_config = FlashBootConfig::new();
        user_app_common::image_loader::flash_based_boot(
            dma_mapping,
            &mut boot_config,
            |_cfg, partition_id| match partition_id {
                PartitionId::A => Ok(IMAGE_A_PARTITION),
                PartitionId::B => Ok(IMAGE_B_PARTITION),
                _ => Err(ErrorCode::Fail),
            },
        )
        .await?;
    }

    Ok(())
}
