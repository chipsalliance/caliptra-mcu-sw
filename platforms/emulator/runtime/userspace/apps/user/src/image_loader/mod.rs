// Licensed under the Apache-2.0 license

#[cfg(any(
    feature = "test-pldm-discovery",
    feature = "test-pldm-fw-update",
    feature = "test-pldm-fw-update-e2e"
))]
mod pldm_fdops_mock;

mod config;

use core::fmt::Write;
#[allow(unused)]
use libapi_emulated_caliptra::image_loading::flash_boot_cfg::FlashBootConfig;
use libsyscall_caliptra::dma::{AXIAddr, DMAMapping};
#[allow(unused)]
use libsyscall_caliptra::flash::SpiFlash;
use libsyscall_caliptra::mci::{mci_reg::RESET_REASON, Mci as MciSyscall};
#[allow(unused)]
use libsyscall_caliptra::system::System;
use libtock_console::Console;
use libtock_platform::ErrorCode;
#[allow(unused)]
use mcu_config::boot;
#[allow(unused)]
use mcu_config::boot::{BootConfigAsync, PartitionId, PartitionStatus, RollbackEnable};
#[allow(unused)]
use mcu_config_emulator::flash::{
    PartitionTable, StandAloneChecksumCalculator, IMAGE_A_PARTITION, IMAGE_B_PARTITION,
    PARTITION_TABLE,
};
#[allow(unused)]
use pldm_lib::daemon::PldmService;

#[allow(unused)]
use crate::EXECUTOR;
#[allow(unused)]
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
#[allow(unused)]
use embassy_sync::{lazy_lock::LazyLock, signal::Signal};
#[allow(unused)]
use libapi_caliptra::image_loading::{
    FlashImageLoader, ImageLoader, PldmFirmwareDeviceParams, PldmImageLoader,
};
use libsyscall_caliptra::DefaultSyscalls;
#[allow(unused)]
use zerocopy::{FromBytes, IntoBytes};

const RESET_REASON_FW_HITLESS_UPD_RESET_MASK: u32 = 0x1;

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
        match image_loading(&EMULATED_DMA_MAPPING).await {
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
        mbox_sram.acquire_lock().unwrap();
        match crate::firmware_update::firmware_update(&EMULATED_DMA_MAPPING).await {
            Ok(_) => System::exit(0),
            Err(_) => System::exit(1),
        }
        // MBOX SRAM lock will be released after reboot
    }
}

#[allow(dead_code)]
#[allow(unused_variables)]
async fn image_loading<D: DMAMapping>(dma_mapping: &'static D) -> Result<(), ErrorCode> {
    let mut console_writer = Console::<DefaultSyscalls>::writer();
    writeln!(console_writer, "IMAGE_LOADER_APP: Hello async world!").unwrap();
    #[cfg(feature = "test-pldm-streaming-boot")]
    {
        let fw_params = PldmFirmwareDeviceParams {
            descriptors: &config::streaming_boot_consts::DESCRIPTOR.get()[..],
            fw_params: config::streaming_boot_consts::STREAMING_BOOT_FIRMWARE_PARAMS.get(),
        };
        let pldm_image_loader =
            PldmImageLoader::new(&fw_params, EXECUTOR.get().spawner(), dma_mapping);
        pldm_image_loader
            .load_and_authorize(config::streaming_boot_consts::IMAGE_ID1)
            .await?;
        pldm_image_loader
            .load_and_authorize(config::streaming_boot_consts::IMAGE_ID2)
            .await?;
        pldm_image_loader.finalize().await?;
    }
    #[cfg(any(
        feature = "test-flash-based-boot",
        feature = "test-firmware-update-flash",
    ))]
    {
        let mut boot_config = FlashBootConfig::new();
        let active_partition_id = boot_config
            .get_active_partition()
            .await
            .map_err(|_| ErrorCode::Fail)?;
        let active_partition = boot_config
            .get_partition_from_id(active_partition_id)
            .map_err(|_| ErrorCode::Fail)?;

        let active = (active_partition_id, active_partition);

        let pending = {
            let pending_partition_id = boot_config.get_pending_partition().await;
            if pending_partition_id.is_ok() {
                let pending_partition_id = pending_partition_id.unwrap();
                let pending_partition = boot_config
                    .get_partition_from_id(pending_partition_id)
                    .map_err(|_| ErrorCode::Fail)?;

                Some((pending_partition_id, pending_partition))
            } else {
                None
            }
        };

        let load_partition = if let Some((pending_partition_id, pending_partition)) = pending {
            (pending_partition_id, pending_partition)
        } else {
            // No pending partition, use the active one
            active
        };

        let flash_syscall = SpiFlash::new(load_partition.1.driver_num);
        let flash_image_loader = FlashImageLoader::new(flash_syscall, dma_mapping);

        if let Some(pending) = pending {
            // Set the new Auth Manifest from the pending partition
            flash_image_loader.set_auth_manifest().await?;
        }

        flash_image_loader
            .load_and_authorize(config::streaming_boot_consts::IMAGE_ID1)
            .await?;
        flash_image_loader
            .load_and_authorize(config::streaming_boot_consts::IMAGE_ID2)
            .await?;
        boot_config
            .set_partition_status(load_partition.0, PartitionStatus::BootSuccessful)
            .await
            .map_err(|_| ErrorCode::Fail)?;
        boot_config
            .set_active_partition(load_partition.0)
            .await
            .map_err(|_| ErrorCode::Fail)?;
    }

    #[cfg(any(
        feature = "test-pldm-discovery",
        feature = "test-pldm-fw-update",
        feature = "test-pldm-fw-update-e2e"
    ))]
    {
        let fdops = pldm_fdops_mock::FdOpsObject::new();
        let mut pldm_service = PldmService::init(&fdops, EXECUTOR.get().spawner());
        writeln!(
            console_writer,
            "PLDM_APP: Starting PLDM service for testing..."
        )
        .unwrap();
        if let Err(e) = pldm_service.start().await {
            writeln!(
                console_writer,
                "PLDM_APP: Error starting PLDM service: {:?}",
                e
            )
            .unwrap();
        }
        pldm_fdops_mock::FdOpsObject::wait_for_pldm_done().await;
    }
    Ok(())
}

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
