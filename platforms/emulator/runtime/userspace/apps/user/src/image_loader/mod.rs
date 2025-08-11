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

#[embassy_executor::task]
pub async fn image_loading_task() {
    #[cfg(any(
        feature = "test-pldm-streaming-boot",
        feature = "test-flash-based-boot",
        feature = "test-pldm-discovery",
        feature = "test-pldm-fw-update",
        feature = "test-pldm-fw-update-e2e",
    ))]
    {
        match image_loading(&EMULATED_DMA_MAPPING).await {
            Ok(_) => {}
            Err(_) => romtime::test_exit(1),
        }
    }
    // After image loading, proceed to firmware update if enabled
    #[cfg(any(
        feature = "test-firmware-update-streaming",
        feature = "test-firmware-update-flash"
    ))]
    {
        match crate::firmware_update::firmware_update(&EMULATED_DMA_MAPPING).await {
            Ok(_) => {}
            Err(_) => romtime::test_exit(1),
        }
    }
    romtime::test_exit(0);
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
        // Need to have an await here to let the PLDM service run
        // otherwise it will be stopped immediately
        // and the executor doesn't have a chance to run the tasks
        let suspend_signal: Signal<CriticalSectionRawMutex, ()> = Signal::new();
        suspend_signal.wait().await;
    }
    Ok(())
}

pub struct EmulatedDMAMap {}
impl DMAMapping for EmulatedDMAMap {
    fn mcu_sram_to_mcu_axi(&self, addr: u32) -> Result<AXIAddr, ErrorCode> {
        const MCU_SRAM_HI_OFFSET: u64 = 0x1000_0000;
        // Convert a local address to an AXI address
        Ok((MCU_SRAM_HI_OFFSET << 32) | (addr as u64))
    }

    fn cptra_axi_to_mcu_axi(&self, addr: AXIAddr) -> Result<AXIAddr, ErrorCode> {
        // Caliptra's External SRAM is mapped at 0x0000_0000_8000_0000
        // that is mapped to this device's DMA 0x2000_0000_8000_0000
        const CALIPTRA_EXTERNAL_SRAM_BASE: u64 = 0x0000_0000_8000_0000;
        const DEVICE_EXTERNAL_SRAM_BASE: u64 = 0x2000_0000_0000_0000;
        if addr < CALIPTRA_EXTERNAL_SRAM_BASE {
            return Err(ErrorCode::Invalid);
        }

        Ok(addr - CALIPTRA_EXTERNAL_SRAM_BASE + DEVICE_EXTERNAL_SRAM_BASE)
    }
}

#[allow(dead_code)]
pub static EMULATED_DMA_MAPPING: EmulatedDMAMap = EmulatedDMAMap {};
