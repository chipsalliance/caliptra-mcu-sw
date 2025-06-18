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
use libapi_emulated_caliptra::flash_boot_cfg::FlashBootConfig;
#[allow(unused)]
use libsyscall_caliptra::flash::SpiFlash;
use libtock_console::Console;
use libtock_platform::ErrorCode;
#[allow(unused)]
use mcu_config::boot;
#[allow(unused)]
use mcu_config::boot::{BootConfig, PartitionId, PartitionStatus, RollbackEnable};
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
        match image_loading().await {
            Ok(_) => romtime::test_exit(0),
            Err(_) => romtime::test_exit(1),
        }
    }
}

#[allow(dead_code)]
async fn image_loading() -> Result<(), ErrorCode> {
    let mut console_writer = Console::<DefaultSyscalls>::writer();
    writeln!(console_writer, "IMAGE_LOADER_APP: Hello async world!").unwrap();
    #[cfg(feature = "test-pldm-streaming-boot")]
    {
        let fw_params = PldmFirmwareDeviceParams {
            descriptors: &config::streaming_boot_consts::DESCRIPTOR.get()[..],
            fw_params: config::streaming_boot_consts::STREAMING_BOOT_FIRMWARE_PARAMS.get(),
        };
        let pldm_image_loader: PldmImageLoader =
            PldmImageLoader::new(&fw_params, EXECUTOR.get().spawner());
        pldm_image_loader
            .load_and_authorize(config::streaming_boot_consts::IMAGE_ID1)
            .await?;
        pldm_image_loader
            .load_and_authorize(config::streaming_boot_consts::IMAGE_ID2)
            .await?;
        pldm_image_loader.finalize().await?;
    }
    #[cfg(feature = "test-flash-based-boot")]
    {
        let mut boot_config = FlashBootConfig::new();
        let active_partition_id = boot_config
            .get_active_partition()
            .await
            .map_err(|_| ErrorCode::Fail)?;
        let active_partition = boot_config
            .get_partition_from_id(active_partition_id)
            .map_err(|_| ErrorCode::Fail)?;
        let flash_syscall = SpiFlash::new(active_partition.driver_num);
        let flash_image_loader: FlashImageLoader = FlashImageLoader::new(flash_syscall);
        flash_image_loader
            .load_and_authorize(config::streaming_boot_consts::IMAGE_ID1)
            .await?;
        flash_image_loader
            .load_and_authorize(config::streaming_boot_consts::IMAGE_ID2)
            .await?;
        boot_config
            .set_partition_status(active_partition_id, PartitionStatus::BootSuccessful)
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
