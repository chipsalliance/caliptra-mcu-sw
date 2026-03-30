// Licensed under the Apache-2.0 license

//! Platform-agnostic image loading building blocks shared between emulator and FPGA user apps.
//!
//! Each platform app provides its own `image_loading_task` and `image_loading` function
//! that compose these shared helpers with platform-specific DMA mapping and boot config.

#[cfg(any(
    feature = "test-pldm-discovery",
    feature = "test-pldm-fw-update",
    feature = "test-pldm-fw-update-e2e"
))]
pub mod pldm_fdops_mock;

pub mod config;

use caliptra_api::mailbox::{
    ActivateFirmwareReq, ActivateFirmwareResp, CommandId, MailboxReqHeader,
};
use core::fmt::Write;
use libsyscall_caliptra::dma::DMAMapping;
#[allow(unused)]
use libsyscall_caliptra::flash::SpiFlash;
use libsyscall_caliptra::mailbox::{Mailbox, MailboxError};
#[allow(unused)]
use libsyscall_caliptra::system::System;
use libtock_console::Console;
use libtock_platform::ErrorCode;
#[allow(unused)]
use mcu_config::boot;
#[allow(unused)]
use mcu_config::boot::{BootConfigAsync, PartitionId, PartitionStatus, RollbackEnable};
#[allow(unused)]
use pldm_lib::daemon::PldmService;

#[allow(unused)]
use embassy_executor::Spawner;
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

pub const RESET_REASON_FW_HITLESS_UPD_RESET_MASK: u32 = 0x1;

/// Platform-agnostic image loading logic.
///
/// This performs PLDM streaming boot and PLDM discovery/update tests.
/// Flash-based boot is handled by each platform's own image_loading function
/// since it requires platform-specific FlashBootConfig.
#[allow(dead_code)]
#[allow(unused_variables)]
pub async fn image_loading<D: DMAMapping>(
    dma_mapping: &'static D,
    spawner: Spawner,
) -> Result<(), ErrorCode> {
    let mut console_writer = Console::<DefaultSyscalls>::writer();
    writeln!(console_writer, "IMAGE_LOADER_APP: Hello async world!").unwrap();
    #[cfg(feature = "test-pldm-streaming-boot")]
    {
        let fw_params = PldmFirmwareDeviceParams {
            descriptors: &config::streaming_boot_consts::DESCRIPTOR.get()[..],
            fw_params: config::streaming_boot_consts::STREAMING_BOOT_FIRMWARE_PARAMS.get(),
        };
        let pldm_image_loader = PldmImageLoader::new(&fw_params, spawner, dma_mapping);
        pldm_image_loader
            .load_and_authorize(config::streaming_boot_consts::IMAGE_ID1)
            .await?;
        pldm_image_loader
            .load_and_authorize(config::streaming_boot_consts::IMAGE_ID2)
            .await?;
        // Close the PLDM session
        pldm_image_loader.finalize()?;
        // Activate the SoC Images (set FW_EXEC_CTRL bit of the corresponding SoC)
        activate_soc_images(&[
            config::streaming_boot_consts::IMAGE_ID1,
            config::streaming_boot_consts::IMAGE_ID2,
        ])
        .await?;
    }

    #[cfg(any(
        feature = "test-pldm-discovery",
        feature = "test-pldm-fw-update",
        feature = "test-pldm-fw-update-e2e"
    ))]
    {
        let fdops = pldm_fdops_mock::FdOpsObject::new();
        let mut pldm_service = PldmService::init(&fdops, spawner);
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

/// Flash-based image loading logic. This is generic over the boot config type.
///
/// Platforms provide their own `BootConfigAsync` implementation and partition lookup.
#[allow(dead_code)]
#[allow(unused_variables)]
#[cfg(any(
    feature = "test-flash-based-boot",
    feature = "test-firmware-update-flash",
))]
pub async fn flash_based_boot<D: DMAMapping, B: BootConfigAsync>(
    dma_mapping: &'static D,
    boot_config: &mut B,
    get_partition: impl Fn(&B, PartitionId) -> Result<mcu_config::flash::FlashPartition, ErrorCode>,
) -> Result<(), ErrorCode> {
    let active_partition_id = boot_config
        .get_active_partition()
        .await
        .map_err(|_| ErrorCode::Fail)?;
    let active_partition = get_partition(boot_config, active_partition_id)?;

    let active = (active_partition_id, active_partition);

    let pending = {
        let pending_partition_id = boot_config.get_pending_partition().await;
        if pending_partition_id.is_ok() {
            let pending_partition_id = pending_partition_id.unwrap();
            let pending_partition = get_partition(boot_config, pending_partition_id)?;
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

    if let Some(_pending) = pending {
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
    activate_soc_images(&[
        config::streaming_boot_consts::IMAGE_ID1,
        config::streaming_boot_consts::IMAGE_ID2,
    ])
    .await
}

/// Activate SoC images by sending an ActivateFirmware mailbox command.
#[allow(dead_code)]
pub async fn activate_soc_images(fw_id_list: &[u32]) -> Result<(), ErrorCode> {
    let fw_ids = {
        let mut ids = [0u32; ActivateFirmwareReq::MAX_FW_ID_COUNT];
        for (i, fw_id) in fw_id_list.iter().enumerate() {
            ids[i] = *fw_id;
        }
        ids
    };
    let mut req = ActivateFirmwareReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id_count: fw_id_list.len() as u32,
        fw_ids,
        mcu_fw_image_size: 0, // MCU image is not activated here
    };

    let req = req.as_mut_bytes();
    let mailbox = Mailbox::<DefaultSyscalls>::new();

    mailbox
        .populate_checksum(CommandId::ACTIVATE_FIRMWARE.into(), req)
        .unwrap();
    let response_buffer = &mut [0u8; core::mem::size_of::<ActivateFirmwareResp>()];
    loop {
        let result = mailbox
            .execute(CommandId::ACTIVATE_FIRMWARE.into(), req, response_buffer)
            .await;
        match result {
            Ok(_) => return Ok(()),
            Err(MailboxError::ErrorCode(ErrorCode::Busy)) => continue,
            Err(_) => return Err(ErrorCode::Fail),
        }
    }
}
