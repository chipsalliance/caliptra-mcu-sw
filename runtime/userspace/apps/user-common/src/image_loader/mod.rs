// Licensed under the Apache-2.0 license

//! Platform-agnostic image loading building blocks shared between emulator and FPGA user apps.

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

// ---------------------------------------------------------------------------
// Common image_loading_task body
// ---------------------------------------------------------------------------

/// Shared body of `image_loading_task`.
///
/// Handles the reset-reason check, SRAM lock management, calls `image_loading`,
/// and exits. Platform-specific hooks (flash-based boot, firmware update) are
/// injected through the `platform_hook` callback which runs *after* the shared
/// `image_loading` call but *before* the SRAM lock release.
///
/// `platform_hook` receives the mbox_sram reference so it can manage the lock
/// for firmware update. Return `true` from the hook to skip the default
/// `System::exit(0)` (e.g. because the hook handles exit itself).
#[allow(dead_code)]
#[allow(unused_variables)]
pub async fn image_loading_task_body<D: DMAMapping>(
    dma_mapping: &'static D,
    spawner: Spawner,
    platform_hook: impl AsyncPlatformHook<D>,
) {
    let mbox_sram = libsyscall_caliptra::mbox_sram::MboxSram::<DefaultSyscalls>::new(
        libsyscall_caliptra::mbox_sram::DRIVER_NUM_MCU_MBOX1_SRAM,
    );
    let mci = MciSyscall::<DefaultSyscalls>::new();
    let reset_reason = mci.read(RESET_REASON, 0).unwrap();
    if reset_reason & RESET_REASON_FW_HITLESS_UPD_RESET_MASK
        == RESET_REASON_FW_HITLESS_UPD_RESET_MASK
    {
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
        if mbox_sram.acquire_lock().is_err() {
            mbox_sram.release_lock().unwrap();
            mbox_sram.acquire_lock().unwrap();
        }
        match image_loading(dma_mapping, spawner).await {
            Ok(_) => {}
            Err(_) => System::exit(1),
        }

        // Let the platform run flash-based boot or firmware update.
        let handled = platform_hook.run(dma_mapping).await;

        mbox_sram.release_lock().unwrap();
        if !handled {
            System::exit(0);
        }
    }
}

/// Trait for the platform-specific hook called inside `image_loading_task_body`.
///
/// Returns `true` if the hook fully handles exit (e.g. firmware update reboot),
/// `false` if the shared code should call `System::exit(0)`.
#[allow(async_fn_in_trait)]
pub trait AsyncPlatformHook<D: DMAMapping> {
    async fn run(self, dma_mapping: &'static D) -> bool;
}

/// No-op hook for platforms that don't need extra image-loading steps.
pub struct NoExtraSteps;

impl<D: DMAMapping> AsyncPlatformHook<D> for NoExtraSteps {
    async fn run(self, _dma_mapping: &'static D) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Platform-agnostic image loading logic
// ---------------------------------------------------------------------------

/// Performs PLDM streaming boot and PLDM discovery/update tests.
/// Flash-based boot is handled by each platform's own hook.
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
        pldm_image_loader.finalize()?;
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

// ---------------------------------------------------------------------------
// Flash-based boot (generic over BootConfigAsync)
// ---------------------------------------------------------------------------

/// Flash-based image loading, generic over the boot config type.
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
        active
    };

    let flash_syscall = SpiFlash::new(load_partition.1.driver_num);
    let flash_image_loader = FlashImageLoader::new(flash_syscall, dma_mapping);

    if let Some(_pending) = pending {
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

// ---------------------------------------------------------------------------
// activate_soc_images
// ---------------------------------------------------------------------------

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
        mcu_fw_image_size: 0,
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
