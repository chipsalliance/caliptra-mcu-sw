// Licensed under the Apache-2.0 license

extern crate alloc;
use alloc::boxed::Box;
#[cfg(any(feature = "streaming-boot", feature = "flash-boot"))]
use alloc::vec::Vec;

#[cfg(any(
    feature = "test-pldm-discovery",
    feature = "test-pldm-fw-update",
    feature = "test-pldm-fw-update-e2e"
))]
mod pldm_fdops_mock;

mod config;

use async_trait::async_trait;
use caliptra_api::mailbox::{
    ActivateFirmwareReq, ActivateFirmwareResp, CommandId, MailboxReqHeader,
};
#[allow(unused)]
use caliptra_mcu_config::boot;
#[allow(unused)]
use caliptra_mcu_config::boot::{BootConfigAsync, PartitionId, PartitionStatus, RollbackEnable};
#[allow(unused)]
use caliptra_mcu_config_emulator::flash::{
    PartitionTable, StandAloneChecksumCalculator, IMAGE_A_PARTITION, IMAGE_B_PARTITION,
    PARTITION_TABLE,
};
#[allow(unused)]
use caliptra_mcu_libapi_emulated_caliptra::image_loading::flash_boot_cfg::FlashBootConfig;
use caliptra_mcu_libsyscall_caliptra::dma::{AXIAddr, DMAMapping};
#[allow(unused)]
use caliptra_mcu_libsyscall_caliptra::flash::SpiFlash;
use caliptra_mcu_libsyscall_caliptra::mailbox::{Mailbox, MailboxError};
#[allow(unused)]
use caliptra_mcu_libsyscall_caliptra::system::{FirmwareBootType, System};
use caliptra_mcu_libtock_console::Console;
use caliptra_mcu_libtock_platform::ErrorCode;
use caliptra_mcu_measurement_api::BootKind;
#[cfg(any(feature = "streaming-boot", feature = "flash-boot"))]
use caliptra_mcu_measurement_api::{ImageHashSource, ImageMetadata};
#[allow(unused)]
#[cfg(any(
    feature = "streaming-boot",
    feature = "test-pldm-discovery",
    feature = "test-pldm-fw-update",
    feature = "test-pldm-fw-update-e2e",
    feature = "test-pldm-streaming-boot"
))]
use caliptra_mcu_pldm_common::message::firmware_update::verify_complete::VerifyResult;
#[allow(unused)]
#[cfg(any(
    feature = "streaming-boot",
    feature = "test-pldm-discovery",
    feature = "test-pldm-fw-update",
    feature = "test-pldm-fw-update-e2e",
    feature = "test-pldm-streaming-boot"
))]
use caliptra_mcu_pldm_lib::daemon::PldmService;
#[cfg(any(feature = "streaming-boot", feature = "flash-boot"))]
use caliptra_mcu_scratch_alloc::{BitmapAllocator, BITMAP_SLOT_SIZE};
#[allow(unused_imports)]
use core::fmt::Write;
#[cfg(any(feature = "streaming-boot", feature = "flash-boot"))]
use core::ptr::NonNull;

#[allow(unused)]
use crate::EXECUTOR;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
#[allow(unused)]
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
#[allow(unused)]
use embassy_sync::{lazy_lock::LazyLock, signal::Signal};
#[allow(unused)]
#[cfg(not(any(
    feature = "streaming-boot",
    feature = "test-pldm-discovery",
    feature = "test-pldm-fw-update",
    feature = "test-pldm-fw-update-e2e",
    feature = "test-pldm-streaming-boot"
)))]
use mcu_caliptra_api::image_loader::{dma_transfer::DmaTransfer, FlashImageLoader, ImageLoader};
#[allow(unused)]
#[cfg(any(
    feature = "streaming-boot",
    feature = "test-pldm-discovery",
    feature = "test-pldm-fw-update",
    feature = "test-pldm-fw-update-e2e",
    feature = "test-pldm-streaming-boot"
))]
use mcu_caliptra_api::image_loader::{
    dma_transfer::DmaTransfer, FlashImageLoader, ImageLoader, PldmFirmwareDeviceParams,
    PldmImageLoader,
};
#[allow(unused)]
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[allow(dead_code)]
const RESET_REASON_FW_HITLESS_UPD_RESET_MASK: u32 = 0x1;
#[cfg(any(feature = "streaming-boot", feature = "flash-boot"))]
const IMAGE_LOAD_MEASUREMENT_SCRATCH_SIZE: usize = 4096;
#[cfg(any(feature = "streaming-boot", feature = "flash-boot"))]
const IMAGE_LOAD_MEASUREMENT_SCRATCH_SLOTS: usize =
    IMAGE_LOAD_MEASUREMENT_SCRATCH_SIZE / BITMAP_SLOT_SIZE;

#[cfg(any(feature = "streaming-boot", feature = "flash-boot"))]
#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct ImageLoadMeasurementScratchSlot([u8; BITMAP_SLOT_SIZE]);

#[embassy_executor::task]
#[allow(unused_variables)]
pub async fn image_loading_task(soc_image_load_list: &'static [u32]) {
    if cfg!(feature = "test-xtask-runtime") {
        System::exit(0);
    }

    let mbox_sram = caliptra_mcu_libsyscall_caliptra::mbox_sram::MboxSram::<DefaultSyscalls>::new(
        caliptra_mcu_libsyscall_caliptra::mbox_sram::DRIVER_NUM_MCU_MBOX1_SRAM,
    );
    let boot_kind = crate::measurement::reset_boot_kind().unwrap_or(BootKind::ColdBoot);
    let mcu_fw_hitless_update_reset = boot_kind == BootKind::HitlessUpdate;
    if mcu_fw_hitless_update_reset {
        // Device rebooted due to firmware update
        // MCU SRAM lock is acquired prior to rebooting the device
        // The lock is needed so that Caliptra can write the updated firmware from MCU MBOX SRAM to MCU SRAM
        // After the update reboot, lock is no longer needed, so release it here
        mbox_sram.release_lock().unwrap();
    }
    #[cfg(any(
        feature = "streaming-boot",
        all(feature = "flash-boot", not(feature = "firmware-update")),
        feature = "test-pldm-discovery",
        feature = "test-pldm-fw-update",
        feature = "test-pldm-fw-update-e2e",
        feature = "test-streaming-boot-flash-write-back",
        feature = "test-mctp-spdm-attestation-hitless",
        feature = "test-mctp-spdm-attestation-hitless-tcb",
        feature = "test-mctp-spdm-attestation-hitless-mixed",
    ))]
    {
        // Release SRAM lock, in case previous session hasn't released it
        // If MCU is not the lock owner, then this should be no-op
        if mbox_sram.acquire_lock().is_err() {
            mbox_sram.release_lock().unwrap();
            mbox_sram.acquire_lock().unwrap();
        }
        match image_loading(
            &EMULATED_DMA_MAPPING,
            soc_image_load_list,
            mcu_fw_hitless_update_reset,
            boot_kind,
        )
        .await
        {
            Ok(_) => {}
            Err(_) => {
                let mut console_writer = Console::<DefaultSyscalls>::writer();
                crate::log_error!(console_writer, "IMAGE_LOADER_APP: image_loading failed");
                System::exit(1);
            }
        }
        mbox_sram.release_lock().unwrap();
        if hitless_attestation_test_enabled() {
            emit_attestation_evidence_ready();
            #[cfg(any(
                feature = "test-mctp-spdm-attestation-hitless",
                feature = "test-mctp-spdm-attestation-hitless-tcb",
                feature = "test-mctp-spdm-attestation-hitless-mixed"
            ))]
            if !mcu_fw_hitless_update_reset {
                EXECUTOR
                    .get()
                    .spawner()
                    .spawn(hitless_attestation_firmware_update_task(
                        soc_image_load_list,
                    ))
                    .map_err(|_| System::exit(1))
                    .ok();
            }
            return;
        }
        emit_attestation_evidence_ready();
        #[cfg(all(
            not(feature = "firmware-update"),
            not(feature = "test-mctp-spdm-attestation"),
            not(feature = "test-mctp-spdm-attestation-tcb"),
            not(feature = "test-mctp-spdm-attestation-mixed")
        ))]
        System::exit(0);
    }
    // After image loading, proceed to firmware update if enabled
    #[cfg(all(
        any(
            feature = "test-firmware-activate",
            feature = "test-firmware-update-streaming"
        ),
        not(feature = "test-mctp-spdm-attestation"),
        not(feature = "test-mctp-spdm-attestation-tcb"),
        not(feature = "test-mctp-spdm-attestation-mixed")
    ))]
    {
        if mbox_sram.acquire_lock().is_err() {
            mbox_sram.release_lock().unwrap();
            mbox_sram.acquire_lock().unwrap();
        }
        match crate::firmware_update::firmware_update(&FPGA_DMA_MAPPING, soc_image_load_list).await
        {
            Ok(_) => System::exit(0),
            Err(_) => System::exit(1),
        }
        // MBOX SRAM lock will be released after reboot
    }
    #[cfg(all(
        feature = "firmware-update",
        not(feature = "test-firmware-update-streaming"),
        not(feature = "test-mctp-spdm-attestation"),
        not(feature = "test-mctp-spdm-attestation-tcb"),
        not(feature = "test-mctp-spdm-attestation-mixed"),
        not(feature = "test-mctp-spdm-attestation-hitless"),
        not(feature = "test-mctp-spdm-attestation-hitless-tcb"),
        not(feature = "test-mctp-spdm-attestation-hitless-mixed")
    ))]
    {
        if mbox_sram.acquire_lock().is_err() {
            mbox_sram.release_lock().unwrap();
            mbox_sram.acquire_lock().unwrap();
        }
        match crate::firmware_update::firmware_update(&EMULATED_DMA_MAPPING, soc_image_load_list)
            .await
        {
            Ok(_) => System::exit(0),
            Err(_) => System::exit(1),
        }
        // MBOX SRAM lock will be released after reboot
    }
}

#[allow(dead_code)]
#[allow(unused_variables)]
async fn image_loading<D: DMAMapping>(
    dma_mapping: &'static D,
    soc_image_load_list: &'static [u32],
    mcu_fw_hitless_update_reset: bool,
    boot_kind: BootKind,
) -> Result<(), ErrorCode> {
    let mut console_writer = Console::<DefaultSyscalls>::writer();
    crate::log_info!(console_writer, "IMAGE_LOADER_APP: Hello async world!");
    #[cfg(any(feature = "streaming-boot", feature = "flash-boot"))]
    let mut scratch = Vec::new();
    #[cfg(any(feature = "streaming-boot", feature = "flash-boot"))]
    scratch
        .try_reserve_exact(IMAGE_LOAD_MEASUREMENT_SCRATCH_SLOTS)
        .map_err(|_| ErrorCode::Fail)?;
    #[cfg(any(feature = "streaming-boot", feature = "flash-boot"))]
    scratch.resize(
        IMAGE_LOAD_MEASUREMENT_SCRATCH_SLOTS,
        ImageLoadMeasurementScratchSlot([0; BITMAP_SLOT_SIZE]),
    );
    #[cfg(any(feature = "streaming-boot", feature = "flash-boot"))]
    let Some(scratch_ptr) = NonNull::new(scratch.as_mut_ptr().cast::<u8>()) else {
        return Err(ErrorCode::Fail);
    };
    #[cfg(any(feature = "streaming-boot", feature = "flash-boot"))]
    let allocator =
        unsafe { BitmapAllocator::new(scratch_ptr, IMAGE_LOAD_MEASUREMENT_SCRATCH_SIZE) };

    #[cfg(any(feature = "streaming-boot", feature = "flash-boot"))]
    let firmware_boot_type = {
        #[cfg(all(feature = "streaming-boot", feature = "flash-boot"))]
        {
            match System::firmware_boot_type() {
                Ok(boot_type) => boot_type,
                Err(ErrorCode::NoSupport) => FirmwareBootType::Streaming,
                Err(error) => return Err(error),
            }
        }
        #[cfg(all(feature = "streaming-boot", not(feature = "flash-boot")))]
        {
            FirmwareBootType::Streaming
        }
        #[cfg(all(feature = "flash-boot", not(feature = "streaming-boot")))]
        {
            FirmwareBootType::Flash
        }
    };
    #[cfg(any(feature = "streaming-boot", feature = "flash-boot"))]
    match firmware_boot_type {
        FirmwareBootType::Unknown => return Err(ErrorCode::Invalid),
        FirmwareBootType::Streaming => {
            #[cfg(feature = "streaming-boot")]
            {
                let fw_params = PldmFirmwareDeviceParams {
                    descriptors: &config::streaming_boot_consts::DESCRIPTOR.get()[..],
                    fw_params: config::streaming_boot_consts::STREAMING_BOOT_FIRMWARE_PARAMS.get(),
                };
                let pldm_image_loader =
                    PldmImageLoader::new(&fw_params, EXECUTOR.get().spawner(), dma_mapping);
                let mut preamble_buf = allocator
                    .alloc_bytes(OWNER_PREAMBLE_RETAINED_SIZE)
                    .map_err(|_| ErrorCode::Fail)?;
                let set_result = pldm_image_loader
                    .set_owner_auth_manifest(preamble_buf.as_mut_slice())
                    .await;
                let load_result = match set_result {
                    Ok(retained_len) => {
                        let measure_res = measure_owner_artifacts(
                            &pldm_image_loader,
                            &allocator,
                            boot_kind,
                            &preamble_buf[..retained_len],
                        )
                        .await;
                        drop(preamble_buf);
                        match measure_res {
                            Ok(()) => {
                                load_soc_images(
                                    &pldm_image_loader,
                                    soc_image_load_list,
                                    false,
                                    &allocator,
                                )
                                .await
                            }
                            Err(error) => Err(error),
                        }
                    }
                    Err(error) => {
                        drop(preamble_buf);
                        Err(error)
                    }
                };
                if let Err(error) = load_result {
                    // Report load/authorization failure to the PLDM Update Agent
                    if pldm_image_loader
                        .finalize(VerifyResult::VerifyFailedFdSecurityChecks)
                        .is_ok()
                    {
                        pldm_image_loader.wait_for_service_stopped().await;
                    }
                    return Err(error);
                }
                // Close the PLDM session on success
                pldm_image_loader.finalize(VerifyResult::VerifySuccess)?;
                // Wait for the PLDM service to fully complete the protocol before proceeding
                pldm_image_loader.wait_for_service_stopped().await;
                // Activate the SoC Images (set FW_EXEC_CTRL bit of the corresponding SoC)
                activate_soc_images(soc_image_load_list).await?;
            }
            #[cfg(not(feature = "streaming-boot"))]
            return Err(ErrorCode::NoSupport);
        }
        FirmwareBootType::Flash => {
            #[cfg(feature = "flash-boot")]
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
                    if let Ok(pending_partition_id) = pending_partition_id {
                        let pending_partition = boot_config
                            .get_partition_from_id(pending_partition_id)
                            .map_err(|_| ErrorCode::Fail)?;

                        Some((pending_partition_id, pending_partition))
                    } else {
                        None
                    }
                };

                let load_partition =
                    if let Some((pending_partition_id, pending_partition)) = pending {
                        (pending_partition_id, pending_partition)
                    } else {
                        // No pending partition, use the active one
                        active
                    };

                let buffered_dma =
                    FlashReaderDma::new(SpiFlash::new(load_partition.1.driver_num), dma_mapping);
                let flash_syscall = SpiFlash::new(load_partition.1.driver_num);
                let flash_image_loader = FlashImageLoader::new(flash_syscall, &buffered_dma);
                let component_update = pending.is_some() && mcu_fw_hitless_update_reset;

                if pending.is_some() && !mcu_fw_hitless_update_reset {
                    // In the full MCU firmware-update hitless path, FirmwareUpdater already
                    // sets the auth manifest before reset. Keep this call for direct
                    // pending-partition boot and future SoC-only update paths until the
                    // platform owns an explicit "auth manifest already set" signal.
                    // Depending on whether the SoC manifest preamble DPE contexts are
                    // updated during hitless update, setting the manifest here may also
                    // create mismatched journey measurements.
                    flash_image_loader.set_auth_manifest().await?;
                }

                let mut preamble_buf = allocator
                    .alloc_bytes(OWNER_PREAMBLE_RETAINED_SIZE)
                    .map_err(|_| ErrorCode::Fail)?;
                let retained_len = flash_image_loader
                    .set_owner_auth_manifest(preamble_buf.as_mut_slice())
                    .await?;
                let measure_res = measure_owner_artifacts(
                    &flash_image_loader,
                    &allocator,
                    boot_kind,
                    &preamble_buf[..retained_len],
                )
                .await;
                drop(preamble_buf);
                measure_res?;
                load_soc_images(
                    &flash_image_loader,
                    soc_image_load_list,
                    component_update,
                    &allocator,
                )
                .await?;
                boot_config
                    .set_partition_status(load_partition.0, PartitionStatus::BootSuccessful)
                    .await
                    .map_err(|_| ErrorCode::Fail)?;
                boot_config
                    .set_active_partition(load_partition.0)
                    .await
                    .map_err(|_| ErrorCode::Fail)?;
                #[cfg(any(
                    feature = "test-mctp-spdm-attestation",
                    feature = "test-mctp-spdm-attestation-tcb",
                    feature = "test-mctp-spdm-attestation-mixed",
                    feature = "test-mctp-spdm-attestation-hitless",
                    feature = "test-mctp-spdm-attestation-hitless-tcb",
                    feature = "test-mctp-spdm-attestation-hitless-mixed"
                ))]
                {
                    return Ok(());
                }
                activate_soc_images(soc_image_load_list).await?;
            }
            #[cfg(not(feature = "flash-boot"))]
            return Err(ErrorCode::NoSupport);
        }
        FirmwareBootType::Network => return Err(ErrorCode::NoSupport),
    }

    #[cfg(any(
        feature = "test-pldm-discovery",
        feature = "test-pldm-fw-update",
        feature = "test-pldm-fw-update-e2e"
    ))]
    {
        let fdops = pldm_fdops_mock::FdOpsObject::new();
        let mut pldm_service = PldmService::init(&fdops, EXECUTOR.get().spawner());
        crate::log_info!(
            console_writer,
            "PLDM_APP: Starting PLDM service for testing..."
        );
        if let Err(e) = pldm_service.start().await {
            crate::log_error!(
                console_writer,
                "PLDM_APP: Error starting PLDM service: {}",
                crate::Dbg(e)
            );
        }
        pldm_fdops_mock::FdOpsObject::wait_for_pldm_done().await;
    }
    Ok(())
}

#[cfg(any(feature = "streaming-boot", feature = "flash-boot"))]
const OWNER_PREAMBLE_RETAINED_SIZE: usize = 2708;

#[cfg(any(feature = "streaming-boot", feature = "flash-boot"))]
#[repr(C)]
#[derive(IntoBytes, FromBytes, Immutable, KnownLayout, Clone, Copy, Debug, Default)]
struct OwnerPreambleHeader {
    marker: u32,
    size: u32,
    version: u32,
    svn: u32,
    flags: u32,
}

#[cfg(any(feature = "streaming-boot", feature = "flash-boot"))]
async fn measure_owner_soc_manifest_preamble<A: mcu_caliptra_api::ApiAlloc>(
    preamble_bytes: &[u8],
    allocator: &A,
    boot_kind: caliptra_mcu_measurement_api::BootKind,
) -> Result<(), ErrorCode> {
    use caliptra_auth_man_types::{OwnerAuthManifestPreamble, OWNER_AUTH_MANIFEST_MARKER};
    use caliptra_mcu_measurement_api::{measure_owsm, IMAGE_MEASUREMENT_DIGEST_SIZE};
    use mcu_caliptra_api::{hash_all, HashAlgo};

    let signed_range = OwnerAuthManifestPreamble::owner_signed_data_range();
    let signed_start = signed_range.start as usize;
    let signed_end = signed_range.end as usize;

    if preamble_bytes.len() < signed_end {
        return Err(ErrorCode::Fail);
    }

    let header = OwnerPreambleHeader::read_from_bytes(
        preamble_bytes
            .get(..core::mem::size_of::<OwnerPreambleHeader>())
            .ok_or(ErrorCode::Fail)?,
    )
    .map_err(|_| ErrorCode::Fail)?;
    if header.marker != OWNER_AUTH_MANIFEST_MARKER {
        return Err(ErrorCode::Fail);
    }
    let svn = header.svn;

    let signed_bytes = preamble_bytes
        .get(signed_start..signed_end)
        .ok_or(ErrorCode::Fail)?;

    let mut preamble_digest = [0u8; IMAGE_MEASUREMENT_DIGEST_SIZE];
    hash_all(
        allocator,
        HashAlgo::Sha384,
        signed_bytes,
        &mut preamble_digest,
    )
    .await
    .map_err(|_| ErrorCode::Fail)?;

    measure_owsm(allocator, &preamble_digest, svn, boot_kind)
        .await
        .map_err(|_| ErrorCode::Fail)?;

    Ok(())
}

#[cfg(any(feature = "streaming-boot", feature = "flash-boot"))]
static mut OWNER_POLICY_BUFFER: [u8;
    crate::soc_image_descriptors::OWNER_MEASUREMENT_POLICY_MAX_SIZE] =
    [0u8; crate::soc_image_descriptors::OWNER_MEASUREMENT_POLICY_MAX_SIZE];

#[cfg(any(feature = "streaming-boot", feature = "flash-boot"))]
async fn read_owner_measurement_policy(
    loader: &impl ImageLoader,
) -> Result<&'static [u8], ErrorCode> {
    use caliptra_mcu_measurement_api::OWNER_MEASUREMENT_POLICY_IDENTIFIER;

    let policy_size = loader
        .component_size(OWNER_MEASUREMENT_POLICY_IDENTIFIER)
        .await?;
    if policy_size == 0
        || policy_size > crate::soc_image_descriptors::OWNER_MEASUREMENT_POLICY_MAX_SIZE
    {
        return Err(ErrorCode::Fail);
    }

    // Safety: single-threaded Tock user app during sequential boot image loading.
    // OWNER_POLICY_BUFFER is populated once from the loader and retained for the lifetime of the app.
    unsafe {
        #[allow(static_mut_refs)]
        let buf = &mut OWNER_POLICY_BUFFER[..policy_size];
        let read_len = loader
            .read_raw_component(OWNER_MEASUREMENT_POLICY_IDENTIFIER, 0, buf)
            .await?;
        if read_len != policy_size {
            return Err(ErrorCode::Fail);
        }
        #[allow(static_mut_refs)]
        Ok(&OWNER_POLICY_BUFFER[..policy_size])
    }
}

#[cfg(any(feature = "streaming-boot", feature = "flash-boot"))]
async fn authenticate_and_measure_owner_artifacts<A: mcu_caliptra_api::ApiAlloc>(
    static_policy_bytes: &'static [u8],
    allocator: &A,
    boot_kind: caliptra_mcu_measurement_api::BootKind,
    retained_preamble: &[u8],
) -> Result<(), ErrorCode> {
    use caliptra_mcu_measurement_api::{
        measure_owner_measurement_policy, validate_and_set_owner_policy, BootKind,
        IMAGE_MEASUREMENT_DIGEST_SIZE, OWNER_MEASUREMENT_POLICY_IDENTIFIER,
    };
    use mcu_caliptra_api::{core_image_info, hash_all, HashAlgo};

    let mut policy_digest = [0u8; IMAGE_MEASUREMENT_DIGEST_SIZE];
    hash_all(
        allocator,
        HashAlgo::Sha384,
        static_policy_bytes,
        &mut policy_digest,
    )
    .await
    .map_err(|_| ErrorCode::Fail)?;

    let policy_image_info = core_image_info(OWNER_MEASUREMENT_POLICY_IDENTIFIER)
        .await
        .map_err(|_| ErrorCode::Fail)?;
    if policy_digest != policy_image_info.digest {
        return Err(ErrorCode::Fail);
    }

    validate_and_set_owner_policy(static_policy_bytes)
        .await
        .map_err(|_| ErrorCode::Fail)?;

    if boot_kind == BootKind::HitlessUpdate {
        measure_owner_measurement_policy(allocator, &policy_digest, boot_kind)
            .await
            .map_err(|_| ErrorCode::Fail)?;
    }

    measure_owner_soc_manifest_preamble(retained_preamble, allocator, boot_kind).await?;
    if boot_kind == BootKind::ColdBoot {
        measure_owner_measurement_policy(allocator, &policy_digest, boot_kind)
            .await
            .map_err(|_| ErrorCode::Fail)?;
    }
    measure_owner_auth_key_component(allocator, boot_kind).await?;
    Ok(())
}

#[cfg(any(feature = "streaming-boot", feature = "flash-boot"))]
async fn measure_owner_auth_key_component<A: mcu_caliptra_api::ApiAlloc>(
    allocator: &A,
    boot_kind: caliptra_mcu_measurement_api::BootKind,
) -> Result<(), ErrorCode> {
    use caliptra_mcu_measurement_api::{measure_owner_auth_key, O_AUTH_KEY_ID};
    use mcu_caliptra_api::core_image_info;

    let owner_key_info = core_image_info(O_AUTH_KEY_ID)
        .await
        .map_err(|_| ErrorCode::Fail)?;
    measure_owner_auth_key(allocator, &owner_key_info.digest, boot_kind)
        .await
        .map_err(|_| ErrorCode::Fail)?;

    Ok(())
}

#[cfg(any(feature = "streaming-boot", feature = "flash-boot"))]
async fn measure_owner_artifacts<A: mcu_caliptra_api::ApiAlloc>(
    loader: &impl ImageLoader,
    allocator: &A,
    boot_kind: caliptra_mcu_measurement_api::BootKind,
    retained_preamble: &[u8],
) -> Result<(), ErrorCode> {
    let static_policy_bytes = read_owner_measurement_policy(loader).await?;
    authenticate_and_measure_owner_artifacts(
        static_policy_bytes,
        allocator,
        boot_kind,
        retained_preamble,
    )
    .await
}

#[cfg(any(feature = "streaming-boot", feature = "flash-boot"))]
async fn load_soc_images<A: mcu_caliptra_api::ApiAlloc>(
    loader: &impl ImageLoader,
    soc_image_load_list: &'static [u32],
    component_update: bool,
    allocator: &A,
) -> Result<(), ErrorCode> {
    for fw_id in soc_image_load_list {
        let loaded = loader.load(*fw_id).await?;
        let metadata = if component_update {
            ImageMetadata::component_update(
                ImageHashSource::LoadAddress,
                loaded.image_size,
                loaded.measurement,
                0,
                0,
            )
        } else {
            ImageMetadata::initial_load_from_load_address(loaded.image_size, loaded.measurement)
        };
        caliptra_mcu_measurement_api::authorize_and_stash(allocator, *fw_id, metadata)
            .await
            .inspect_err(|_| {
                let mut console_writer = Console::<DefaultSyscalls>::writer();
                crate::log_error!(
                    console_writer,
                    "IMAGE_LOADER_APP: authorize_and_stash failed for 0x{}",
                    crate::Hex32(*fw_id)
                );
            })
            .map_err(|_| ErrorCode::Fail)?;
    }
    if !component_update {
        caliptra_mcu_measurement_api::mark_initial_soc_load_complete()
            .await
            .inspect_err(|_| {
                let mut console_writer = Console::<DefaultSyscalls>::writer();
                crate::log_error!(
                    console_writer,
                    "IMAGE_LOADER_APP: mark initial SoC load complete failed"
                );
            })
            .map_err(|_| ErrorCode::Fail)?;
    }
    Ok(())
}

#[cfg(any(
    feature = "test-mctp-spdm-attestation",
    feature = "test-mctp-spdm-attestation-tcb",
    feature = "test-mctp-spdm-attestation-mixed",
    feature = "test-mctp-spdm-attestation-hitless",
    feature = "test-mctp-spdm-attestation-hitless-tcb",
    feature = "test-mctp-spdm-attestation-hitless-mixed"
))]
fn emit_attestation_evidence_ready() {
    let mut console_writer = Console::<DefaultSyscalls>::writer();
    let _ = writeln!(console_writer, "ATTESTATION_EVIDENCE_READY");
}

#[cfg(not(any(
    feature = "test-mctp-spdm-attestation",
    feature = "test-mctp-spdm-attestation-tcb",
    feature = "test-mctp-spdm-attestation-mixed",
    feature = "test-mctp-spdm-attestation-hitless",
    feature = "test-mctp-spdm-attestation-hitless-tcb",
    feature = "test-mctp-spdm-attestation-hitless-mixed"
)))]
#[allow(dead_code)]
fn emit_attestation_evidence_ready() {}

#[allow(dead_code)]
#[cfg(any(
    feature = "test-mctp-spdm-attestation-hitless",
    feature = "test-mctp-spdm-attestation-hitless-tcb",
    feature = "test-mctp-spdm-attestation-hitless-mixed"
))]
fn hitless_attestation_test_enabled() -> bool {
    true
}

#[allow(dead_code)]
#[cfg(not(any(
    feature = "test-mctp-spdm-attestation-hitless",
    feature = "test-mctp-spdm-attestation-hitless-tcb",
    feature = "test-mctp-spdm-attestation-hitless-mixed"
)))]
fn hitless_attestation_test_enabled() -> bool {
    false
}

#[cfg(any(
    feature = "test-mctp-spdm-attestation-hitless",
    feature = "test-mctp-spdm-attestation-hitless-tcb",
    feature = "test-mctp-spdm-attestation-hitless-mixed"
))]
#[embassy_executor::task]
async fn hitless_attestation_firmware_update_task(soc_image_load_list: &'static [u32]) {
    let mbox_sram = caliptra_mcu_libsyscall_caliptra::mbox_sram::MboxSram::<DefaultSyscalls>::new(
        caliptra_mcu_libsyscall_caliptra::mbox_sram::DRIVER_NUM_MCU_MBOX1_SRAM,
    );
    if mbox_sram.acquire_lock().is_err() {
        mbox_sram.release_lock().unwrap();
        mbox_sram.acquire_lock().unwrap();
    }
    if crate::firmware_update::firmware_update(&EMULATED_DMA_MAPPING, soc_image_load_list)
        .await
        .is_err()
    {
        System::exit(1);
    }
}

#[allow(dead_code)]
async fn activate_soc_images(fw_id_list: &[u32]) -> Result<(), ErrorCode> {
    if fw_id_list.is_empty() {
        return Ok(());
    }

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
        flags: 0,
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

pub struct EmulatedDMAMap {}
impl DMAMapping for EmulatedDMAMap {
    fn mcu_sram_to_mcu_axi(&self, addr: u32) -> Result<AXIAddr, ErrorCode> {
        Ok(addr as AXIAddr)
    }

    fn cptra_axi_to_mcu_axi(&self, addr: AXIAddr) -> Result<AXIAddr, ErrorCode> {
        // Caliptra's External Test SRAM at 0x8000_0000 maps to
        // the MCU's External SRAM at 0xB00C_0000 (same backing store via events).
        const CPTRA_EXT_SRAM_BASE: u64 = 0x8000_0000;
        const CPTRA_EXT_SRAM_SIZE: u64 = 0x0010_0000; // 1MB
        const MCU_EXT_SRAM_BASE: u64 = 0xB00C_0000;
        if (CPTRA_EXT_SRAM_BASE..CPTRA_EXT_SRAM_BASE + CPTRA_EXT_SRAM_SIZE).contains(&addr) {
            Ok(MCU_EXT_SRAM_BASE + (addr - CPTRA_EXT_SRAM_BASE))
        } else {
            Ok(addr)
        }
    }
}

#[allow(dead_code)]
pub static EMULATED_DMA_MAPPING: EmulatedDMAMap = EmulatedDMAMap {};

pub struct FpgaDMAMap {}
impl DMAMapping for FpgaDMAMap {
    fn mcu_sram_to_mcu_axi(&self, addr: u32) -> Result<AXIAddr, ErrorCode> {
        Ok(addr as AXIAddr)
    }

    fn cptra_axi_to_mcu_axi(&self, addr: AXIAddr) -> Result<AXIAddr, ErrorCode> {
        // FPGA: Caliptra and MCU share the same AXI address space
        Ok(addr)
    }
}

#[allow(dead_code)]
pub static FPGA_DMA_MAPPING: FpgaDMAMap = FpgaDMAMap {};

/// This is the size of the buffer used for DMA transfers.
const MAX_DMA_TRANSFER_SIZE: usize = 128;

/// Flash-backed DmaTransfer that buffers through SRAM.
/// Reads from SPI flash into a stack buffer, then
/// DMAs from the buffer to the destination.
pub struct FlashReaderDma<D: DMAMapping + 'static> {
    flash: SpiFlash,
    dma_mapping: &'static D,
}

#[allow(dead_code)]
impl<D: DMAMapping + 'static> FlashReaderDma<D> {
    pub fn new(flash: SpiFlash, dma_mapping: &'static D) -> Self {
        Self { flash, dma_mapping }
    }
}

impl<D: DMAMapping + 'static> DMAMapping for FlashReaderDma<D> {
    fn mcu_sram_to_mcu_axi(&self, sram_addr: u32) -> Result<AXIAddr, ErrorCode> {
        self.dma_mapping.mcu_sram_to_mcu_axi(sram_addr)
    }

    fn cptra_axi_to_mcu_axi(&self, cptra_addr: u64) -> Result<AXIAddr, ErrorCode> {
        self.dma_mapping.cptra_axi_to_mcu_axi(cptra_addr)
    }
}

#[async_trait(?Send)]
impl<D: DMAMapping + 'static> DmaTransfer for FlashReaderDma<D> {
    fn max_transfer_size(&self) -> usize {
        MAX_DMA_TRANSFER_SIZE
    }

    async fn transfer(
        &self,
        src_offset: usize,
        dest_addr: AXIAddr,
        length: usize,
    ) -> Result<(), ErrorCode> {
        use caliptra_mcu_libsyscall_caliptra::dma::{DMASource, DMATransaction, DMA as DMASyscall};
        let dma_syscall: DMASyscall = DMASyscall::new();
        let mut buffer = [0u8; MAX_DMA_TRANSFER_SIZE];
        self.flash
            .read(src_offset, length, &mut buffer[..length])
            .await?;
        let source_address = self
            .dma_mapping
            .mcu_sram_to_mcu_axi(buffer.as_ptr() as u32)?;
        dma_syscall
            .xfer(&DMATransaction {
                byte_count: length,
                source: DMASource::Address(source_address),
                dest_addr,
            })
            .await
    }
}
