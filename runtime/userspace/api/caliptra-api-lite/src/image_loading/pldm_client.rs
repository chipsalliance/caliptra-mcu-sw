// Licensed under the Apache-2.0 license

use caliptra_mcu_flash_image::{FlashHeader, ImageHeader};
use caliptra_mcu_libsyscall_caliptra::dma::{AXIAddr, DMAMapping};
use caliptra_mcu_pldm_common::message::firmware_update::get_fw_params::FirmwareParameters;
use caliptra_mcu_pldm_common::message::firmware_update::verify_complete::VerifyResult;
use caliptra_mcu_pldm_common::protocol::firmware_update::Descriptor;
use caliptra_mcu_pldm_lib::daemon::{wait_until_stopped, PldmService};
use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use mcu_error::McuResult;
use zerocopy::FromBytes;

use crate::errors::image_loading as image_errors;

use super::pldm_context::{State, DOWNLOAD_CTX, PLDM_STATE};
use super::pldm_fdops::StreamingFdOps;

const MAX_IMAGE_COUNT: usize = 127;

pub static PLDM_TASK_YIELD: Signal<CriticalSectionRawMutex, ()> = Signal::new();
pub static IMAGE_LOADING_TASK_YIELD: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static PLDM_SERVICE_STOPPED: Signal<CriticalSectionRawMutex, ()> = Signal::new();

#[embassy_executor::task]
async fn pldm_service_task(
    descriptors: &'static [Descriptor],
    fw_params: &'static FirmwareParameters,
    dma_mapping: &'static dyn DMAMapping,
    spawner: Spawner,
) {
    pldm_service(descriptors, fw_params, dma_mapping, spawner).await;
}

async fn pldm_service(
    descriptors: &'static [Descriptor],
    fw_params: &'static FirmwareParameters,
    dma_mapping: &'static dyn DMAMapping,
    spawner: Spawner,
) {
    let pldm_ops = StreamingFdOps::new(descriptors, fw_params, dma_mapping);
    let mut pldm_service_init: PldmService = PldmService::init(&pldm_ops, spawner);
    if pldm_service_init.start().await.is_err() {
        PLDM_STATE.lock(|state| {
            let mut state = state.borrow_mut();
            *state = State::NotRunning;
        });
        IMAGE_LOADING_TASK_YIELD.signal(());
    } else {
        wait_until_stopped().await;
        PLDM_SERVICE_STOPPED.signal(());
    }
}

async fn pldm_download_header() -> McuResult<()> {
    PLDM_STATE.lock(|state| {
        let mut state = state.borrow_mut();
        *state = State::DownloadingHeader;
    });
    DOWNLOAD_CTX.lock(|ctx| {
        let mut ctx = ctx.borrow_mut();
        ctx.total_length = core::mem::size_of::<FlashHeader>();
        ctx.initial_offset = 0;
        ctx.current_offset = 0;
        ctx.total_downloaded = 0;
    });

    PLDM_TASK_YIELD.signal(());
    IMAGE_LOADING_TASK_YIELD.wait().await;
    let state = PLDM_STATE.lock(|state| *state.borrow());
    if state != State::HeaderDownloadComplete {
        return Err(image_errors::PLDM_UNEXPECTED_STATE);
    }

    let num_images = DOWNLOAD_CTX.lock(|ctx| {
        let ctx = ctx.borrow();
        FlashHeader::ref_from_prefix(&ctx.header)
            .map(|(header, _)| header.image_count as usize)
            .map_err(|_| image_errors::INVALID_FLASH_HEADER)
    })?;

    if num_images > MAX_IMAGE_COUNT {
        return Err(image_errors::PLDM_IMAGE_COUNT_TOO_LARGE);
    }
    Ok(())
}

pub async fn pldm_download_toc(component_id: u32) -> McuResult<(u32, u32)> {
    let num_images = DOWNLOAD_CTX.lock(|ctx| {
        let ctx = ctx.borrow();
        FlashHeader::ref_from_prefix(&ctx.header)
            .map(|(header, _)| header.image_count as usize)
            .map_err(|_| image_errors::INVALID_FLASH_HEADER)
    })?;

    PLDM_STATE.lock(|state| {
        let mut state = state.borrow_mut();
        *state = State::DownloadingToc;
    });

    let mut image_offset_and_size = None;
    for index in 0..num_images {
        let initial_offset = core::mem::size_of::<FlashHeader>()
            .checked_add(
                index
                    .checked_mul(core::mem::size_of::<ImageHeader>())
                    .ok_or(image_errors::IMAGE_OFFSET_OVERFLOW)?,
            )
            .ok_or(image_errors::IMAGE_OFFSET_OVERFLOW)?;
        DOWNLOAD_CTX.lock(|ctx| {
            let mut ctx = ctx.borrow_mut();
            ctx.total_length = core::mem::size_of::<ImageHeader>();
            ctx.initial_offset = initial_offset;
            ctx.current_offset = ctx.initial_offset;
            ctx.total_downloaded = 0;
        });

        loop {
            PLDM_TASK_YIELD.signal(());
            IMAGE_LOADING_TASK_YIELD.wait().await;
            let is_download_complete = PLDM_STATE.lock(|state| -> McuResult<bool> {
                let mut state = state.borrow_mut();
                if *state == State::TocDownloadComplete {
                    DOWNLOAD_CTX.lock(|ctx| -> McuResult<()> {
                        let ctx = ctx.borrow();
                        let (info, _) = ImageHeader::ref_from_prefix(&ctx.image_info)
                            .map_err(|_| image_errors::INVALID_IMAGE_HEADER)?;
                        if info.identifier == component_id {
                            image_offset_and_size = Some((info.offset, info.size));
                            *state = State::ImageDownloadReady;
                        } else {
                            *state = State::DownloadingToc;
                        }
                        Ok(())
                    })?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            })?;
            if is_download_complete {
                break;
            }
        }

        if let Some(offset_size) = image_offset_and_size {
            return Ok(offset_size);
        }
    }

    Err(image_errors::IMAGE_NOT_FOUND)
}

pub async fn pldm_download_image(load_address: AXIAddr, offset: u32, size: u32) -> McuResult<()> {
    PLDM_STATE.lock(|state| {
        let mut state = state.borrow_mut();
        *state = State::DownloadingImage;
    });

    DOWNLOAD_CTX.lock(|ctx| {
        let mut ctx = ctx.borrow_mut();
        ctx.total_length = size as usize;
        ctx.initial_offset = offset as usize;
        ctx.current_offset = offset as usize;
        ctx.total_downloaded = 0;
        ctx.load_address = load_address;
    });

    PLDM_TASK_YIELD.signal(());
    IMAGE_LOADING_TASK_YIELD.wait().await;
    let state = PLDM_STATE.lock(|state| *state.borrow());
    if state != State::ImageDownloadComplete {
        return Err(image_errors::PLDM_UNEXPECTED_STATE);
    }
    Ok(())
}

pub async fn initialize_pldm<D: DMAMapping + 'static>(
    spawner: Spawner,
    descriptors: &'static [Descriptor],
    fw_params: &'static FirmwareParameters,
    dma_mapping: &'static D,
) -> McuResult<()> {
    let is_initialized = PLDM_STATE.lock(|state| {
        let mut state = state.borrow_mut();
        if *state == State::NotRunning {
            *state = State::Initializing;
            false
        } else {
            true
        }
    });
    if !is_initialized {
        if descriptors.is_empty() {
            return Err(image_errors::PLDM_DESCRIPTORS_EMPTY);
        }
        PLDM_SERVICE_STOPPED.reset();
        spawner
            .spawn(pldm_service_task(
                descriptors,
                fw_params,
                dma_mapping,
                spawner,
            ))
            .map_err(|_| image_errors::PLDM_TASK_SPAWN_FAILED)?;

        IMAGE_LOADING_TASK_YIELD.wait().await;
        let state = PLDM_STATE.lock(|state| *state.borrow());
        if state != State::Initialized {
            return Err(image_errors::PLDM_SERVICE_START_FAILED);
        }

        return pldm_download_header().await;
    }
    Ok(())
}

pub async fn wait_service_stopped() {
    PLDM_SERVICE_STOPPED.wait().await;
}

pub fn finalize(verify_result: VerifyResult) -> McuResult<()> {
    DOWNLOAD_CTX.lock(|ctx| {
        let mut ctx = ctx.borrow_mut();
        ctx.download_complete = true;
        ctx.verify_result = verify_result;
    });
    PLDM_TASK_YIELD.signal(());
    Ok(())
}
