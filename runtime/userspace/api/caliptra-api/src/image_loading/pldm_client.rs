// Licensed under the Apache-2.0 license

extern crate alloc;
use crate::image_loading::pldm_context::State;
use crate::image_loading::pldm_fdops::StreamingFdOps;
use flash_image::{FlashHeader, ImageHeader};

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;

use embassy_executor::Spawner;
use embassy_sync::signal::Signal;
use libsyscall_caliptra::dma::{AXIAddr, DMAMapping};

use libtock_platform::ErrorCode;

use pldm_common::message::firmware_update::get_fw_params::FirmwareParameters;
use pldm_common::message::firmware_update::verify_complete::VerifyResult;
use pldm_common::protocol::firmware_update::Descriptor;
use pldm_lib::daemon::PldmService;
use pldm_lib::firmware_device::fd_ops::FdOps;

use zerocopy::FromBytes;

use super::pldm_context::{DOWNLOAD_CTX, PLDM_STATE};

const MAX_IMAGE_COUNT: u32 = 127;

pub static PLDM_TASK_YIELD: Signal<CriticalSectionRawMutex, ()> = Signal::new();
pub static IMAGE_LOADING_TASK_YIELD: Signal<CriticalSectionRawMutex, ()> = Signal::new();

#[embassy_executor::task]
async fn pldm_service_task(pldm_ops: &'static dyn FdOps, spawner: Spawner) {
    pldm_service(pldm_ops, spawner).await;
}

pub async fn pldm_service(pldm_ops: &'static dyn FdOps, spawner: Spawner) {
    let mut pldm_service_init: PldmService = PldmService::init(pldm_ops, spawner);
    pldm_service_init.start().await.unwrap();
}

async fn pldm_download_header() -> Result<(), ErrorCode> {
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
        return Err(ErrorCode::Fail);
    }

    let num_images = DOWNLOAD_CTX.lock(|ctx| {
        let ctx = ctx.borrow();
        let (header, _rest) = FlashHeader::ref_from_prefix(&ctx.header).unwrap();
        header.image_count as usize
    });

    if num_images > MAX_IMAGE_COUNT as usize {
        return Err(ErrorCode::Fail);
    }
    Ok(())
}

pub async fn pldm_download_toc(image_id: u32) -> Result<(u32, u32), ErrorCode> {
    let num_images = DOWNLOAD_CTX.lock(|ctx| {
        let ctx = ctx.borrow();
        let (header, _rest) = FlashHeader::ref_from_prefix(&ctx.header).unwrap();
        header.image_count as usize
    });

    // Set State to DownloadingToc
    PLDM_STATE.lock(|state| {
        let mut state = state.borrow_mut();
        *state = State::DownloadingToc;
    });

    let mut image_offset_and_size = None;
    for index in 0..num_images {
        DOWNLOAD_CTX.lock(|ctx| {
            let mut ctx = ctx.borrow_mut();
            ctx.total_length = core::mem::size_of::<ImageHeader>(); // image info length
            ctx.initial_offset =
                core::mem::size_of::<FlashHeader>() + index * core::mem::size_of::<ImageHeader>();
            ctx.current_offset = ctx.initial_offset;
            ctx.total_downloaded = 0;
        });

        // Wait for TOC DownloadComplete to be ready
        loop {
            PLDM_TASK_YIELD.signal(());
            IMAGE_LOADING_TASK_YIELD.wait().await;
            let is_dowload_complete = PLDM_STATE.lock(|state| {
                let mut state = state.borrow_mut();
                if *state == State::TocDownloadComplete {
                    DOWNLOAD_CTX.lock(|ctx| {
                        let ctx = ctx.borrow();
                        let (info, _rest) = ImageHeader::ref_from_prefix(&ctx.image_info).unwrap();
                        if info.identifier == image_id {
                            image_offset_and_size = Some((info.offset, info.size));
                            *state = State::ImageDownloadReady;
                        } else {
                            *state = State::DownloadingToc;
                        }
                    });

                    true
                } else {
                    false
                }
            });
            if is_dowload_complete {
                break;
            }
        }

        if image_offset_and_size.is_some() {
            break;
        }
    }

    match image_offset_and_size {
        Some(offset_size) => Ok(offset_size),
        None => Err(ErrorCode::Fail),
    }
}

pub async fn pldm_download_image(
    load_address: AXIAddr,
    offset: u32,
    size: u32,
) -> Result<(), ErrorCode> {
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
        return Err(ErrorCode::Fail);
    }
    Ok(())
}

pub async fn initialize_pldm<'a, D: DMAMapping + 'static>(
    spawner: Spawner,
    descriptors: &'a [Descriptor],
    fw_params: &'a FirmwareParameters,
    dma_mapping: &'a D,
) -> Result<(), ErrorCode> {
    let is_initialiazed = PLDM_STATE.lock(|state| {
        let mut state = state.borrow_mut();
        if *state == State::NotRunning {
            *state = State::Initializing;
            false
        } else {
            true
        }
    });
    if !is_initialiazed {
        if descriptors.is_empty() {
            panic!("PLDM descriptors cannot be empty");
        }
        let mut stud_fd_ops = StreamingFdOps::new(descriptors, fw_params, dma_mapping);
        let stud_fd_ops: &'static mut StreamingFdOps<D> =
            unsafe { core::mem::transmute(&mut stud_fd_ops) };

        spawner
            .spawn(pldm_service_task(stud_fd_ops, spawner))
            .unwrap();

        IMAGE_LOADING_TASK_YIELD.wait().await;
        let state = PLDM_STATE.lock(|state| *state.borrow());
        if state != State::Initialized {
            return Err(ErrorCode::Fail);
        }

        return pldm_download_header().await;
    }
    Ok(())
}

pub fn finalize(verify_result: VerifyResult) -> Result<(), ErrorCode> {
    DOWNLOAD_CTX.lock(|ctx| {
        let mut ctx = ctx.borrow_mut();
        ctx.download_complete = true;
        ctx.verify_result = verify_result;
    });
    PLDM_TASK_YIELD.signal(());
    Ok(())
}
