// Licensed under the Apache-2.0 license

use core::cell::RefCell;

use flash_image::{FlashHeader, ImageHeader};
use libsyscall_caliptra::dma::AXIAddr;

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::blocking_mutex::Mutex;
use pldm_common::message::firmware_update::verify_complete::VerifyResult;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum State {
    NotRunning,
    Initializing,
    Initialized,
    DownloadingHeader,
    HeaderDownloadComplete,
    DownloadingToc,
    TocDownloadComplete,
    ImageDownloadReady,
    DownloadingImage,
    ImageDownloadComplete,
}

#[derive(Debug, Clone, Copy)]
pub struct DownloadCtx {
    pub total_length: usize,
    pub initial_offset: usize,
    pub current_offset: usize,
    pub total_downloaded: usize,
    pub last_requested_length: usize,
    pub download_complete: bool,
    pub verify_result: VerifyResult,
    pub header: [u8; core::mem::size_of::<FlashHeader>()],
    pub image_info: [u8; core::mem::size_of::<ImageHeader>()],
    pub load_address: AXIAddr,
}

pub static DOWNLOAD_CTX: Mutex<CriticalSectionRawMutex, RefCell<DownloadCtx>> =
    Mutex::new(RefCell::new(DownloadCtx {
        total_length: 0,
        current_offset: 0,
        initial_offset: 0,
        total_downloaded: 0,
        download_complete: false,
        verify_result: VerifyResult::VerifySuccess,
        header: [0; core::mem::size_of::<FlashHeader>()],
        image_info: [0; core::mem::size_of::<ImageHeader>()],
        load_address: 0,
        last_requested_length: 0,
    }));

pub static PLDM_STATE: Mutex<CriticalSectionRawMutex, RefCell<State>> =
    Mutex::new(RefCell::new(State::NotRunning));
