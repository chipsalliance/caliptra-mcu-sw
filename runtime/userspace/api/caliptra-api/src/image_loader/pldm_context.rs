// Licensed under the Apache-2.0 license

use core::cell::RefCell;

use caliptra_mcu_flash_image::{MAX_FLASH_HEADER_SIZE, MAX_IMAGE_HEADER_SIZE};
use caliptra_mcu_libsyscall_caliptra::dma::AXIAddr;

use caliptra_mcu_pldm_common::message::firmware_update::verify_complete::VerifyResult;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::blocking_mutex::Mutex;

pub const PLDM_PAYLOAD_CHUNK_SIZE: usize = 256;

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
    DownloadingPayload,
    PayloadDownloadComplete,
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
    pub header: [u8; MAX_FLASH_HEADER_SIZE],
    pub image_info: [u8; MAX_IMAGE_HEADER_SIZE],
    pub payload: [u8; PLDM_PAYLOAD_CHUNK_SIZE],
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
        header: [0; MAX_FLASH_HEADER_SIZE],
        image_info: [0; MAX_IMAGE_HEADER_SIZE],
        payload: [0; PLDM_PAYLOAD_CHUNK_SIZE],
        load_address: 0,
        last_requested_length: 0,
    }));

pub static PLDM_STATE: Mutex<CriticalSectionRawMutex, RefCell<State>> =
    Mutex::new(RefCell::new(State::NotRunning));
