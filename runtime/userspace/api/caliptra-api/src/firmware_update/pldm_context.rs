// Licensed under the Apache-2.0 license

use core::cell::RefCell;

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::blocking_mutex::Mutex;
use pldm_common::message::firmware_update::get_fw_params::FirmwareParameters;
use pldm_common::message::firmware_update::verify_complete::VerifyResult;
use pldm_common::protocol::firmware_update::Descriptor;

use super::StagingMemory;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum State {
    NotRunning,
    Initialized,
    DownloadingImage,
    ImageDownloadComplete,
}

#[derive(Debug, Clone, Copy)]
pub struct DownloadCtx<'a> {
    pub total_length: usize,
    pub initial_offset: usize,
    pub current_offset: usize,
    pub total_downloaded: usize,
    pub last_requested_length: usize,
    pub verify_result: VerifyResult,
    pub descriptors: Option<&'a [Descriptor]>,
    pub fw_params: Option<&'a FirmwareParameters>,
    pub staging_memory: Option<&'a dyn StagingMemory>,
}

pub static DOWNLOAD_CTX: Mutex<CriticalSectionRawMutex, RefCell<DownloadCtx>> =
    Mutex::new(RefCell::new(DownloadCtx {
        total_length: 0,
        current_offset: 0,
        initial_offset: 0,
        total_downloaded: 0,
        verify_result: VerifyResult::VerifySuccess,
        last_requested_length: 0,
        descriptors: None,
        fw_params: None,
        staging_memory: None,
    }));

pub static PLDM_STATE: Mutex<CriticalSectionRawMutex, RefCell<State>> =
    Mutex::new(RefCell::new(State::NotRunning));
