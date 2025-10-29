// Licensed under the Apache-2.0 license

extern crate alloc;
use super::pldm_context::State;
use super::pldm_context::{DOWNLOAD_CTX, PLDM_STATE};
use super::pldm_fdops::UpdateFdOps;
use super::StagingMemory;

use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use libtock_platform::ErrorCode;
use pldm_common::message::firmware_update::apply_complete::ApplyResult;
use pldm_common::message::firmware_update::get_fw_params::FirmwareParameters;
use pldm_common::message::firmware_update::verify_complete::VerifyResult;
use pldm_common::protocol::firmware_update::Descriptor;
use pldm_lib::daemon::PldmService;
use pldm_lib::firmware_device::fd_ops::FdOps;

pub static FW_UPDATE_TASK_YIELD: Signal<CriticalSectionRawMutex, ()> = Signal::new();
pub static PLDM_DAEMON_TASK_YIELD: Signal<CriticalSectionRawMutex, ()> = Signal::new();

#[embassy_executor::task]
async fn pldm_service_task(pldm_ops: &'static dyn FdOps, spawner: Spawner) {
    let mut pldm_service_init: PldmService = PldmService::init(pldm_ops, spawner);
    pldm_service_init.start().await.unwrap();
}

pub async fn initialize_pldm(
    spawner: Spawner,
    descriptors: &'static [Descriptor],
    fw_params: &'static FirmwareParameters,
    staging_memory: &'static dyn StagingMemory,
) -> Result<(), ErrorCode> {
    let is_initialiazed = PLDM_STATE.lock(|state| {
        let mut state = state.borrow_mut();
        if *state == State::NotRunning {
            *state = State::Initialized;
            false
        } else {
            true
        }
    });
    if !is_initialiazed {
        if descriptors.is_empty() {
            panic!("PLDM descriptors cannot be empty");
        }
        let mut update_fd_ops: UpdateFdOps = UpdateFdOps::new();
        let static_update_fd_ops: &'static mut UpdateFdOps =
            unsafe { core::mem::transmute(&mut update_fd_ops) };

        PLDM_STATE.lock(|state| {
            let mut state = state.borrow_mut();
            *state = State::DownloadingImage;
        });

        DOWNLOAD_CTX.lock(|ctx| {
            let mut ctx = ctx.borrow_mut();
            ctx.total_length = 0;
            ctx.initial_offset = 0;
            ctx.current_offset = 0;
            ctx.total_downloaded = 0;
            ctx.descriptors = Some(descriptors);
            ctx.fw_params = Some(fw_params);
            ctx.staging_memory = Some(staging_memory);
        });

        spawner
            .spawn(pldm_service_task(static_update_fd_ops, spawner))
            .unwrap();
    }
    Ok(())
}

pub async fn pldm_wait(wait_state: State) -> Result<(), ErrorCode> {
    FW_UPDATE_TASK_YIELD.wait().await;
    let state = PLDM_STATE.lock(|state| *state.borrow());
    if state != wait_state {
        return Err(ErrorCode::Fail);
    }
    Ok(())
}

pub fn pldm_total_component_size() -> usize {
    DOWNLOAD_CTX.lock(|ctx| {
        let ctx = ctx.borrow();
        ctx.total_length
    })
}

pub fn pldm_set_verification_result(verify_result: VerifyResult) {
    DOWNLOAD_CTX.lock(|ctx| {
        let mut ctx = ctx.borrow_mut();
        ctx.verify_result = verify_result;
    });
    // Yield to the PLDM daemon task to complete verification
    PLDM_DAEMON_TASK_YIELD.signal(());
}

pub fn pldm_set_apply_result(apply_result: ApplyResult) {
    DOWNLOAD_CTX.lock(|ctx| {
        let mut ctx = ctx.borrow_mut();
        ctx.apply_result = apply_result;
    });
    // Yield to the PLDM daemon task to complete application
    PLDM_DAEMON_TASK_YIELD.signal(());
}
