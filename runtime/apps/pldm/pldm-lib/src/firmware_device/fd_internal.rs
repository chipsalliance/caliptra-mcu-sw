// Licensed under the Apache-2.0 license

use crate::control_context::Tid;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::Mutex;
use pldm_common::message::firmware_update::get_status::GetStatusReasonCode;
use pldm_common::protocol::firmware_update::{FirmwareDeviceState, PldmFdTime, UpdateOptionFlags};
use pldm_common::util::fw_component::FirmwareComponent;

#[allow(dead_code)]
pub struct FdInternal {
    inner: Mutex<NoopRawMutex, FdInternalInner>,
}

#[allow(dead_code)]
pub struct FdInternalInner {
    state: FirmwareDeviceState,
    prev_state: FirmwareDeviceState,

    /* Reason for last transition to idle state,
     * only valid when state == PLDM_FD_STATE_IDLE */
    reason: Option<GetStatusReasonCode>,

    /*Details of the component currently being updated.
     * Set by UpdateComponent, available during download/verify/apply.
     * Also used as temporary storage for PassComponentTable */
    update_comp: FirmwareComponent,
    update_flags: UpdateOptionFlags,

    max_transfer: u32,

    /* Used for download/verify/apply requests */
    req: FdReq,
    requester_mode_specific: FdSpecific,

    /* Address of the UA */
    ua_address: Option<Tid>,
    update_timestamp_fd_t1: PldmFdTime,
    fd_t1_timeout: PldmFdTime,
    fd_t2_retry_time: PldmFdTime,
}

impl Default for FdInternal {
    fn default() -> Self {
        Self::new(
            crate::config::FD_MAX_TRANSFER_SIZE as u32,
            crate::config::DEFAULT_FD_T1_TIMEOUT,
            crate::config::DEFAULT_FD_T2_RETRY_TIME,
        )
    }
}

impl FdInternal {
    pub fn new(max_transfer: u32, fd_t1_timeout: u64, fd_t2_retry_time: u64) -> Self {
        Self {
            inner: Mutex::new(FdInternalInner::new(
                max_transfer,
                fd_t1_timeout,
                fd_t2_retry_time,
            )),
        }
    }

    pub async fn is_update_mode(&self) -> bool {
        let inner = self.inner.lock().await;
        inner.state != FirmwareDeviceState::Idle
    }

    pub async fn set_fd_state(&self, state: FirmwareDeviceState) {
        let mut inner = self.inner.lock().await;
        if inner.state != state {
            inner.prev_state = inner.state.clone();
            inner.state = state;
        }
    }

    pub async fn get_fd_state(&self) -> FirmwareDeviceState {
        let inner = self.inner.lock().await;
        inner.state.clone()
    }

    pub async fn set_transfer_size(&self, transfer_size: usize) {
        let mut inner = self.inner.lock().await;
        inner.max_transfer = transfer_size as u32;
    }

    pub async fn get_transfer_size(&self) -> usize {
        let inner = self.inner.lock().await;
        inner.max_transfer as usize
    }

    pub async fn set_component(&self, comp: &FirmwareComponent) {
        let mut inner = self.inner.lock().await;
        inner.update_comp = comp.clone();
    }

    pub async fn set_update_flags(&self, flags: UpdateOptionFlags) {
        let mut inner = self.inner.lock().await;
        inner.update_flags = flags;
    }

    pub async fn set_fd_req(
        &self,
        req_state: FdReqState,
        complete: bool,
        result: Option<u8>,
        instance_id: Option<u8>,
        command: Option<u8>,
        sent_time: Option<PldmFdTime>,
    ) {
        let mut inner = self.inner.lock().await;
        inner.req = FdReq {
            state: req_state,
            complete,
            result,
            instance_id,
            command,
            sent_time,
        };
    }

    pub async fn set_update_timestamp_fd_t1(&self, timestamp: PldmFdTime) {
        let mut inner = self.inner.lock().await;
        inner.update_timestamp_fd_t1 = timestamp;
    }
}

impl Default for FdInternalInner {
    fn default() -> Self {
        Self::new(
            crate::config::FD_MAX_TRANSFER_SIZE as u32,
            crate::config::DEFAULT_FD_T1_TIMEOUT,
            crate::config::DEFAULT_FD_T2_RETRY_TIME,
        )
    }
}

impl FdInternalInner {
    fn new(max_transfer: u32, fd_t1_timeout: u64, fd_t2_retry_time: u64) -> Self {
        Self {
            state: FirmwareDeviceState::Idle,
            prev_state: FirmwareDeviceState::Idle,
            reason: None,
            update_comp: FirmwareComponent::default(),
            update_flags: UpdateOptionFlags(0),
            max_transfer,
            req: FdReq::new(),
            requester_mode_specific: FdSpecific::Download(FdDownload::new()),
            ua_address: None,
            update_timestamp_fd_t1: 0,
            fd_t1_timeout,
            fd_t2_retry_time,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FdReqState {
    // pldm_fd_req instance is unused
    Unused,
    // Ready to send a request
    Ready,
    // Waiting for a response
    Sent,
    // Completed and failed, will not send more requests.
    // Waiting for a cancel from the UA.
    Failed,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct FdReq {
    state: FdReqState,

    /* Set once when ready to move to next state, will return
     * this result for TransferComplete/VerifyComplete/ApplyComplete request. */
    complete: bool,
    /* Only valid when complete is set */
    result: Option<u8>,

    /* Only valid in SENT state */
    instance_id: Option<u8>,
    command: Option<u8>,
    sent_time: Option<PldmFdTime>,
}

impl Default for FdReq {
    fn default() -> Self {
        Self::new()
    }
}

impl FdReq {
    fn new() -> Self {
        Self {
            state: FdReqState::Unused,
            complete: false,
            result: None,
            instance_id: None,
            command: None,
            sent_time: None,
        }
    }
}

#[derive(Debug)]
pub enum FdSpecific {
    Download(FdDownload),
    Verify(FdVerify),
    Apply(FdApply),
}

#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct FdDownload {
    offset: u32,
}

impl FdDownload {
    fn new() -> Self {
        Self { offset: 0 }
    }
}

#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct FdVerify {
    progress_percent: u8,
}

#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct FdApply {
    progress_percent: u8,
}
