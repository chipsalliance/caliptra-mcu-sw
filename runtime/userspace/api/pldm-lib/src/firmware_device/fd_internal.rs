// Licensed under the Apache-2.0 license

use crate::control_context::Tid;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::Mutex;
use pldm_common::message::firmware_update::get_status::GetStatusReasonCode;
use pldm_common::protocol::firmware_update::{FirmwareDeviceState, PldmFdTime, UpdateOptionFlags};
use pldm_common::util::fw_component::FirmwareComponent;

pub struct FdInternal {
    inner: Mutex<NoopRawMutex, FdInternalInner>,
}

#[allow(dead_code)]
pub struct FdInternalInner {
    // Current state of the firmware device.
    state: FirmwareDeviceState,

    // Previous state of the firmware device.
    prev_state: FirmwareDeviceState,

    // Reason for the last transition to the idle state.
    // Only valid when `state == FirmwareDeviceState::Idle`.
    reason: Option<GetStatusReasonCode>,

    // Details of the component currently being updated.
    // Set by `UpdateComponent`, available during download/verify/apply.
    update_comp: FirmwareComponent,

    // Flags indicating update options.
    update_flags: UpdateOptionFlags,

    // Maximum transfer size allowed by the UA or platform implementation.
    max_xfer_size: u32,

    // Request details used for download/verify/apply operations.
    req: FdReq,

    // Mode-specific data for the requester.
    requester_mode_specific: FdSpecific,

    // Address of the Update Agent (UA).
    ua_address: Option<Tid>,

    // Timestamp for FD T1 timeout in milliseconds.
    fd_t1_update_ts: PldmFdTime,

    fd_t1_timeout: PldmFdTime,
    fd_t2_retry_time: PldmFdTime,
}

impl Default for FdInternal {
    fn default() -> Self {
        Self::new(
            crate::config::FD_MAX_XFER_SIZE as u32,
            crate::config::DEFAULT_FD_T1_TIMEOUT,
            crate::config::DEFAULT_FD_T2_RETRY_TIME,
        )
    }
}

impl FdInternal {
    pub fn new(
        max_xfer_size: u32,
        fd_t1_timeout: PldmFdTime,
        fd_t2_retry_time: PldmFdTime,
    ) -> Self {
        Self {
            inner: Mutex::new(FdInternalInner::new(
                max_xfer_size,
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

    pub async fn set_xfer_size(&self, transfer_size: usize) {
        let mut inner = self.inner.lock().await;
        inner.max_xfer_size = transfer_size as u32;
    }

    pub async fn get_xfer_size(&self) -> usize {
        let inner = self.inner.lock().await;
        inner.max_xfer_size as usize
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

    pub async fn set_fd_t1_update_ts(&self, timestamp: PldmFdTime) {
        let mut inner = self.inner.lock().await;
        inner.fd_t1_update_ts = timestamp;
    }
}

impl Default for FdInternalInner {
    fn default() -> Self {
        Self::new(
            crate::config::FD_MAX_XFER_SIZE as u32,
            crate::config::DEFAULT_FD_T1_TIMEOUT,
            crate::config::DEFAULT_FD_T2_RETRY_TIME,
        )
    }
}

impl FdInternalInner {
    fn new(max_xfer_size: u32, fd_t1_timeout: u64, fd_t2_retry_time: u64) -> Self {
        Self {
            state: FirmwareDeviceState::Idle,
            prev_state: FirmwareDeviceState::Idle,
            reason: None,
            update_comp: FirmwareComponent::default(),
            update_flags: UpdateOptionFlags(0),
            max_xfer_size,
            req: FdReq::new(),
            requester_mode_specific: FdSpecific::Download(FdDownload::new()),
            ua_address: None,
            fd_t1_update_ts: 0,
            fd_t1_timeout,
            fd_t2_retry_time,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FdReqState {
    // The `pldm_fd_req` instance is unused.
    Unused,
    // Ready to send a request.
    Ready,
    // Waiting for a response.
    Sent,
    // Completed and failed; will not send more requests.
    Failed,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct FdReq {
    // The current state of the request.
    state: FdReqState,

    // Indicates if the request is complete and ready to transition to the next state.
    // This is relevant for TransferComplete, VerifyComplete, and ApplyComplete requests.
    complete: bool,

    // The result of the request, only valid when `complete` is set.
    result: Option<u8>,

    // The instance ID of the request, only valid in the `SENT` state.
    instance_id: Option<u8>,

    // The command associated with the request, only valid in the `SENT` state.
    command: Option<u8>,

    // The time when the request was sent, only valid in the `SENT` state.
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
