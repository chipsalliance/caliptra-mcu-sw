// Licensed under the Apache-2.0 license

use crate::control_context::Tid;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::Mutex;
use pldm_common::message::firmware_update::get_status::GetStatusReasonCode;
use pldm_common::protocol::firmware_update::{
    FirmwareDeviceState, PldmFdTime, UpdateOptionFlags, PLDM_FWUP_MAX_PADDING_SIZE,
};
use pldm_common::util::fw_component::FirmwareComponent;

pub struct FdInternal {
    inner: Mutex<NoopRawMutex, FdInternalInner>,
}

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
    initiator_mode_state: InitiatorModeState,

    // Address of the Update Agent (UA).
    _ua_address: Option<Tid>,

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

    pub async fn set_fd_idle(&self, reason_code: GetStatusReasonCode) {
        let mut inner = self.inner.lock().await;
        if inner.state != FirmwareDeviceState::Idle {
            inner.prev_state = inner.state.clone();
            inner.state = FirmwareDeviceState::Idle;
            inner.reason = Some(reason_code);
        }
    }

    pub async fn fd_idle_timeout(&self) {
        let state = self.get_fd_state().await;
        let reason = match state {
            FirmwareDeviceState::Idle => return,
            FirmwareDeviceState::LearnComponents => GetStatusReasonCode::LearnComponentTimeout,
            FirmwareDeviceState::ReadyXfer => GetStatusReasonCode::ReadyXferTimeout,
            FirmwareDeviceState::Download => GetStatusReasonCode::DownloadTimeout,
            FirmwareDeviceState::Verify => GetStatusReasonCode::VerifyTimeout,
            FirmwareDeviceState::Apply => GetStatusReasonCode::ApplyTimeout,
            FirmwareDeviceState::Activate => GetStatusReasonCode::ActivateFw,
        };

        self.set_fd_idle(reason).await;
    }

    pub async fn get_fd_reason(&self) -> Option<GetStatusReasonCode> {
        let inner = self.inner.lock().await;
        inner.reason
    }

    pub async fn get_fd_state(&self) -> FirmwareDeviceState {
        let inner = self.inner.lock().await;
        inner.state.clone()
    }

    pub async fn get_fd_prev_state(&self) -> FirmwareDeviceState {
        let inner = self.inner.lock().await;
        inner.prev_state.clone()
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

    pub async fn get_component(&self) -> FirmwareComponent {
        let inner = self.inner.lock().await;
        inner.update_comp.clone()
    }

    pub async fn set_update_flags(&self, flags: UpdateOptionFlags) {
        let mut inner = self.inner.lock().await;
        inner.update_flags = flags;
    }

    pub async fn get_update_flags(&self) -> UpdateOptionFlags {
        let inner = self.inner.lock().await;
        inner.update_flags
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

    pub async fn alloc_next_instance_id(&self) -> Option<u8> {
        let mut inner = self.inner.lock().await;
        inner.req.instance_id = Some(
            inner
                .req
                .instance_id
                .map_or(1, |id| (id + 1) % crate::config::INSTANCE_ID_COUNT),
        );
        inner.req.instance_id
    }

    pub async fn get_fd_req(&self) -> FdReq {
        let inner = self.inner.lock().await;
        inner.req.clone()
    }

    pub async fn get_fd_req_state(&self) -> FdReqState {
        let inner = self.inner.lock().await;
        inner.req.state.clone()
    }

    pub async fn set_fd_req_state(&self, state: FdReqState) {
        let mut inner = self.inner.lock().await;
        inner.req.state = state;
    }

    pub async fn get_fd_sent_time(&self) -> Option<PldmFdTime> {
        let inner = self.inner.lock().await;
        inner.req.sent_time
    }

    pub async fn is_fd_req_complete(&self) -> bool {
        let inner = self.inner.lock().await;
        inner.req.complete
    }

    pub async fn get_fd_req_result(&self) -> Option<u8> {
        let inner = self.inner.lock().await;
        inner.req.result
    }

    pub async fn get_fd_download_chunk(
        &self,
        requested_offset: u32,
        requested_length: u32,
    ) -> Option<(u32, u32)> {
        let inner = self.inner.lock().await;
        if inner.state != FirmwareDeviceState::Download {
            return None;
        }

        let comp_image_size = inner.update_comp.comp_image_size.unwrap_or(0);
        if requested_offset > comp_image_size
            || requested_offset
                .checked_add(requested_length)
                .is_none_or(|requested_end| {
                    comp_image_size
                        .checked_add(PLDM_FWUP_MAX_PADDING_SIZE as u32)
                        .is_some_and(|allowed_end| requested_end > allowed_end)
                })
        {
            return None;
        }
        let chunk_size = requested_length.min(inner.max_xfer_size);
        Some((requested_offset, chunk_size))
    }

    pub async fn get_fd_download_state(&self) -> Option<(u32, u32)> {
        let inner = self.inner.lock().await;
        if let InitiatorModeState::Download(download) = &inner.initiator_mode_state {
            Some((download.offset, download.length))
        } else {
            None
        }
    }

    pub async fn set_fd_download_state(&self, offset: u32, length: u32) {
        let mut inner = self.inner.lock().await;
        if let InitiatorModeState::Download(download) = &mut inner.initiator_mode_state {
            download.offset = offset;
            download.length = length;
        }
    }

    pub async fn set_initiator_mode(&self, mode: InitiatorModeState) {
        let mut inner = self.inner.lock().await;
        inner.initiator_mode_state = mode;
    }

    pub async fn set_fd_verify_progress(&self, progress: u8) {
        let mut inner = self.inner.lock().await;
        if let InitiatorModeState::Verify(verify) = &mut inner.initiator_mode_state {
            verify.progress_percent = progress;
        }
    }

    pub async fn set_fd_apply_progress(&self, progress: u8) {
        let mut inner = self.inner.lock().await;
        if let InitiatorModeState::Apply(apply) = &mut inner.initiator_mode_state {
            apply.progress_percent = progress;
        }
    }

    pub async fn get_fd_verify_progress(&self) -> Option<u8> {
        let inner = self.inner.lock().await;
        if let InitiatorModeState::Verify(verify) = &inner.initiator_mode_state {
            Some(verify.progress_percent)
        } else {
            None
        }
    }

    pub async fn get_fd_apply_progress(&self) -> Option<u8> {
        let inner = self.inner.lock().await;
        if let InitiatorModeState::Apply(apply) = &inner.initiator_mode_state {
            Some(apply.progress_percent)
        } else {
            None
        }
    }

    pub async fn set_fd_t1_update_ts(&self, timestamp: PldmFdTime) {
        let mut inner = self.inner.lock().await;
        inner.fd_t1_update_ts = timestamp;
    }

    pub async fn get_fd_t1_update_ts(&self) -> PldmFdTime {
        let inner = self.inner.lock().await;
        inner.fd_t1_update_ts
    }

    pub async fn set_fd_t1_timeout(&self, timeout: PldmFdTime) {
        let mut inner = self.inner.lock().await;
        inner.fd_t1_timeout = timeout;
    }

    pub async fn get_fd_t1_timeout(&self) -> PldmFdTime {
        let inner = self.inner.lock().await;
        inner.fd_t1_timeout
    }

    pub async fn set_fd_t2_retry_time(&self, retry_time: PldmFdTime) {
        let mut inner = self.inner.lock().await;
        inner.fd_t2_retry_time = retry_time;
    }

    pub async fn get_fd_t2_retry_time(&self) -> PldmFdTime {
        let inner = self.inner.lock().await;
        inner.fd_t2_retry_time
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
            initiator_mode_state: InitiatorModeState::Download(DownloadState::default()),
            _ua_address: None,
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

#[derive(Debug, Clone)]
pub struct FdReq {
    // The current state of the request.
    pub state: FdReqState,

    // Indicates if the request is complete and ready to transition to the next state.
    // This is relevant for TransferComplete, VerifyComplete, and ApplyComplete requests.
    pub complete: bool,

    // The result of the request, only valid when `complete` is set.
    pub result: Option<u8>,

    // The instance ID of the request, only valid in the `SENT` state.
    pub instance_id: Option<u8>,

    // The command associated with the request, only valid in the `SENT` state.
    pub command: Option<u8>,

    // The time when the request was sent, only valid in the `SENT` state.
    pub sent_time: Option<PldmFdTime>,
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
pub enum InitiatorModeState {
    Download(DownloadState),
    Verify(VerifyState),
    Apply(ApplyState),
}

#[derive(Debug, Default)]
pub struct DownloadState {
    pub offset: u32,
    pub length: u32,
}

#[derive(Debug, Default)]
pub struct VerifyState {
    pub progress_percent: u8,
}

#[derive(Debug, Default)]
pub struct ApplyState {
    pub progress_percent: u8,
}
