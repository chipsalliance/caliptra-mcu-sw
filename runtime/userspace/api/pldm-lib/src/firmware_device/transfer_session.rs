// Licensed under the Apache-2.0 license

//! Transfer session for optimized firmware download.
//!
//! This module provides a local transfer context that can be used during
//! firmware download operations to avoid repeated mutex acquisitions.
//! The session captures state at the start of a transfer and only requires
//! mutex access at boundaries (start, end, cancellation check).

use core::sync::atomic::{AtomicBool, Ordering};
use pldm_common::message::firmware_update::transfer_complete::TransferResult;
use pldm_common::protocol::firmware_update::{PldmFdTime, PLDM_FWUP_MAX_PADDING_SIZE};
use pldm_common::util::fw_component::FirmwareComponent;

use super::fd_internal::FdReqState;

/// Local state for an active download transfer.
///
/// This struct holds all the state needed during a firmware download,
/// allowing the hot path to avoid mutex acquisitions on every chunk.
pub struct TransferSession {
    /// Current download offset
    pub offset: u32,
    /// Current chunk length being requested
    pub length: u32,
    /// Maximum transfer size allowed
    pub max_xfer_size: u32,
    /// Component image size
    pub comp_image_size: u32,
    /// Current instance ID for requests
    pub instance_id: u8,
    /// Whether the transfer is complete
    pub complete: bool,
    /// Transfer result (set when complete)
    pub result: Option<TransferResult>,
    /// Request state
    pub req_state: FdReqState,
    /// Timestamp when request was sent
    pub sent_time: Option<PldmFdTime>,
    /// FD T1 timeout value
    pub fd_t1_timeout: PldmFdTime,
    /// FD T2 retry time
    pub fd_t2_retry_time: PldmFdTime,
    /// Last T1 update timestamp
    pub fd_t1_update_ts: PldmFdTime,
    /// Cached component info
    pub component: FirmwareComponent,
}

impl TransferSession {
    /// Create a new transfer session from the given parameters.
    pub fn new(
        max_xfer_size: u32,
        component: FirmwareComponent,
        fd_t1_timeout: PldmFdTime,
        fd_t2_retry_time: PldmFdTime,
        initial_instance_id: u8,
        now: PldmFdTime,
    ) -> Self {
        Self {
            offset: 0,
            length: 0,
            max_xfer_size,
            comp_image_size: component.comp_image_size.unwrap_or(0),
            instance_id: initial_instance_id,
            complete: false,
            result: None,
            req_state: FdReqState::Ready,
            sent_time: None,
            fd_t1_timeout,
            fd_t2_retry_time,
            fd_t1_update_ts: now,
            component,
        }
    }

    /// Allocate the next instance ID.
    pub fn alloc_next_instance_id(&mut self) -> u8 {
        self.instance_id = (self.instance_id + 1) % crate::config::INSTANCE_ID_COUNT;
        self.instance_id
    }

    /// Check if we should send a request based on current state and timing.
    pub fn should_send_request(&self, now: PldmFdTime) -> bool {
        match self.req_state {
            FdReqState::Unused => false,
            FdReqState::Ready => true,
            FdReqState::Failed => false,
            FdReqState::Sent => {
                if let Some(sent_time) = self.sent_time {
                    if now < sent_time {
                        return false;
                    }
                    (now - sent_time) >= self.fd_t2_retry_time
                } else {
                    false
                }
            }
        }
    }

    /// Calculate the chunk parameters for a download request.
    ///
    /// Returns `Some((offset, length))` if valid, `None` if the request is invalid.
    pub fn get_download_chunk(
        &self,
        requested_offset: u32,
        requested_length: u32,
    ) -> Option<(u32, u32)> {
        if requested_offset > self.comp_image_size
            || requested_offset
                .checked_add(requested_length)
                .is_none_or(|requested_end| {
                    self.comp_image_size
                        .checked_add(PLDM_FWUP_MAX_PADDING_SIZE as u32)
                        .is_some_and(|allowed_end| requested_end > allowed_end)
                })
        {
            return None;
        }
        let chunk_size = requested_length.min(self.max_xfer_size);
        Some((requested_offset, chunk_size))
    }

    /// Mark the request as sent.
    pub fn mark_sent(&mut self, now: PldmFdTime, command: u8) {
        self.req_state = FdReqState::Sent;
        self.sent_time = Some(now);
        self.fd_t1_update_ts = now;
        let _ = command; // Command tracking could be added if needed
    }

    /// Mark the transfer as ready for next chunk.
    pub fn mark_ready_for_next(&mut self) {
        self.req_state = FdReqState::Ready;
        self.complete = false;
        self.result = None;
        self.sent_time = None;
    }

    /// Mark the transfer as complete with the given result.
    pub fn mark_complete(&mut self, result: TransferResult) {
        self.req_state = FdReqState::Ready;
        self.complete = true;
        self.result = Some(result);
    }

    /// Mark the transfer as failed.
    pub fn mark_failed(&mut self, result: TransferResult) {
        self.req_state = FdReqState::Failed;
        self.complete = true;
        self.result = Some(result);
    }

    /// Check if T1 timeout has occurred.
    pub fn is_t1_timeout(&self, now: PldmFdTime) -> bool {
        if self.req_state != FdReqState::Sent {
            return false;
        }
        let elapsed = now.saturating_sub(self.fd_t1_update_ts);
        elapsed > self.fd_t1_timeout
    }

    /// Update T1 timestamp.
    pub fn update_t1_timestamp(&mut self, now: PldmFdTime) {
        self.fd_t1_update_ts = now;
    }
}

/// Atomic flag for signaling transfer cancellation from the responder task.
///
/// This allows the responder to signal cancellation without requiring
/// mutex access in the hot download path.
pub struct CancellationFlag {
    cancelled: AtomicBool,
}

impl CancellationFlag {
    pub const fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
        }
    }

    /// Signal that the transfer should be cancelled.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Check if cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// Reset the cancellation flag.
    pub fn reset(&self) {
        self.cancelled.store(false, Ordering::Release);
    }
}

impl Default for CancellationFlag {
    fn default() -> Self {
        Self::new()
    }
}
