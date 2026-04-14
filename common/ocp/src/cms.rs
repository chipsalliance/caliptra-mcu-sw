// Licensed under the Apache-2.0 license

//! Component Memory Space (CMS) abstractions for the OCP Recovery Interface.
//!
//! The OCP spec defines two access models for CMS regions:
//! - **Memory window** (INDIRECT_CTRL / INDIRECT_STATUS / INDIRECT_DATA): random-access,
//!   offset-based I/O with optional polling.
//! - **FIFO** (INDIRECT_FIFO_CTRL / INDIRECT_FIFO_STATUS / INDIRECT_FIFO_DATA): streaming
//!   producer/consumer I/O with internal index tracking.
//!
//! This module defines one trait for each model. Integrators provide concrete implementations
//! (e.g. backed by RAM slices, flash, registers) and pass them to the `RecoveryStateMachine`.
//!
//! Slice-backed reference implementations are provided in submodules.

pub mod slice_fifo;
pub mod slice_indirect;

use crate::error::CmsError;
use crate::protocol::indirect_fifo_status::IndirectFifoStatus;
use crate::protocol::indirect_status::IndirectStatus;

/// Integrator-provided backing store for a memory-window CMS region.
///
/// Accessed via `INDIRECT_CTRL` / `INDIRECT_STATUS` / `INDIRECT_DATA` commands. The region
/// owns its indirect memory offset (IMO) and manages auto-increment, wrap, and overflow
/// tracking internally. Status metadata (region type, size, flags, polling) is returned
/// as a complete [`IndirectStatus`] struct.
pub trait IndirectCmsRegion {
    /// Returns the current `INDIRECT_STATUS` for this region.
    ///
    /// The returned [`IndirectStatus`] contains the status flags (overflow, read-only error,
    /// polling error, write-only error), region type, polling bit, and region size. The state
    /// machine serializes this directly for `INDIRECT_STATUS` reads.
    fn status(&self) -> IndirectStatus;

    /// Returns the current indirect memory offset (IMO) in bytes. Always 4-byte aligned.
    ///
    /// Used when `INDIRECT_CTRL` is read back.
    fn imo(&self) -> u32;

    /// Sets the indirect memory offset (IMO) in bytes.
    ///
    /// Called by the state machine when `INDIRECT_CTRL` is written (bytes 2-5).
    /// Implementations should truncate unaligned values to the previous 4-byte boundary.
    fn set_imo(&mut self, offset: u32);

    /// Write `data` at the current IMO.
    ///
    /// The implementation auto-increments the IMO by the transfer size rounded up to the
    /// next 4-byte boundary. If the IMO would exceed the region size, it wraps to 0 and
    /// the implementation records an overflow condition.
    ///
    /// Returns [`CmsError::ReadOnly`] if the region type does not permit writes.
    /// Returns [`CmsError::PollingNotReady`] if polling is required and the region is not ready.
    fn write(&mut self, data: &[u8]) -> Result<(), CmsError>;

    /// Read up to `buf.len()` bytes starting at the current IMO.
    ///
    /// The implementation auto-increments the IMO by the transfer size rounded up to the
    /// next 4-byte boundary. If the IMO would exceed the region size, it wraps to 0 and
    /// the implementation records an overflow condition.
    ///
    /// Returns the number of bytes actually read.
    /// Returns [`CmsError::WriteOnly`] if the region type does not permit reads.
    /// Returns [`CmsError::PollingNotReady`] if polling is required and the region is not ready.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, CmsError>;

    /// Read up to `buf.len()` bytes starting at `offset` for device-internal
    /// consumption, bypassing host access control.
    ///
    /// Unlike [`read`](IndirectCmsRegion::read), this method:
    /// - Takes an explicit byte offset instead of using the current IMO.
    /// - Does **not** modify the IMO or set overflow/status flags.
    /// - Does **not** check host-facing access permissions.
    ///
    /// The OCP spec defines region types like `CodeSpace` as write-only *from
    /// the host's perspective* — the host pushes firmware images but must not
    /// read them back. However, the device firmware itself must be able to read
    /// the region to consume the data the host wrote. `device_read` serves this
    /// purpose.
    ///
    /// Returns the number of bytes actually copied into `buf`.
    fn device_read(&self, offset: u32, buf: &mut [u8]) -> usize;

    /// Clear accumulated status flags (overflow, polling error, access errors).
    ///
    /// Called when `INDIRECT_STATUS` is read (clear-on-read semantics).
    fn clear_status(&mut self);

    /// Reset the region state.
    ///
    /// Called when this CMS is selected via `INDIRECT_CTRL` (i.e. on CMS change). The
    /// implementation should reset the IMO to 0 and clear all accumulated status.
    fn reset(&mut self);
}

/// Integrator-provided backing store for a FIFO CMS region.
///
/// Accessed via `INDIRECT_FIFO_CTRL` / `INDIRECT_FIFO_STATUS` / `INDIRECT_FIFO_DATA` commands.
/// The FIFO manages its own write and read indices internally. Status metadata (region type,
/// empty/full flags, indices, sizes) is returned as a complete [`IndirectFifoStatus`] struct.
pub trait FifoCmsRegion {
    /// Returns the current `INDIRECT_FIFO_STATUS` for this region.
    ///
    /// The returned [`IndirectFifoStatus`] contains the status flags (empty, full), region
    /// type, write index, read index, FIFO size, and max transfer size. The state machine
    /// serializes this directly for `INDIRECT_FIFO_STATUS` reads.
    fn status(&self) -> IndirectFifoStatus;

    /// Push data into the FIFO (write direction).
    ///
    /// Returns [`CmsError::FifoFull`] if the write would cause the write index to advance
    /// to equal the read index. Returns [`CmsError::ReadOnly`] if the region is read-only.
    fn push(&mut self, data: &[u8]) -> Result<(), CmsError>;

    /// Pop data from the FIFO (read direction).
    ///
    /// Reads up to `buf.len()` bytes and returns the number actually read.
    /// Returns [`CmsError::FifoEmpty`] if the read index equals the write index.
    /// Returns [`CmsError::WriteOnly`] if the region is write-only.
    fn pop(&mut self, buf: &mut [u8]) -> Result<usize, CmsError>;

    /// Pop data from the FIFO for device-internal consumption, bypassing host
    /// access control.
    ///
    /// The OCP spec defines region types like `CodeSpace` as write-only *from
    /// the host's perspective* — the host pushes firmware images but must not
    /// read them back. [`pop`](FifoCmsRegion::pop) enforces this by returning
    /// [`CmsError::WriteOnly`] for such regions.
    ///
    /// However, the device firmware itself must be able to drain the FIFO to
    /// consume the data the host wrote. `device_drain` serves this purpose: it
    /// reads data from the FIFO unconditionally, without checking the region's
    /// host-facing access permissions.
    ///
    /// Returns the number of bytes read into `buf`, or [`CmsError::FifoEmpty`]
    /// if the FIFO contains no data.
    fn device_drain(&mut self, buf: &mut [u8]) -> Result<usize, CmsError>;

    /// Request a FIFO reset (INDIRECT_FIFO_CTRL byte 1 = 0x01, "Write 1, Device Clears").
    ///
    /// The implementation performs the reset and manages the reset-pending state
    /// internally. The implementation is responsible for managing the lifecycle
    /// of the reset, and ensuring `is_reset_pending` returns true between the
    /// reset request and completion.
    fn request_reset(&mut self);

    /// Returns `true` if a previously requested reset has not yet completed.
    ///
    /// The state machine reads this when serializing INDIRECT_FIFO_CTRL to
    /// populate the reset byte. Once the device finishes the reset it clears
    /// this flag, implementing the "Write 1, Device Clears" spec behavior.
    fn is_reset_pending(&self) -> bool;
}
