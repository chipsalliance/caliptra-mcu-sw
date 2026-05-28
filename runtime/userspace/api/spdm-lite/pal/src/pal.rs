// Licensed under the Apache-2.0 license

//! Concrete MCU implementation of the SPDM-Lite Platform Abstraction Layer.
//!
//! This module defines [`McuSpdmPal`], the MCU-side type that satisfies
//! the [`SpdmPal`](mcu_spdm_lite_traits::SpdmPal) super-trait by
//! wrapping a boxed
//! [`SpdmPalTransport`](mcu_spdm_lite_traits::SpdmPalTransport)
//! implementation (e.g.,
//! [`McuMctpTransport`](../../../transports/src/mctp.rs)) and re-exposing
//! it as a framed
//! [`SpdmIoTransport`](mcu_spdm_lite_traits::SpdmIoTransport) via the
//! companion [`io`](super::io) module.
//!
//! The MCU SPDM-Lite stack consumes `McuSpdmPal` as its single entry
//! point for platform-specific I/O.

use super::*;

extern crate alloc;

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::ptr::NonNull;

use super::cert::store::SharedCertStore;

/// MCU implementation of the SPDM-Lite Platform Abstraction Layer.
///
/// Owns the underlying byte-oriented PAL transport (held behind an
/// [`UnsafeCell`] for interior mutability — the SPDM responder is
/// strictly single-task, so we never observe concurrent access) plus a
/// single [`BitmapAllocator`](super::alloc::BitmapAllocator) backed by
/// a caller-supplied scratch region. The allocator is reset at the
/// start of every `recv_request`, so allocations are scoped to a
/// single SPDM exchange even though the allocator object itself lives
/// on the PAL.
pub struct McuSpdmPal {
    /// The wrapped byte-oriented PAL transport.
    pub(crate) transport: UnsafeCell<Box<dyn SpdmPalTransport>>,

    /// Per-IO scratch allocator, reset by every `recv_request`.
    pub(crate) allocator: BitmapAllocator,

    /// Shared cert store — same instance for all transports.
    pub(crate) cert_store: &'static SharedCertStore,
}

impl McuSpdmPal {
    /// Creates a new `McuSpdmPal` wrapping the given PAL transport and
    /// per-IO scratch buffer.
    ///
    /// # Parameters
    ///
    /// * `transport` — Boxed byte-oriented transport implementation
    ///   (e.g. `McuMctpTransport`). Owned for the lifetime of the
    ///   returned `McuSpdmPal`.
    /// * `io_buf_ptr` — Base of the caller-supplied scratch region
    ///   used to back the per-IO [`BitmapAllocator`].
    /// * `io_buf_capacity` — Total length, in bytes, of the region
    ///   at `io_buf_ptr`.
    ///
    /// # Returns
    ///
    /// A `McuSpdmPal` that satisfies the
    /// [`SpdmPal`](mcu_spdm_lite_traits::SpdmPal) super-trait,
    /// suitable for handing to [`SpdmStack`](crate::SpdmStack).
    ///
    /// # Safety
    ///
    /// * `io_buf_ptr` must be aligned to
    ///   [`BITMAP_SLOT_SIZE`](super::alloc::BITMAP_SLOT_SIZE) and point
    ///   to `io_buf_capacity` bytes of writable memory exclusively
    ///   owned by this `McuSpdmPal` for its entire lifetime.
    /// * The constructed `McuSpdmPal` must only be driven from a single
    ///   task; calling `recv_request` / `send_response` concurrently is
    ///   undefined behavior (interior mutability is not synchronized).
    pub unsafe fn new(
        transport: Box<dyn SpdmPalTransport>,
        io_buf_ptr: NonNull<u8>,
        io_buf_capacity: usize,
        cert_store: &'static SharedCertStore,
    ) -> Self {
        Self {
            transport: UnsafeCell::new(transport),
            allocator: BitmapAllocator::new(io_buf_ptr, io_buf_capacity),
            cert_store,
        }
    }

    /// Returns an exclusive reference to the wrapped transport.
    ///
    /// # Returns
    ///
    /// `&mut Box<dyn SpdmPalTransport>` aliased through the
    /// [`UnsafeCell`]; valid for the lifetime of the borrow on
    /// `self`.
    ///
    /// # Safety
    ///
    /// Caller asserts no other reference to the transport is live.
    /// Upheld by the single-task responder invariant: this is only
    /// called from `recv_request` / `send_response` on the responder
    /// task, which never re-enters itself.
    #[inline]
    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn transport_mut(&self) -> &mut Box<dyn SpdmPalTransport> {
        &mut *self.transport.get()
    }

    /// Reports the transport MTU without taking a mutable borrow.
    ///
    /// # Returns
    ///
    /// The byte count returned by
    /// [`SpdmPalTransport::mtu`] — the maximum SPDM payload the
    /// transport carries per message, excluding framing.
    pub(crate) fn transport_mtu(&self) -> usize {
        // SAFETY: `mtu` only reads transport fields and never mutates.
        unsafe { (*self.transport.get()).mtu() }
    }

    /// Reports whether the transport supports Secured Messages.
    ///
    /// # Returns
    ///
    /// `true` if the transport advertises SPDM Secured Message
    /// framing support, `false` otherwise.
    pub(crate) fn transport_secure_supported(&self) -> bool {
        // SAFETY: shared-read only.
        unsafe { (*self.transport.get()).secure_message_supported() }
    }

    /// Number of transport-framing header bytes.
    ///
    /// # Returns
    ///
    /// Byte count returned by [`SpdmPalTransport::header_size`] —
    /// the offset at which the SPDM payload starts inside the
    /// transport's send/receive buffers.
    pub(crate) fn transport_header_size(&self) -> usize {
        // SAFETY: shared-read only.
        unsafe { (*self.transport.get()).header_size() }
    }

    pub(crate) fn transport_send_len_alignment(&self) -> usize {
        // SAFETY: shared-read only.
        unsafe { (*self.transport.get()).send_len_alignment() }
    }
}

impl SpdmPal for McuSpdmPal {}
