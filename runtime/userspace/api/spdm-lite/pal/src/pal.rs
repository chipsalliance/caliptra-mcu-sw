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
use core::cell::{Cell, UnsafeCell};
use core::ptr::NonNull;

use super::cert::store::SharedCertStore;
use super::measurements::MeasurementProvider;

/// MCU implementation of the SPDM-Lite Platform Abstraction Layer.
///
/// Generic over `M: MeasurementProvider` so all measurement dispatch
/// is monomorphized (no dyn).
///
/// Owns the underlying byte-oriented PAL transport (held behind an
/// [`UnsafeCell`] for interior mutability — the SPDM responder is
/// strictly single-task, so we never observe concurrent access) plus a
/// single [`BitmapAllocator`](super::alloc::BitmapAllocator) backed by
/// a caller-supplied scratch region. The allocator is reset at the
/// start of every `recv_request`, so allocations are scoped to a
/// single SPDM exchange even though the allocator object itself lives
/// on the PAL.
pub struct McuSpdmPal<M: MeasurementProvider> {
    /// The wrapped byte-oriented PAL transport.
    pub(crate) transport: UnsafeCell<Box<dyn SpdmPalTransport>>,

    /// Per-IO scratch allocator, reset by every `recv_request`.
    pub(crate) allocator: BitmapAllocator,

    /// Shared cert store — same instance for all transports.
    pub(crate) cert_store: &'static SharedCertStore,

    /// Persistent static buffer holding one in-flight large SPDM message
    /// (`CHUNK_GET` response or `CHUNK_SEND` reassembly). Lent out for reads /
    /// writes via [`Cell::take`]/[`Cell::set`] (the empty slice marks it
    /// "checked out"), so a chunked transfer survives the per-request allocator
    /// `reset`. No `unsafe` is needed to hand out the writable slice.
    pub(crate) large_buf: Cell<Option<&'static mut [u8]>>,

    /// Measurement data provider (monomorphized).
    pub(crate) meas_provider: M,
}

impl<M: MeasurementProvider> McuSpdmPal<M> {
    /// Creates a new `McuSpdmPal` with persistent chunk storage and a
    /// measurement provider.
    ///
    /// # Safety
    ///
    /// * `io_buf_ptr` must be aligned to
    ///   [`BITMAP_SLOT_SIZE`](super::alloc::BITMAP_SLOT_SIZE) and point
    ///   to `io_buf_capacity` bytes of writable memory exclusively
    ///   owned by this `McuSpdmPal` for its entire lifetime.
    /// * `large_buf` — When present, a dedicated static buffer holding one
    ///   in-flight large SPDM message (`CHUNK_GET` response / `CHUNK_SEND`
    ///   reassembly). Must be exclusively owned by this `McuSpdmPal` for its
    ///   entire lifetime; its length caps `MaxSPDMmsgSize`.
    /// * The constructed `McuSpdmPal` must only be driven from a single
    ///   task; calling `recv_request` / `send_response` concurrently is
    ///   undefined behavior (interior mutability is not synchronized).
    pub unsafe fn new(
        transport: Box<dyn SpdmPalTransport>,
        io_buf_ptr: NonNull<u8>,
        io_buf_capacity: usize,
        cert_store: &'static SharedCertStore,
        large_buf: Option<&'static mut [u8]>,
        meas_provider: M,
    ) -> Self {
        Self {
            transport: UnsafeCell::new(transport),
            allocator: BitmapAllocator::new(io_buf_ptr, io_buf_capacity),
            cert_store,
            large_buf: Cell::new(large_buf),
            meas_provider,
        }
    }

    /// Returns an exclusive reference to the wrapped transport.
    ///
    /// # Safety
    ///
    /// Caller asserts no other reference to the transport is live.
    /// Upheld by the single-task responder invariant.
    #[inline]
    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn transport_mut(&self) -> &mut Box<dyn SpdmPalTransport> {
        &mut *self.transport.get()
    }

    /// Reports the transport MTU without taking a mutable borrow.
    pub(crate) fn transport_mtu(&self) -> usize {
        unsafe { (*self.transport.get()).mtu() }
    }

    /// Reports whether the transport supports Secured Messages.
    pub(crate) fn transport_secure_supported(&self) -> bool {
        unsafe { (*self.transport.get()).secure_message_supported() }
    }

    /// Number of transport-framing header bytes.
    pub(crate) fn transport_header_size(&self) -> usize {
        unsafe { (*self.transport.get()).header_size() }
    }

    pub(crate) fn transport_send_len_alignment(&self) -> usize {
        unsafe { (*self.transport.get()).send_len_alignment() }
    }
}

impl<M: MeasurementProvider> SpdmPal for McuSpdmPal<M> {}
