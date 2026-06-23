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
/// a caller-supplied scratch region. The allocator serves both
/// per-request scratch allocations and any large-message buffer
/// retained on connection state across exchanges.
pub struct McuSpdmPal<M: MeasurementProvider> {
    /// The wrapped byte-oriented PAL transport.
    pub(crate) transport: UnsafeCell<Box<dyn SpdmPalTransport>>,

    /// Per-task scratch allocator. Lifted to `'static` so its lifetime is
    /// independent of the PAL — long-lived allocations (the in-flight large
    /// SPDM message owned by `LargeTransfer` state) can outlive any single
    /// SPDM request cycle without needing a `'pal` lifetime parameter
    /// threaded through the stack.
    pub(crate) allocator: &'static BitmapAllocator,

    /// Shared cert store — same instance for all transports.
    pub(crate) cert_store: &'static SharedCertStore,

    /// Measurement data provider (monomorphized).
    pub(crate) meas_provider: M,
}

impl<M: MeasurementProvider> McuSpdmPal<M> {
    /// Creates a new `McuSpdmPal` with a measurement provider.
    ///
    /// # Safety
    ///
    /// * `allocator` — A `&'static BitmapAllocator` obtained from
    ///   [`StaticBitmapAllocatorCell::init_once`]. Must be exclusively used
    ///   by the task owning this `McuSpdmPal` (the underlying allocator is
    ///   `!Sync`; using it from multiple tasks is undefined behavior).
    /// * The constructed `McuSpdmPal` must only be driven from a single
    ///   task; calling `recv_request` / `send_response` concurrently is
    ///   undefined behavior (interior mutability is not synchronized).
    pub unsafe fn new(
        transport: Box<dyn SpdmPalTransport>,
        allocator: &'static BitmapAllocator,
        cert_store: &'static SharedCertStore,
        meas_provider: M,
    ) -> Self {
        Self {
            transport: UnsafeCell::new(transport),
            allocator,
            cert_store,
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
