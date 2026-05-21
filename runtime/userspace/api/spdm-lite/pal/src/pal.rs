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
    /// The wrapped byte-oriented PAL transport. Wrapped in
    /// [`UnsafeCell`] because the
    /// [`SpdmPalIoTransport`](mcu_spdm_lite_traits::SpdmPalIoTransport)
    /// methods now take `&self` to allow `Self::Io<'_>` to remain
    /// borrowed across `alloc` / `send_response`. The single-task
    /// responder invariant rules out aliased access.
    pub(crate) transport: UnsafeCell<Box<dyn SpdmPalTransport>>,

    /// Per-IO scratch allocator, reset by every `recv_request`.
    pub(crate) allocator: BitmapAllocator,

    /// Optional persistent byte buffer used to reassemble one SPDM
    /// `CHUNK_SEND` large request across multiple I/O exchanges.
    pub(crate) large_msg_ptr: Option<NonNull<u8>>,
    pub(crate) large_msg_capacity: usize,

    /// Per-slot cache of the full SPDM cert-chain digest, indexed
    /// `[slot as usize]`. Lazily populated on first GET_DIGESTS;
    /// invalidation never required because the DPE-backed chain
    /// bytes (and Caliptra's RFC-6979–deterministic ECDSA leaf
    /// cert) are immutable for the responder's lifetime.
    pub(crate) cached_chain_digest:
        UnsafeCell<[Option<[u8; 48]>; mcu_spdm_lite_traits::MAX_SLOTS as usize]>,

    /// Per-slot cache of the raw DER cert-chain length (DPE chain
    /// bytes + leaf cert), indexed `[slot as usize]`. Populated as
    /// a side effect of length probing.
    pub(crate) cached_chain_len:
        UnsafeCell<[Option<u32>; mcu_spdm_lite_traits::MAX_SLOTS as usize]>,
}

impl McuSpdmPal {
    /// Creates a new `McuSpdmPal` wrapping the given PAL transport and
    /// per-IO scratch buffer plus a persistent large-message buffer
    /// used by SPDM chunk reassembly.
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
    /// * `large_msg_ptr` — Base of the caller-supplied persistent
    ///   buffer used to reassemble one `CHUNK_SEND` large request, or
    ///   `None` when large-message chunking is not supported by this
    ///   integration.
    /// * `large_msg_capacity` — Total length, in bytes, of the region
    ///   at `large_msg_ptr`. Ignored when `large_msg_ptr` is `None`.
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
    /// * When present, `large_msg_ptr` must point to
    ///   `large_msg_capacity` bytes of writable memory exclusively
    ///   owned by this `McuSpdmPal` for its entire lifetime.
    /// * The constructed `McuSpdmPal` must only be driven from a single
    ///   task; calling `recv_request` / `send_response` concurrently is
    ///   undefined behavior (interior mutability is not synchronized).
    pub unsafe fn new(
        transport: Box<dyn SpdmPalTransport>,
        io_buf_ptr: NonNull<u8>,
        io_buf_capacity: usize,
        large_msg_ptr: Option<NonNull<u8>>,
        large_msg_capacity: usize,
    ) -> Self {
        let large_msg_capacity = if large_msg_ptr.is_some() {
            large_msg_capacity
        } else {
            0
        };
        Self {
            transport: UnsafeCell::new(transport),
            allocator: BitmapAllocator::new(io_buf_ptr, io_buf_capacity),
            large_msg_ptr,
            large_msg_capacity,
            cached_chain_digest: UnsafeCell::new([None; mcu_spdm_lite_traits::MAX_SLOTS as usize]),
            cached_chain_len: UnsafeCell::new([None; mcu_spdm_lite_traits::MAX_SLOTS as usize]),
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
}

impl SpdmPal for McuSpdmPal {}
