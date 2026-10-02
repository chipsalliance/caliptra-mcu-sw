// Licensed under the Apache-2.0 license

//! Platform-specific allocator traits for SPDM-Lite.
//!
//! The SPDM-Lite stack often needs to allocate scratch buffers and
//! protocol state from a platform-managed memory pool rather than the
//! global heap. This module defines:
//!
//! * [`SpdmPalAlloc`] — A factory that hands out one allocation at a
//!   time from a platform pool (e.g., DTCM scratch memory). Allocations
//!   are returned as RAII guards implementing [`core::ops::DerefMut`],
//!   which release the underlying memory back to the pool on drop.
//!
//! Most allocations are scoped to a single SPDM I/O exchange ([`SpdmPalIo`]).
//! One persistent large-message buffer may outlive an exchange while it is
//! parked on `ConnectionState::large_buf`.

use self::super::*;
use core::ops::DerefMut;

/// Byte-buffer guard handed out by [`SpdmPalAlloc::alloc_bytes`]. Handlers
/// return their fully-encoded response in one of these.
pub type PalBytes<'a, Pal> = <Pal as SpdmPalAlloc>::Bytes<'a>;

/// Platform-managed allocation for the SPDM stack.
///
/// The stack takes scratch buffers and protocol state from a platform-owned
/// pool rather than the global heap, so SPDM memory use is bounded and
/// independent of other tasks.
///
/// # Contract
///
/// - Every guard type releases its storage back to the pool on `Drop`.
/// - Scratch allocations ([`alloc`](Self::alloc), [`alloc_bytes`](Self::alloc_bytes))
///   borrow `self` and are scoped to one [`SpdmPalIo`] exchange.
/// - Large-message and persistent allocations deliberately outlive an
///   exchange; see their sections below for who is expected to hold them.
/// - The [`ScratchAllocProvider`](mcu_caliptra_api::ScratchAllocProvider) supertrait is
///   what lets a PAL reach the Caliptra mailbox APIs: a PAL exposes the
///   allocator it borrows instead of implementing
///   [`ScratchAlloc`](mcu_caliptra_api::ScratchAlloc) itself, so those APIs compile
///   once over the concrete allocator no matter how many PALs exist.
pub trait SpdmPalAlloc: mcu_caliptra_api::ScratchAllocProvider {
    /// RAII guard type returned by [`Self::alloc`].
    ///
    /// Implementors return any owning handle that derefs to `T` (e.g.,
    /// a `Box`-like wrapper over a bitmap-managed slot). Dropping the
    /// box must release the underlying allocation back to the pool.
    type Box<'a, T>: DerefMut<Target = T>
    where
        Self: 'a,
        T: Sized + 'a;

    /// RAII guard type returned by [`Self::alloc_bytes`]. Must deref
    /// to a `[u8]` slice of exactly the requested length.
    type Bytes<'a>: DerefMut<Target = [u8]>
    where
        Self: 'a;

    /// Allocates space for a `T` from the platform pool (e.g., the
    /// NonDma / DTCM scratch region) and moves `value` into it.
    fn alloc<T: Sized>(&self, io: &impl SpdmPalIo, value: T) -> McuResult<Self::Box<'_, T>>;

    /// Allocates a byte buffer of `len` bytes from the platform pool.
    ///
    /// The contents are uninitialized; callers must write before
    /// reading. Useful for response-building paths that need a
    /// variable-size buffer without using stack arrays.
    fn alloc_bytes(&self, io: &impl SpdmPalIo, len: usize) -> McuResult<Self::Bytes<'_>>;

    // ---- Persistent large-message buffer ------------------------------------
    //
    // One in-flight large SPDM message (a `CHUNK_GET` response or a `CHUNK_SEND`
    // reassembly buffer) may be allocated from the same pool as scratch memory,
    // then parked on `ConnectionState::large_buf` so it can survive across later
    // exchanges until chunking completes.

    /// Scratch-backed capacity for retaining one complete large request or
    /// response.
    ///
    /// This is not advertised as `MaxSPDMmsgSize`; streamed messages may exceed
    /// it.
    fn large_buffered_msg_capacity(&self) -> usize;

    /// RAII guard type returned by [`Self::alloc_large_buf`].
    type LargeBuf: DerefMut<Target = [u8]>;

    /// Allocates a persistent large-message buffer of exactly `len` bytes.
    /// Callers move the returned guard onto `ConnectionState::large_buf` when the
    /// message must survive across later exchanges.
    fn alloc_large_buf(&self, len: usize) -> McuResult<Self::LargeBuf>;

    /// Converts a large-message buffer into a normal response buffer.
    ///
    /// Used by handlers that first build into maximum-capacity storage, then
    /// discover from the actual encoded length that the response fits without
    /// chunking.
    fn large_buf_into_bytes(&self, buf: Self::LargeBuf, len: usize) -> McuResult<Self::Bytes<'_>>;

    // ---- Persistent typed allocations ----------------------------------------
    //
    // Long-lived objects (session state, hash contexts) that must survive across
    // SPDM exchanges but should NOT compete on the global heap.

    /// RAII owner for a typed persistent allocation. Stored in
    /// `SessionManager` across exchanges; released on session teardown.
    type PersistentBox<T: Sized + 'static>: DerefMut<Target = T>;

    /// Allocate a persistent typed object from the per-task pool.
    fn alloc_persistent<T: Sized + 'static>(&self, value: T) -> McuResult<Self::PersistentBox<T>>;
}
