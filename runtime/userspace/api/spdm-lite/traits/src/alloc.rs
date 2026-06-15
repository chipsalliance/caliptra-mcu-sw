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
//! Allocations are scoped to a single SPDM I/O exchange ([`SpdmPalIo`])
//! so the platform can correlate allocator lifetime with the in-flight
//! request and reclaim memory between exchanges.

use self::super::*;
use core::ops::DerefMut;

/// Factory trait for platform-managed SPDM-Lite allocations.
///
/// Implementors expose a single allocation slot (or pool) that can be
/// rented to the SPDM-Lite stack for the duration of a single
/// [`SpdmPalIo`] exchange. The returned [`Self::Box`] borrows from
/// `self`, so only one outstanding allocation per `SpdmPalAlloc`
/// instance is permitted at a time.
/// Type alias for the byte-buffer guard handed out by a PAL's
/// [`SpdmPalAlloc::alloc_bytes`]. Handlers use this to return their
/// fully-encoded response buffer up to the dispatcher.
pub type PalBytes<'a, Pal> = <Pal as SpdmPalAlloc>::Bytes<'a>;

pub trait SpdmPalAlloc: mcu_caliptra_api_lite::ApiAlloc {
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
    // reassembly buffer) is held in a single persistent buffer that outlives the
    // request that produces it and is served/consumed over later exchanges.
    // Backed by the same pool as the per-request scratch (allocated on demand,
    // reusable as scratch when idle) rather than a dedicated static region.

    /// Maximum size, in bytes, of a single in-flight large SPDM message this
    /// responder can hold. Drives the `CHUNK` capability advertisement
    /// (`MaxSPDMmsgSize`) and buffered large-response/request validation.
    fn large_capacity(&self) -> usize;

    /// Reserves the persistent large-message buffer (`len` bytes) from the pool,
    /// replacing (freeing) any previously-held one. Must be called before
    /// [`Self::large_write`] / [`Self::large_read`]. The buffer persists across
    /// requests until [`Self::large_end`] releases it (or the next `large_begin`
    /// replaces it).
    fn large_begin(&self, len: usize) -> McuResult<()>;

    /// Copies `data` into the held large-message buffer at `offset`.
    fn large_write(&self, offset: usize, data: &[u8]) -> McuResult<()>;

    /// Copies bytes from the held large-message buffer at `offset` into `out`.
    fn large_read(&self, offset: usize, out: &mut [u8]) -> McuResult<()>;

    /// Releases the large-message buffer back to the pool (freed and zeroed).
    /// Idempotent: a no-op when no large buffer is currently held.
    fn large_end(&self);

    /// RAII guard type returned by [`Self::large_take`].
    ///
    /// Implementors return any owning handle that derefs to a `[u8]` slice of
    /// exactly the requested length over the persistent large-message buffer.
    /// Dropping the guard must return the underlying slice to the PAL so that
    /// subsequent [`Self::large_read`] / [`Self::large_capacity`] calls see it
    /// again. The drop **must not** wipe the slice — the bytes need to survive
    /// for chunked delivery.
    type LargeBuf<'a>: DerefMut<Target = [u8]>
    where
        Self: 'a;

    /// Reserves the persistent large-message buffer and hands out a mutable
    /// view of exactly `len` bytes to the caller. The bytes survive after the
    /// guard drops (so `CHUNK_GET` can serve them via [`Self::large_read`]).
    ///
    /// While the returned guard is alive, the underlying slice is not parked
    /// in the PAL, so calls to [`Self::large_capacity`], [`Self::large_begin`],
    /// [`Self::large_write`], or [`Self::large_read`] from another code path
    /// will observe an empty buffer. A single-task SPDM responder runs requests
    /// sequentially, so this is safe — but callers must drop the guard before
    /// invoking those methods.
    fn large_take(&self, len: usize) -> McuResult<Self::LargeBuf<'_>>;
}
