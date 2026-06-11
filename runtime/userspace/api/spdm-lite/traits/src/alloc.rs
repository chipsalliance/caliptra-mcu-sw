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

pub trait SpdmPalAlloc {
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
}
