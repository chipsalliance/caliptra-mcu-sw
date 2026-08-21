// Licensed under the Apache-2.0 license

//! [`ApiAlloc`] — per-call scratch-allocator contract for Caliptra
//! mailbox primitives.

use core::ops::DerefMut;
use mcu_error::McuResult;

/// Per-call scratch allocator.
///
/// Implementors hand out uninitialised byte buffers whose lifetime
/// ends with the returned guard (i.e. when the mailbox round-trip
/// completes). The crate's mailbox primitives place their request
/// and response bytes in [`Self::Buf`] — never on the stack — so
/// callers' async-task futures don't grow by the multi-kilobyte
/// Caliptra `Cm*Req` payload field.
pub trait ApiAlloc {
    type Buf<'a>: DerefMut<Target = [u8]>
    where
        Self: 'a;

    /// Allocate `len` bytes of scratch. Contents are uninitialised
    /// — callers (including this crate) must write before reading.
    fn alloc(&self, len: usize) -> McuResult<Self::Buf<'_>>;
}

/// The canonical pool behind an [`ApiAlloc`] wrapper.
///
/// [`ApiAlloc`] carries a GAT, so it is not object-safe and every
/// `<A: ApiAlloc>` API is monomorphised once per implementor. Several
/// implementors are thin wrappers that delegate to the *same* underlying
/// pool, which makes those instantiations byte-identical and pure waste —
/// a multi-kilobyte command handler reachable from two transports is
/// emitted twice.
///
/// Implementors expose that shared pool here. Callers about to hand the
/// allocator to a large generic API pass [`Self::pool`] instead of `self`,
/// so every transport instantiates it over one type. Leaf pools implement
/// this as the identity (`Pool = Self`).
pub trait ApiAllocPool: ApiAlloc {
    /// Allocator that actually owns the memory. Wrappers name their inner
    /// pool; a pool names itself.
    type Pool: ApiAlloc;

    /// Borrow the underlying pool.
    fn pool(&self) -> &Self::Pool;
}
