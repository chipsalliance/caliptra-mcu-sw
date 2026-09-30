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

/// The canonical [`ApiAlloc`] behind an allocator owner or wrapper.
///
/// [`ApiAlloc`] carries a GAT, so it is not object-safe and every
/// `<A: ApiAlloc>` API is monomorphised once per implementor. Several
/// task owners delegate to the *same* underlying pool type. Making those
/// owners implement [`ApiAlloc`] would emit duplicate instantiations of
/// multi-kilobyte command handlers.
///
/// Owners expose their allocator here without becoming allocators themselves.
/// Callers hand [`Self::pool`] to generic APIs so every production task
/// instantiates them over the same concrete pool type. Leaf pools implement
/// this as the identity (`Pool = Self`).
pub trait ApiAllocPool {
    /// Allocator that actually owns the memory. Wrappers name their inner
    /// pool; a pool names itself.
    type Pool: ApiAlloc;

    /// Borrow the underlying pool.
    fn pool(&self) -> &Self::Pool;
}
