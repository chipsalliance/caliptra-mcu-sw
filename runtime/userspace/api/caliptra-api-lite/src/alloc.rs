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
