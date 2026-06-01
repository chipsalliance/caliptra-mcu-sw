// Licensed under the Apache-2.0 license

//! Persistent large-message storage for SPDM chunking.
//!
//! Per-I/O scratch allocations are reset on every received request, so
//! `CHUNK_SEND` reassembly needs a tiny persistent byte-store API.

use super::*;

/// Platform-provided persistent storage for one in-flight large SPDM message.
pub trait SpdmPalLargeMessage {
    /// Maximum reassembled message size this responder can hold.
    fn capacity(&self) -> usize;

    /// Copy `data` into the persistent large-message buffer at `offset`.
    fn write(&self, offset: usize, data: &[u8]) -> McuResult<()>;

    /// Copy bytes from the persistent large-message buffer into `out`.
    fn read(&self, offset: usize, out: &mut [u8]) -> McuResult<()>;

    /// Mutably borrow the leading `len` bytes of the persistent large-message buffer.
    ///
    /// # Safety
    ///
    /// Callers must ensure there is no other live borrow of the persistent
    /// large-message buffer, and must not hold the returned mutable slice across
    /// another PAL operation that could access that buffer.
    unsafe fn large_message_mut(&self, len: usize) -> McuResult<&mut [u8]>;
}
