// Licensed under the Apache-2.0 license

//! Persistent large-message storage for SPDM chunking.
//!
//! Per-I/O scratch allocations are reset on every received request, so
//! `CHUNK_SEND` reassembly needs a tiny persistent byte-store API.

use super::*;

/// Platform-provided persistent storage for one in-flight large SPDM message.
pub trait SpdmPalLargeMessage {
    /// Maximum reassembled message size this responder can hold.
    fn large_message_capacity(&self) -> usize;

    /// Copy `data` into the persistent large-message buffer at `offset`.
    fn write_large_message(&self, offset: usize, data: &[u8]) -> McuResult<()>;

    /// Borrow the leading `len` bytes of the persistent large-message buffer.
    fn large_message(&self, len: usize) -> McuResult<&[u8]>;

    /// Mutably borrow the leading `len` bytes of the persistent large-message buffer.
    ///
    /// Implementations may rely on the spdm-lite single-responder-task invariant;
    /// callers must not hold this borrow across another PAL operation that could
    /// access the same persistent buffer.
    fn large_message_mut(&self, len: usize) -> McuResult<&mut [u8]>;
}
