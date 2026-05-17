// Licensed under the Apache-2.0 license

//! SPDM cert-store abstraction (DSP0274 §10.5 / §10.6).
//!
//! Backends expose a slot-indexed view of the responder's cert
//! chains. The trait is intentionally minimal — no caching is
//! mandated; impls may go to flash, RAM, or fetch fresh from a
//! Caliptra mailbox on every call.

use crate::SpdmPalHashAlgo;
use mcu_error::McuResult;

/// Maximum number of cert-chain slots the responder advertises.
/// DSP0274 §10.5 caps this at 8 (`SlotMask` is one byte).
pub const MAX_SLOTS: u8 = 8;

/// Slot-indexed cert-store backend.
#[allow(async_fn_in_trait)]
pub trait SpdmPalCertStore: crate::SpdmPalIoTransport {
    /// Bitmask of provisioned slots, bits 0..=7. Drives DIGESTS's
    /// `SupportedSlotMask` / `ProvisionedSlotMask` (DSP0274 §10.5
    /// Table 25).
    fn provisioned_slots(&self) -> u8;

    /// Length in bytes of slot `slot`'s raw DER cert chain
    /// (excludes the 52-byte SPDM cert-chain header that the stack
    /// prepends — `Length(2) | Reserved(2) | RootHash(48)`).
    ///
    /// Async + `io`-taking because real cert stores live behind
    /// a mailbox: discovering the chain length may require multiple
    /// `GetCertificateChain` round-trips. Implementations are
    /// encouraged to cache the result internally.
    async fn cert_chain_len(&self, io: &Self::Io<'_>, slot: u8) -> McuResult<usize>;

    /// Write the digest of slot's **root certificate** under `algo`
    /// into `out`. `out.len()` must be at least `algo.hash_size()`.
    async fn root_cert_hash(
        &self,
        io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalHashAlgo,
        out: &mut [u8],
    ) -> McuResult<()>;

    /// Read at most `dst.len()` bytes from slot's raw cert chain at
    /// `offset` into `dst`. Returns bytes actually written;
    /// `Ok(0)` is the natural end-of-chain signal for streaming
    /// loops.
    async fn read_cert_chain(
        &self,
        io: &Self::Io<'_>,
        slot: u8,
        offset: usize,
        dst: &mut [u8],
    ) -> McuResult<usize>;

    /// Optional cache hook: return a previously stored full
    /// SPDM-cert-chain digest for `(slot, algo)`, or `None` to
    /// force recomputation. Default impl never caches.
    #[inline]
    fn cached_chain_digest(&self, _slot: u8, _algo: SpdmPalHashAlgo) -> Option<[u8; 48]> {
        None
    }

    /// Optional cache hook: store the freshly computed SPDM
    /// cert-chain digest for future
    /// [`cached_chain_digest`](Self::cached_chain_digest) lookups.
    /// Default impl is a no-op.
    #[inline]
    fn cache_chain_digest(&self, _slot: u8, _algo: SpdmPalHashAlgo, _digest: &[u8]) {}
}
