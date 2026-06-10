// Licensed under the Apache-2.0 license

//! Running-hash abstraction used by the SPDM-Lite stack.
//!
//! Each backend defines its own [`SpdmPalHash::State`] type — the
//! 200-byte Caliptra mailbox context, a `sha2::Sha384` instance,
//! a test mock with arbitrary fields, etc. Containers that hold
//! hash state (the transcript manager, future signing flows) are
//! generic over `State`, never tied to a particular backend.
//!
//! # Why `&impl SpdmPalIo` on every call?
//!
//! Backends that need per-IO scratch (the Caliptra mailbox impl
//! allocates a 64-byte command buffer per call) use the
//! [`SpdmPalIo`] handle to scope those allocations to the
//! currently-in-flight SPDM exchange. Software backends ignore
//! the `io` argument entirely.
//!
//! # Fallible clone on `State`
//!
//! [`SpdmPalHash::hash_clone`] lets the transcript manager fork a
//! running hash and continue both branches independently — e.g.
//! `M1 = VCA.fork().extend(B).extend(C)` per SPDM The
//! operation is fallible because some backends allocate heap storage
//! for running hash contexts.

use super::*;

/// Hash algorithms supported by SPDM-Lite backends.
///
/// Extend this enum as new algorithms (SHA-256, SHA-512, …) are
/// wired up. Every variant must have an entry in
/// [`Self::hash_size`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SpdmPalHashAlgo {
    /// SHA-384 (48-byte digest).
    Sha384,
}

impl SpdmPalHashAlgo {
    /// Returns the digest size, in bytes, produced by
    /// [`SpdmPalHash::hash_finish`] when run against this algorithm.
    ///
    /// # Returns
    ///
    /// Number of bytes that will be written into the leading prefix
    /// of `out` by [`SpdmPalHash::hash_finish`]. Callers must size
    /// their digest buffer to at least this many bytes.
    #[inline]
    pub const fn hash_size(self) -> usize {
        match self {
            SpdmPalHashAlgo::Sha384 => 48,
        }
    }
}

/// Running-hash backend.
///
/// Implementors expose a streaming digest API: `init` → repeated
/// `update` → `finish`. State is opaque to callers; only the
/// digest written by `finish` is observable externally.
pub trait SpdmPalHash {
    /// Backend-defined running-hash state.
    type State;

    /// Begins a new running hash and returns the initial state.
    ///
    /// # Parameters
    ///
    /// * `io` — Handle to the in-flight SPDM exchange. Backends
    ///   that allocate per-call scratch use this to scope the
    ///   allocation; software backends ignore it.
    /// * `algo` — Hash algorithm to use. Must be a value the
    ///   backend supports.
    /// * `seed` — Optional first chunk to feed in. Pass an empty
    ///   slice (`&[]`) when no priming data is available. When
    ///   non-empty, `seed` is absorbed as if `hash_update` had
    ///   been called once with it before this function returned.
    ///
    /// # Returns
    ///
    /// * `Ok(State)` — Fresh running-hash state with `seed`
    ///   already absorbed (if non-empty), ready for further
    ///   [`Self::hash_update`] calls.
    ///
    /// # Errors
    ///
    /// * `Err(McuErrorCode)` — Backend-specific failure (mailbox
    ///   busy / hardware error / allocator exhausted / unsupported
    ///   `algo`). The exact code is backend-defined.
    async fn hash_init(
        &self,
        io: &impl SpdmPalIo,
        algo: SpdmPalHashAlgo,
        seed: &[u8],
    ) -> McuResult<Self::State>;

    /// Appends `data` to a running hash.
    ///
    /// `data` may be any length; the implementation chunks
    /// internally as needed. Calling `hash_update` with an empty
    /// slice is a no-op.
    ///
    /// # Parameters
    ///
    /// * `io` — Handle to the in-flight SPDM exchange. See
    ///   [`Self::hash_init`] for usage.
    /// * `state` — Running-hash state previously returned by
    ///   [`Self::hash_init`]; mutated in place.
    /// * `data` — Bytes to absorb into the running hash.
    ///
    /// # Returns
    ///
    /// * `Ok(())` — `state` now reflects the additional bytes.
    ///
    /// # Errors
    ///
    /// * `Err(McuErrorCode)` — Backend-specific failure during the
    ///   update; `state` should be considered invalid on error and
    ///   not reused.
    async fn hash_update(
        &self,
        io: &impl SpdmPalIo,
        state: &mut Self::State,
        data: &[u8],
    ) -> McuResult<()>;

    /// Fallibly clones a running hash state.
    ///
    /// The returned state must be independent: updates to one state
    /// must not affect the other. Backends that allocate per-state
    /// storage should return `OUT_OF_MEMORY` instead of panicking when
    /// cloning cannot allocate.
    fn hash_clone(&self, io: &impl SpdmPalIo, state: &Self::State) -> McuResult<Self::State>;

    /// Finalises the running hash and writes the digest into the
    /// leading prefix of `out`.
    ///
    /// After this call returns (successfully or not), `state` is no
    /// longer a valid running hash and must not be reused for
    /// further `hash_update` / `hash_finish` calls.
    ///
    /// # Parameters
    ///
    /// * `io` — Handle to the in-flight SPDM exchange. See
    ///   [`Self::hash_init`] for usage.
    /// * `state` — Running-hash state to finalise.
    /// * `out` — Destination for the digest. Must be at least
    ///   `algo.hash_size()` bytes (the `algo` originally passed to
    ///   [`Self::hash_init`]); only the leading prefix of that
    ///   length is written, the rest is left untouched.
    ///
    /// # Returns
    ///
    /// * `Ok(())` — Digest written into `out[0..algo.hash_size()]`.
    ///
    /// # Errors
    ///
    /// * `Err(McuErrorCode)` — Backend-specific failure (mailbox
    ///   error, `out` too short, etc.).
    async fn hash_finish(
        &self,
        io: &impl SpdmPalIo,
        state: &mut Self::State,
        out: &mut [u8],
    ) -> McuResult<()>;
}
