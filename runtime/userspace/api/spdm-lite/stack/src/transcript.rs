// Licensed under the Apache-2.0 license

//! Transcript manager (DSP0274 §8.10).
//!
//! Generic over the [`Hash::State`](mcu_spdm_lite_traits::Hash)
//! associated type so the manager works with any hash backend —
//! Caliptra mailbox (200-byte ctx), software (sha2 crate), test
//! mocks (whatever).
//!
//! Holds **only running hash states** — never the raw bytes of the
//! transcript.
//!
//! ## Design
//!
//! Spec rule: `M1 = A ∥ B ∥ C` and (for V1.2+) `L1 = A ∥ M`, where
//! `A` is the VCA bytes. We keep an always-running VCA hash and
//! **fork it with a fallible hash-clone operation** the first time
//! M1 / L1 actually start contributing. This lets heap-backed hash
//! states report allocation failure instead of panicking.

use mcu_spdm_lite_traits::{McuResult, SpdmPalHash, SpdmPalHashAlgo, SpdmPalIo};

/// One of the running transcripts the responder maintains.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Slot {
    /// Always-running VCA hash (DSP0274 §10.4.1).
    Vca,
    /// `M1` transcript — CHALLENGE_AUTH signature input.
    M1,
    /// `L1` transcript — MEASUREMENTS signature input.
    L1,
}

/// SPDM-Lite transcript state.
///
/// `S` is the [`Hash::State`] of the chosen hash backend.
///
/// # Heap allocation
///
/// When `S = HashState` (the caliptra-api-lite backend), each of
/// the three `Option<S>` slots allocates 200 bytes on the global
/// heap via `Box` when initialized — up to 600 bytes total.
/// See [`HashState`](caliptra_api_lite::sha::HashState) for details.
pub struct Transcript<S> {
    pub(crate) vca: Option<S>,
    pub(crate) m1: Option<S>,
    pub(crate) l1: Option<S>,
}

impl<S> Default for Transcript<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Transcript<S> {
    pub const fn new() -> Self {
        Self {
            vca: None,
            m1: None,
            l1: None,
        }
    }

    /// Drops every connection-scoped transcript context. Called by
    /// the dispatcher on every `GET_VERSION` per DSP0274 §10.4.
    pub fn reset(&mut self) {
        self.vca = None;
        self.m1 = None;
        self.l1 = None;
    }

    pub async fn append_vca<H>(
        &mut self,
        hash: &H,
        io: &impl SpdmPalIo,
        bytes: &[u8],
    ) -> McuResult<()>
    where
        H: SpdmPalHash<State = S>,
    {
        self.append(Slot::Vca, hash, io, bytes).await
    }

    pub async fn append_m1<H>(
        &mut self,
        hash: &H,
        io: &impl SpdmPalIo,
        bytes: &[u8],
    ) -> McuResult<()>
    where
        H: SpdmPalHash<State = S>,
    {
        self.append(Slot::M1, hash, io, bytes).await
    }

    pub async fn append_l1<H>(
        &mut self,
        hash: &H,
        io: &impl SpdmPalIo,
        bytes: &[u8],
    ) -> McuResult<()>
    where
        H: SpdmPalHash<State = S>,
    {
        self.append(Slot::L1, hash, io, bytes).await
    }

    pub async fn finalize_m1<H>(
        &mut self,
        hash: &H,
        io: &impl SpdmPalIo,
        out: &mut [u8],
    ) -> McuResult<()>
    where
        H: SpdmPalHash<State = S>,
    {
        self.finalize(Slot::M1, hash, io, out).await
    }

    pub async fn finalize_l1<H>(
        &mut self,
        hash: &H,
        io: &impl SpdmPalIo,
        out: &mut [u8],
    ) -> McuResult<()>
    where
        H: SpdmPalHash<State = S>,
    {
        self.finalize(Slot::L1, hash, io, out).await
    }

    // ---- Workhorses (the only `#[inline(never)]` symbols) ---------------

    #[inline(never)]
    async fn append<H>(
        &mut self,
        slot: Slot,
        hash: &H,
        io: &impl SpdmPalIo,
        bytes: &[u8],
    ) -> McuResult<()>
    where
        H: SpdmPalHash<State = S>,
    {
        // Lazy init / fork on first call after reset.
        match slot {
            Slot::Vca if self.vca.is_none() => {
                self.vca = Some(hash.hash_init(io, SpdmPalHashAlgo::Sha384, bytes).await?);
                return Ok(());
            }
            Slot::M1 if self.m1.is_none() => {
                let vca = self.vca.as_ref().ok_or(mcu_error::codes::INVARIANT)?;
                self.m1 = Some(hash.hash_clone(io, vca)?);
            }
            Slot::L1 if self.l1.is_none() => {
                let vca = self.vca.as_ref().ok_or(mcu_error::codes::INVARIANT)?;
                self.l1 = Some(hash.hash_clone(io, vca)?);
            }
            _ => {}
        }
        let state = self.slot_mut(slot).ok_or(mcu_error::codes::INVARIANT)?;
        hash.hash_update(io, state, bytes).await
    }

    #[inline(never)]
    async fn finalize<H>(
        &mut self,
        slot: Slot,
        hash: &H,
        io: &impl SpdmPalIo,
        out: &mut [u8],
    ) -> McuResult<()>
    where
        H: SpdmPalHash<State = S>,
    {
        let state = self.slot_mut(slot).ok_or(mcu_error::codes::INVARIANT)?;
        hash.hash_finish(io, state, out).await?;
        *self.slot_opt_mut(slot) = None;
        Ok(())
    }

    #[inline]
    fn slot_mut(&mut self, slot: Slot) -> Option<&mut S> {
        match slot {
            Slot::Vca => self.vca.as_mut(),
            Slot::M1 => self.m1.as_mut(),
            Slot::L1 => self.l1.as_mut(),
        }
    }

    #[inline]
    fn slot_opt_mut(&mut self, slot: Slot) -> &mut Option<S> {
        match slot {
            Slot::Vca => &mut self.vca,
            Slot::M1 => &mut self.m1,
            Slot::L1 => &mut self.l1,
        }
    }

    /// Clone-and-finalize the VCA state to produce a VCA digest
    /// without consuming the running state.
    ///
    /// This is used to seed per-session TH transcripts: TH starts
    /// with `hash(VCA)` (the 48-byte SHA-384 digest), not a fork of
    /// the running VCA hash state.
    pub async fn vca_digest<H>(
        &self,
        hash: &H,
        io: &impl SpdmPalIo,
        out: &mut [u8],
    ) -> McuResult<()>
    where
        H: SpdmPalHash<State = S>,
    {
        let vca = self.vca.as_ref().ok_or(mcu_error::codes::INVARIANT)?;
        let mut clone = hash.hash_clone(io, vca)?;
        hash.hash_finish(io, &mut clone, out).await
    }
}
