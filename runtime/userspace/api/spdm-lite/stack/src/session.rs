// Licensed under the Apache-2.0 license

//! SPDM secure session management.
//!
//! Owns the fixed-size session table ([`SessionManager`]) and
//! per-session state ([`SessionInfo`]). Session lifecycle:
//!
//! 1. KEY_EXCHANGE → [`SessionManager::create_session`] →
//!    `HandshakeInProgress`
//! 2. FINISH → state = `Established`, handshake keys destroyed
//! 3. Session used for secured message framing
//! 4. GET_VERSION or error → [`SessionManager::remove_all_and_destroy`]

use core::ops::{Deref, DerefMut};
use mcu_spdm_lite_codec::{errors::SPDM_SESSION_LIMIT_EXCEEDED, SpdmVersion};
use mcu_spdm_lite_traits::{McuResult, SpdmPalHash, SpdmPalIo};

use crate::key_schedule::{spdm_version_str, KeySchedule};

// ── Session state ───────────────────────────────────────────────────

/// Session lifecycle state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// KEY_EXCHANGE_RSP sent, waiting for FINISH.
    HandshakeInProgress,
    /// FINISH done, data keys active.
    Established,
}

// ── Per-session TH transcript ───────────────────────────────────────

/// Per-session TH transcript hash state.
///
/// Wraps the PAL's running-hash state (`S`) with methods that enforce
/// the correct TH feeding order.
///
/// The TH is started by **forking** (cloning) the connection's
/// running VCA hash state via [`init_from_running`](Self::init_from_running).
/// This ensures the raw VCA message bytes are already consumed in
/// the hash, producing `TH = hash(raw_VCA ‖ …)` as SPDM
/// requires. Handlers then append cert_chain_hash,
/// KEY_EXCHANGE_REQ, KEY_EXCHANGE_RSP, signature, FINISH_REQ, and
/// FINISH_RSP.
///
/// # Heap allocation
///
/// When `S = HashState` (the caliptra-api-lite backend), each
/// `Option<S>` allocates 200 bytes on the global heap via `Box`.
/// One instance exists per session, so N concurrent sessions add
/// `N × 200` bytes of heap for TH. The owning [`SessionInfo`] is also
/// heap-allocated by [`SessionManager::create_session`], so secure
/// session state does not inflate the responder task future while no
/// session is active.
pub struct SessionTranscript<S> {
    th: Option<S>,
}

impl<S> Default for SessionTranscript<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> SessionTranscript<S> {
    pub const fn new() -> Self {
        Self { th: None }
    }

    /// Fork the running VCA hash state into this session's TH.
    ///
    /// The cloned state already contains the raw VCA message bytes
    /// (GET_VERSION ‖ VERSION ‖ … ‖ ALGORITHMS). Subsequent
    /// [`Self::append`] calls add cert_chain_hash, KEY_EXCHANGE_REQ,
    /// KEY_EXCHANGE_RSP, etc., producing the correct TH input:
    ///
    /// ```text
    /// TH = hash(raw_VCA ‖ cert_chain_hash ‖ req ‖ rsp_partial)
    /// ```
    ///
    /// **Do not** feed `hash(VCA)` into a fresh hash — that would
    /// produce `hash(hash(VCA) ‖ …)`, which is incorrect per
    /// SPDM
    pub fn init_from_running<H: SpdmPalHash<State = S>>(
        &mut self,
        hash: &H,
        io: &impl SpdmPalIo,
        running: &S,
    ) -> McuResult<()> {
        self.th = Some(hash.hash_clone(io, running)?);
        Ok(())
    }

    /// Append data to the running TH.
    pub async fn append<H: SpdmPalHash<State = S>>(
        &mut self,
        hash: &H,
        io: &impl SpdmPalIo,
        data: &[u8],
    ) -> McuResult<()> {
        let state = self.th.as_mut().ok_or(mcu_error::codes::INVARIANT)?;
        hash.hash_update(io, state, data).await
    }

    /// Clone the running state and finalize the clone to produce a
    /// digest, leaving the original state intact for further appending.
    ///
    /// Used for TH1 (signing) and TH1' (HMAC) snapshots.
    pub async fn clone_and_finalize<H: SpdmPalHash<State = S>>(
        &self,
        hash: &H,
        io: &impl SpdmPalIo,
        out: &mut [u8],
    ) -> McuResult<()> {
        let state = self.th.as_ref().ok_or(mcu_error::codes::INVARIANT)?;
        let mut clone = hash.hash_clone(io, state)?;
        hash.hash_finish(io, &mut clone, out).await
    }

    /// Finalize destructively (last use — e.g. TH2).
    pub async fn finalize<H: SpdmPalHash<State = S>>(
        &mut self,
        hash: &H,
        io: &impl SpdmPalIo,
        out: &mut [u8],
    ) -> McuResult<()> {
        let state = self.th.as_mut().ok_or(mcu_error::codes::INVARIANT)?;
        hash.hash_finish(io, state, out).await?;
        self.th = None;
        Ok(())
    }
}

// ── SessionInfo ─────────────────────────────────────────────────────

/// Per-session state.
///
/// `K` = [`SpdmPalSessionCrypto::Key`], `S` = [`SpdmPalHash::State`].
pub struct SessionInfo<K: Clone, S> {
    /// Combined session ID: `(rsp_session_id << 16) | req_session_id`.
    pub session_id: u32,
    /// Lifecycle state.
    pub state: SessionState,
    /// Key schedule (owns all CMK handles for this session).
    pub key_schedule: KeySchedule<K>,
    /// Per-session TH transcript hash state.
    pub transcript: SessionTranscript<S>,
}

impl<K: Clone, S> SessionInfo<K, S> {
    /// Construct a new `SessionInfo` value. Caller is responsible for
    /// wrapping it in the appropriate box type via the PAL allocator.
    pub fn new(session_id: u32, version: SpdmVersion) -> Self {
        Self {
            session_id,
            state: SessionState::HandshakeInProgress,
            key_schedule: KeySchedule::new(spdm_version_str(version)),
            transcript: SessionTranscript::new(),
        }
    }
}

// ── SessionManager ──────────────────────────────────────────────────

/// Fixed-size session table.
///
/// `K` = key handle, `S` = hash state, `B` = box type wrapping
/// `SessionInfo<K, S>`, `N` = max concurrent sessions.
pub struct SessionManager<K: Clone, S, B, const N: usize> {
    sessions: [Option<B>; N],
    next_rsp_session_id: u16,
    _phantom: core::marker::PhantomData<(K, S)>,
}

impl<K: Clone, S, B, const N: usize> Default for SessionManager<K, S, B, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Clone, S, B, const N: usize> SessionManager<K, S, B, N> {
    pub fn new() -> Self {
        Self {
            sessions: core::array::from_fn(|_| None),
            next_rsp_session_id: 1,
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<K: Clone, S, B: Deref<Target = SessionInfo<K, S>> + DerefMut, const N: usize>
    SessionManager<K, S, B, N>
{
    /// Allocate a new session slot.
    ///
    /// `alloc_fn` is called to wrap the constructed `SessionInfo` in the
    /// platform box type (e.g., `McuSpdmBox` from bitmap, or `Box` in tests).
    ///
    /// Returns the combined session ID on success. The session starts
    /// in [`SessionState::HandshakeInProgress`].
    pub fn create_session(
        &mut self,
        req_session_id: u16,
        version: SpdmVersion,
        alloc_fn: impl FnOnce(SessionInfo<K, S>) -> McuResult<B>,
    ) -> McuResult<u32> {
        let slot = self
            .sessions
            .iter()
            .position(|s| s.is_none())
            .ok_or(SPDM_SESSION_LIMIT_EXCEEDED)?;

        // Pick a responder session ID that avoids collision.
        let rsp_id = self.alloc_rsp_session_id(req_session_id)?;
        let session_id = ((rsp_id as u32) << 16) | (req_session_id as u32);

        let info = SessionInfo::new(session_id, version);
        self.sessions[slot] = Some(alloc_fn(info)?);

        Ok(session_id)
    }

    /// Look up a session by combined ID.
    pub fn find(&self, session_id: u32) -> Option<&SessionInfo<K, S>> {
        self.sessions
            .iter()
            .flatten()
            .find(|s| s.session_id == session_id)
            .map(|b| &**b)
    }

    /// Look up a session by combined ID (mutable).
    pub fn find_mut(&mut self, session_id: u32) -> Option<&mut SessionInfo<K, S>> {
        self.sessions
            .iter_mut()
            .flatten()
            .find(|s| s.session_id == session_id)
            .map(|b| &mut **b)
    }

    /// Remove a session and clear all local key blobs.
    pub fn remove_and_destroy(&mut self, session_id: u32) {
        for slot in self.sessions.iter_mut() {
            if slot.as_ref().is_some_and(|s| s.session_id == session_id) {
                if let Some(info) = slot.as_mut() {
                    info.key_schedule.destroy_all();
                }
                *slot = None;
                return;
            }
        }
    }

    /// Remove all sessions and clear all local key blobs.
    pub fn remove_all_and_destroy(&mut self) {
        for slot in self.sessions.iter_mut() {
            if let Some(info) = slot.as_mut() {
                info.key_schedule.destroy_all();
            }
            *slot = None;
        }
    }

    /// Check if any session is in the handshake phase.
    pub fn has_handshake_in_progress(&self) -> bool {
        self.sessions
            .iter()
            .flatten()
            .any(|s| s.state == SessionState::HandshakeInProgress)
    }

    /// Allocate a responder session ID that doesn't collide with
    /// existing sessions. Skips ID 0.
    fn alloc_rsp_session_id(&mut self, req_id: u16) -> McuResult<u16> {
        // Try up to N+1 IDs (to handle wrap-around)
        for _ in 0..=N {
            let rsp_id = self.next_rsp_session_id;
            self.next_rsp_session_id = self.next_rsp_session_id.wrapping_add(1);
            if self.next_rsp_session_id == 0 {
                self.next_rsp_session_id = 1;
            }

            let combined = ((rsp_id as u32) << 16) | (req_id as u32);
            let collision = self
                .sessions
                .iter()
                .flatten()
                .any(|s| s.session_id == combined);
            if !collision {
                return Ok(rsp_id);
            }
        }
        Err(SPDM_SESSION_LIMIT_EXCEEDED)
    }
}
