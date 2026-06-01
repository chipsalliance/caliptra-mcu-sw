// Licensed under the Apache-2.0 license

//! SPDM secure session management.
//!
//! Owns the fixed-size session table ([`SessionManager`]) and
//! per-session state ([`SessionInfo`]).  Session lifecycle:
//!
//! 1. KEY_EXCHANGE → [`SessionManager::create_session`] →
//!    `HandshakeInProgress`
//! 2. FINISH → state = `Established`, handshake keys destroyed
//! 3. Session used for secured message framing
//! 4. GET_VERSION or error → [`SessionManager::remove_all_and_destroy`]

use mcu_spdm_lite_codec::SpdmVersion;
use mcu_spdm_lite_traits::{
    McuResult, SpdmPalHash, SpdmPalHashAlgo, SpdmPalIo, SpdmPalSessionCrypto,
};

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
/// The TH is started from `hash(VCA)` (the digest of VCA, not the
/// running VCA state).  Handlers then append cert_chain_hash,
/// KEY_EXCHANGE_REQ, KEY_EXCHANGE_RSP, signature, FINISH_REQ, and
/// FINISH_RSP.
pub struct SessionTranscript<S: Clone> {
    th: Option<S>,
}

impl<S: Clone> SessionTranscript<S> {
    pub const fn new() -> Self {
        Self { th: None }
    }

    /// Start the TH with `vca_digest` (hash(VCA)) as the first input.
    pub async fn init<H: SpdmPalHash<State = S>>(
        &mut self,
        hash: &H,
        io: &impl SpdmPalIo,
        vca_digest: &[u8],
    ) -> McuResult<()> {
        self.th = Some(
            hash.hash_init(io, SpdmPalHashAlgo::Sha384, vca_digest)
                .await?,
        );
        Ok(())
    }

    /// Append data to the running TH.
    pub async fn append<H: SpdmPalHash<State = S>>(
        &mut self,
        hash: &H,
        io: &impl SpdmPalIo,
        data: &[u8],
    ) -> McuResult<()> {
        let state = self
            .th
            .as_mut()
            .ok_or(mcu_error::codes::INVARIANT)?;
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
        let mut clone = self
            .th
            .clone()
            .ok_or(mcu_error::codes::INVARIANT)?;
        hash.hash_finish(io, &mut clone, out).await
    }

    /// Finalize destructively (last use — e.g. TH2).
    pub async fn finalize<H: SpdmPalHash<State = S>>(
        &mut self,
        hash: &H,
        io: &impl SpdmPalIo,
        out: &mut [u8],
    ) -> McuResult<()> {
        let state = self
            .th
            .as_mut()
            .ok_or(mcu_error::codes::INVARIANT)?;
        hash.hash_finish(io, state, out).await?;
        self.th = None;
        Ok(())
    }
}

// ── SessionInfo ─────────────────────────────────────────────────────

/// Per-session state.
///
/// `K` = [`SpdmPalSessionCrypto::Key`], `S` = [`SpdmPalHash::State`].
pub struct SessionInfo<K: Clone, S: Clone> {
    /// Combined session ID: `(rsp_session_id << 16) | req_session_id`.
    pub session_id: u32,
    /// Lifecycle state.
    pub state: SessionState,
    /// Key schedule (owns all CMK handles for this session).
    pub key_schedule: KeySchedule<K>,
    /// Per-session TH transcript hash state.
    pub transcript: SessionTranscript<S>,
}

// ── SessionManager ──────────────────────────────────────────────────

/// Fixed-size session table.
///
/// `K` = key handle, `S` = hash state, `N` = max concurrent sessions.
pub struct SessionManager<K: Clone, S: Clone, const N: usize> {
    sessions: [Option<SessionInfo<K, S>>; N],
    next_rsp_session_id: u16,
}

impl<K: Clone, S: Clone, const N: usize> SessionManager<K, S, N> {
    pub fn new() -> Self {
        Self {
            sessions: core::array::from_fn(|_| None),
            next_rsp_session_id: 1,
        }
    }

    /// Allocate a new session slot.
    ///
    /// Returns the combined session ID on success. The session starts
    /// in [`SessionState::HandshakeInProgress`].
    pub fn create_session(
        &mut self,
        req_session_id: u16,
        version: SpdmVersion,
    ) -> McuResult<u32> {
        let slot = self
            .sessions
            .iter()
            .position(|s| s.is_none())
            .ok_or(mcu_error::codes::INVARIANT)?;

        // Pick a responder session ID that avoids collision.
        let rsp_id = self.alloc_rsp_session_id(req_session_id)?;
        let session_id = ((rsp_id as u32) << 16) | (req_session_id as u32);

        self.sessions[slot] = Some(SessionInfo {
            session_id,
            state: SessionState::HandshakeInProgress,
            key_schedule: KeySchedule::new(spdm_version_str(version)),
            transcript: SessionTranscript::new(),
        });

        Ok(session_id)
    }

    /// Look up a session by combined ID.
    pub fn find(&self, session_id: u32) -> Option<&SessionInfo<K, S>> {
        self.sessions
            .iter()
            .flatten()
            .find(|s| s.session_id == session_id)
    }

    /// Look up a session by combined ID (mutable).
    pub fn find_mut(&mut self, session_id: u32) -> Option<&mut SessionInfo<K, S>> {
        self.sessions
            .iter_mut()
            .flatten()
            .find(|s| s.session_id == session_id)
    }

    /// Remove a session and destroy all its key handles.
    pub async fn remove_and_destroy<P>(
        &mut self,
        pal: &P,
        io: &impl SpdmPalIo,
        session_id: u32,
    ) where
        P: SpdmPalSessionCrypto<Key = K>,
    {
        for slot in self.sessions.iter_mut() {
            if slot.as_ref().map_or(false, |s| s.session_id == session_id) {
                if let Some(info) = slot.as_mut() {
                    info.key_schedule.destroy_all(pal, io).await;
                }
                *slot = None;
                return;
            }
        }
    }

    /// Remove all sessions and destroy all key handles.
    pub async fn remove_all_and_destroy<P>(
        &mut self,
        pal: &P,
        io: &impl SpdmPalIo,
    ) where
        P: SpdmPalSessionCrypto<Key = K>,
    {
        for slot in self.sessions.iter_mut() {
            if let Some(info) = slot.as_mut() {
                info.key_schedule.destroy_all(pal, io).await;
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
        Err(mcu_error::codes::INVARIANT)
    }
}
