// Licensed under the Apache-2.0 license

use crate::transcript::SessionTranscript;
use bitfield::bitfield;
use caliptra_api::mailbox::Cmk;
use libapi_caliptra::crypto::asym::ecdh::{CmKeyUsage, Ecdh, CMB_ECDH_EXCHANGE_DATA_MAX_SIZE};
use libapi_caliptra::error::CaliptraApiError;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const MAX_NUM_SESSIONS: usize = 1;

#[derive(Debug, PartialEq)]
pub enum SessionError {
    SessionsLimitReached,
    InvalidSessionId,
    SecretNotFound,
    CaliptraApi(CaliptraApiError),
}

pub(crate) type SessionResult<T> = Result<T, SessionError>;

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable, Clone, Copy, Default)]
    #[repr(C)]
    pub struct SessionPolicy(u8);
    impl Debug;
    u8;
    pub termination_policy, _: 0, 0;
    pub event_all_policy, _: 1, 1;
    reserved, _: 7, 2;
}

#[derive(Default)]
pub(crate) struct SessionManager {
    active_session_id: Option<u32>,
    sessions: [Option<SessionInfo>; MAX_NUM_SESSIONS],
    cur_responder_session_id: u16,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            active_session_id: None,
            sessions: [None; MAX_NUM_SESSIONS],
            cur_responder_session_id: 0,
        }
    }

    pub fn generate_session_id(&mut self, requester_session_id: u16) -> (u32, u16) {
        let rsp_session_id = self.cur_responder_session_id;
        let session_id = u32::from(rsp_session_id) << 16 | u32::from(requester_session_id);
        self.cur_responder_session_id = self.cur_responder_session_id.wrapping_add(1);
        (session_id, rsp_session_id)
    }

    pub fn session_active(&self) -> bool {
        self.active_session_id.is_some()
    }

    #[allow(dead_code)]
    pub fn set_active_session_id(&mut self, session_id: u32) {
        self.active_session_id = Some(session_id);
    }

    pub fn reset_active_session_id(&mut self) {
        self.active_session_id = None;
    }

    pub fn create_session(
        &mut self,
        session_id: u32,
        session_policy: SessionPolicy,
    ) -> SessionResult<()> {
        for i in 0..MAX_NUM_SESSIONS {
            if self.sessions[i].is_none() {
                let mut session_info = SessionInfo::new(session_id);
                session_info.set_session_policy(session_policy);
                self.sessions[i] = Some(session_info);
                return Ok(());
            }
        }
        Err(SessionError::SessionsLimitReached)
    }

    #[allow(dead_code)]
    pub fn delete_session(&mut self, _session_id: u32) -> Option<usize> {
        todo!("Delete Session");
    }

    #[allow(dead_code)]
    pub fn session_info(&self, session_id: u32) -> SessionResult<&SessionInfo> {
        self.sessions
            .iter()
            .find_map(|s| s.as_ref().filter(|info| info.session_id == session_id))
            .ok_or(SessionError::InvalidSessionId)
    }

    pub fn session_info_mut(&mut self, session_id: u32) -> SessionResult<&mut SessionInfo> {
        self.sessions
            .iter_mut()
            .find_map(|s| s.as_mut().filter(|info| info.session_id == session_id))
            .ok_or(SessionError::InvalidSessionId)
    }
}

#[allow(dead_code)]
pub(crate) enum SessionState {
    HandshakeNotStarted, // Before KEY_EXCHANGE and after END_SESSION
    HandshakeInProgress, // After KEY_EXCHANGE and before FINISH
    SessionEstablished,  // After FINISH
}

#[allow(dead_code)]
pub(crate) struct SessionInfo {
    session_id: u32,
    session_policy: SessionPolicy,
    session_state: SessionState,
    session_context: SessionContext,
    pub(crate) session_transcript: SessionTranscript,
}

impl SessionInfo {
    pub fn new(session_id: u32) -> Self {
        Self {
            session_id,
            session_policy: SessionPolicy::default(),
            session_state: SessionState::HandshakeNotStarted,
            session_context: SessionContext::default(),
            session_transcript: SessionTranscript::new(),
        }
    }

    pub fn set_session_policy(&mut self, policy: SessionPolicy) {
        self.session_policy = policy;
    }

    /// Computes the DHE secret using ECDH key exchange
    ///
    /// # Arguments
    /// `peer_exch_data` is the exchange data received from the peer.
    ///
    /// # Returns
    /// Self exchange data to be sent to peer.
    pub async fn compute_dhe_secret(
        &mut self,
        peer_exch_data: &[u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
    ) -> SessionResult<[u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE]> {
        let mut self_exch_data = [0u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE];

        // Generate an ephemeral key pair
        let generate_resp = Ecdh::ecdh_generate()
            .await
            .map_err(SessionError::CaliptraApi)?;

        self_exch_data.copy_from_slice(&generate_resp.exchange_data);

        // Finish the ECDH key exchange to generate the shared secret
        let shared_secret = Ecdh::ecdh_finish(CmKeyUsage::Hmac, &generate_resp, peer_exch_data)
            .await
            .map_err(SessionError::CaliptraApi)?;

        // Store the shared secret in the session context
        self.session_context.master_secret_info.dhe_secret = Some(shared_secret);

        Ok(self_exch_data)
    }
}

#[derive(Default)]
struct SessionContext {
    // Placeholder for session-specific data
    master_secret_info: MasterSecretInfo,
}

#[derive(Default)]
struct MasterSecretInfo {
    // DHE secret
    dhe_secret: Option<Cmk>,
    // TODO: Handshake secret
    // TODO: Master secret
}
