// Licensed under the Apache-2.0 license

use super::{KeySchedule, SessionError, SessionKeyType, SessionResult};
use crate::protocol::SpdmVersion;
use crate::transcript::SessionTranscript;
use bitfield::bitfield;
use libapi_caliptra::crypto::aes_gcm::Aes256GcmTag;
use libapi_caliptra::crypto::asym::ecdh::CMB_ECDH_EXCHANGE_DATA_MAX_SIZE;
use libapi_caliptra::crypto::asym::AsymAlgo;
use libapi_caliptra::crypto::hash::SHA384_HASH_SIZE;
use zerocopy::{FromBytes, Immutable, IntoBytes};

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

#[derive(Debug, PartialEq, Clone, Copy)]
pub(crate) enum SessionState {
    HandshakeNotStarted, // Before KEY_EXCHANGE and after END_SESSION
    HandshakeInProgress, // After KEY_EXCHANGE and before FINISH
    Establishing,        // When FINISH is successfully processed
    Established,         // After FINISH
    Terminating,         // When END_SESSION is received
}

#[derive(Debug, PartialEq)]
pub enum SessionType {
    None,
    MacOnly,
    MacAndEncrypt,
}

#[allow(dead_code)]
pub(crate) struct SessionInfo {
    pub(crate) session_id: u32,
    pub(crate) session_policy: SessionPolicy,
    pub(crate) session_state: SessionState,
    pub(crate) session_type: SessionType,
    // spdm_version: SpdmVersion, // Negotiated SPDM version for this session
    pub(crate) asym_algo: AsymAlgo, // Asymmetric algorithm negotiated for this session
    key_schedule_ctx: KeySchedule,  // Key schedule context for this session
    pub(crate) session_transcript: SessionTranscript,
}

impl SessionInfo {
    pub fn new(session_id: u32) -> Self {
        Self {
            session_id,
            session_policy: SessionPolicy::default(),
            session_state: SessionState::HandshakeNotStarted,
            session_type: SessionType::None,
            asym_algo: AsymAlgo::EccP384, // Default to ECC P384
            key_schedule_ctx: KeySchedule::default(),
            session_transcript: SessionTranscript::new(),
        }
    }

    pub fn init(
        &mut self,
        session_policy: SessionPolicy,
        session_type: SessionType,
        spdm_version: SpdmVersion,
        asym_algo: AsymAlgo,
    ) {
        self.session_policy = session_policy;
        self.session_state = SessionState::HandshakeNotStarted;
        self.session_type = session_type;
        self.key_schedule_ctx.set_spdm_version(spdm_version);
        self.asym_algo = asym_algo;
    }

    /// Sets the session state
    ///
    /// # Arguments
    /// `state` is the new state to set.
    pub fn set_session_state(&mut self, state: SessionState) {
        self.session_state = state;
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
        self.key_schedule_ctx
            .compute_dhe_secret(peer_exch_data)
            .await
            .map_err(SessionError::KeySchedule)
    }

    pub async fn generate_session_handshake_key(
        &mut self,
        th1_transcript_hash: &[u8; SHA384_HASH_SIZE],
    ) -> SessionResult<()> {
        self.key_schedule_ctx
            .generate_session_handshake_key(th1_transcript_hash)
            .await
            .map_err(SessionError::KeySchedule)
    }

    pub async fn generate_session_data_key(
        &mut self,
        th2_transcript_hash: &[u8; SHA384_HASH_SIZE],
    ) -> SessionResult<()> {
        self.key_schedule_ctx
            .generate_session_data_key(th2_transcript_hash)
            .await
            .map_err(SessionError::KeySchedule)
    }

    pub async fn compute_hmac(
        &mut self,
        session_key_type: SessionKeyType,
        data: &[u8],
    ) -> SessionResult<[u8; SHA384_HASH_SIZE]> {
        self.key_schedule_ctx
            .hmac(session_key_type, data)
            .await
            .map_err(SessionError::KeySchedule)
    }

    pub async fn encrypt_secure_message(
        &mut self,
        aad_data: &[u8],
        plaintext_message: &[u8],
        encrypted_message: &mut [u8],
    ) -> SessionResult<(usize, Aes256GcmTag)> {
        let session_key_type = match self.session_state {
            SessionState::HandshakeNotStarted => return Err(SessionError::InvalidState),
            SessionState::HandshakeInProgress | SessionState::Establishing => {
                SessionKeyType::ResponseHandshakeEncDecKey
            }
            SessionState::Established | SessionState::Terminating => {
                SessionKeyType::ResponseDataEncDecKey
            }
        };

        self.key_schedule_ctx
            .encrypt_message(
                session_key_type,
                aad_data,
                plaintext_message,
                encrypted_message,
            )
            .await
            .map_err(SessionError::KeySchedule)
    }

    pub async fn decrypt_secure_message(
        &mut self,
        aad_data: &[u8],
        encrypted_message: &[u8],
        plaintext_message: &mut [u8],
        tag: Aes256GcmTag,
    ) -> SessionResult<usize> {
        let session_key_type = match self.session_state {
            SessionState::HandshakeNotStarted => return Err(SessionError::InvalidState),
            SessionState::HandshakeInProgress | SessionState::Establishing => {
                SessionKeyType::RequestHandshakeEncDecKey
            }
            SessionState::Established | SessionState::Terminating => {
                SessionKeyType::RequestDataEncDecKey
            }
        };

        self.key_schedule_ctx
            .decrypt_message(
                session_key_type,
                aad_data,
                encrypted_message,
                plaintext_message,
                tag,
            )
            .await
            .map_err(SessionError::KeySchedule)
    }
}
