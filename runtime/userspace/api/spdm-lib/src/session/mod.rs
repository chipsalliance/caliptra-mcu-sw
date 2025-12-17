// Licensed under the Apache-2.0 license

//! Session management module for SPDM protocol

use crate::codec::{encode_u8_slice, Codec, CodecError, MessageBuf};
use crate::context::MAX_SPDM_RESPONDER_BUF_SIZE;
use crate::transport::common::SpdmTransport;
use core::mem::size_of;
use libapi_caliptra::crypto::aes_gcm::Aes256GcmTag;
use libapi_caliptra::error::CaliptraApiError;

use zerocopy::{FromBytes, IntoBytes};

pub mod info;
pub mod key_schedule;

// Re-export main types
pub(crate) use info::{SessionInfo, SessionPolicy, SessionState, SessionType};
pub(crate) use key_schedule::{KeySchedule, KeyScheduleError, SessionKeyType};

pub const MAX_NUM_SESSIONS: usize = 1;
const MAX_SPDM_AEAD_ASSOCIATED_DATA_SIZE: usize = 16; // Size of the associated data for AEAD

#[derive(Debug, PartialEq)]
pub enum SessionError {
    SessionsLimitReached,
    InvalidSessionId,
    InvalidState,
    DheSecretNotFound,
    HandshakeSecretNotFound,
    BufferTooSmall,
    EncodeAeadError,
    DecodeAeadError,
    KeySchedule(KeyScheduleError),
    CaliptraApi(CaliptraApiError),
    Codec(CodecError),
}

pub type SessionResult<T> = Result<T, SessionError>;

#[derive(Default)]
pub(crate) struct SessionManager {
    active_session_id: Option<u32>,
    handshake_phase_session_id: Option<u32>,
    sessions: [Option<SessionInfo>; MAX_NUM_SESSIONS],
    cur_responder_session_id: u16,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            active_session_id: None,
            handshake_phase_session_id: None,
            sessions: [None; MAX_NUM_SESSIONS],
            cur_responder_session_id: 0,
        }
    }

    pub fn reset(&mut self) {
        self.active_session_id = None;
        self.handshake_phase_session_id = None;
        self.sessions = [None; MAX_NUM_SESSIONS];
        self.cur_responder_session_id = 0;
    }

    pub fn generate_session_id(&mut self, requester_session_id: u16) -> (u32, u16) {
        let rsp_session_id = self.cur_responder_session_id;
        let session_id = (u32::from(rsp_session_id) << 16) | u32::from(requester_session_id);
        self.cur_responder_session_id = self.cur_responder_session_id.wrapping_add(1);
        (session_id, rsp_session_id)
    }

    pub fn set_active_session_id(&mut self, session_id: u32) {
        self.active_session_id = Some(session_id);
    }

    pub fn reset_active_session_id(&mut self) {
        self.active_session_id = None;
    }

    pub fn active_session_id(&self) -> Option<u32> {
        self.active_session_id
    }

    pub fn handshake_phase_session_id(&self) -> Option<u32> {
        self.handshake_phase_session_id
    }

    pub fn set_handshake_phase_session_id(&mut self, session_id: u32) {
        self.handshake_phase_session_id = Some(session_id);
    }

    pub fn reset_handshake_phase_session_id(&mut self) {
        self.handshake_phase_session_id = None;
    }

    pub fn create_session(&mut self, session_id: u32) -> SessionResult<()> {
        for i in 0..MAX_NUM_SESSIONS {
            if self.sessions[i].is_none() {
                let session_info = SessionInfo::new(session_id);
                self.sessions[i] = Some(session_info);
                return Ok(());
            }
        }
        Err(SessionError::SessionsLimitReached)
    }

    pub fn set_session_state(&mut self, session_id: u32, state: SessionState) -> SessionResult<()> {
        let session_info = self
            .sessions
            .iter_mut()
            .find_map(|s| s.as_mut().filter(|info| info.session_id == session_id))
            .ok_or(SessionError::InvalidSessionId)?;

        session_info.set_session_state(state);
        Ok(())
    }

    pub fn delete_session(&mut self, session_id: u32) -> SessionResult<()> {
        let session_index = self
            .sessions
            .iter()
            .position(|s| {
                s.as_ref()
                    .map(|info| info.session_id == session_id)
                    .unwrap_or(false)
            })
            .ok_or(SessionError::InvalidSessionId)?;

        self.sessions[session_index] = None;
        if self.active_session_id == Some(session_id) {
            self.reset_active_session_id();
        }
        if self.handshake_phase_session_id == Some(session_id) {
            self.reset_handshake_phase_session_id();
        }
        Ok(())
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

    pub async fn encode_secure_message(
        &mut self,
        transport: &dyn SpdmTransport,
        app_data_buffer: &[u8],
        secure_message: &mut MessageBuf<'_>,
    ) -> SessionResult<()> {
        let session_id = self
            .active_session_id
            .ok_or(SessionError::InvalidSessionId)?;

        let session_info = self.session_info_mut(session_id)?;

        let mut aead_data = [0u8; MAX_SPDM_AEAD_ASSOCIATED_DATA_SIZE];
        let mut aead_buf = MessageBuf::new(&mut aead_data);
        let mut aead_len = session_id
            .encode(&mut aead_buf)
            .map_err(SessionError::Codec)?;

        if transport.sequence_num_size_bytes() > 0 {
            todo!("Handle sequence number if exists and process");
        }

        let mut encrypted_data = [0u8; MAX_SPDM_RESPONDER_BUF_SIZE];
        let mut plaintext_data = [0u8; MAX_SPDM_RESPONDER_BUF_SIZE];
        // copy app_data_length + app_data + random data to encrypt using aead.
        let app_data_len = app_data_buffer.len() as u16;
        plaintext_data[..2].copy_from_slice(&app_data_len.to_le_bytes());
        plaintext_data[2..2 + app_data_buffer.len()].copy_from_slice(app_data_buffer);
        let encrypted_len = 2 + app_data_buffer.len();
        if transport.random_data_size_bytes() > 0 {
            todo!("Handle random data bytes");
        }

        let tag_length = size_of::<Aes256GcmTag>();
        let length: u16 = encrypted_len as u16 + tag_length as u16;
        aead_len += length.encode(&mut aead_buf).map_err(SessionError::Codec)?;
        let associated_data = aead_buf
            .message_slice(aead_len)
            .map_err(SessionError::Codec)?;

        let (encrypted_size, tag) = session_info
            .encrypt_secure_message(
                associated_data,
                &plaintext_data[..encrypted_len],
                &mut encrypted_data,
            )
            .await?;

        let mut secure_message_len = session_id
            .encode(secure_message)
            .map_err(SessionError::Codec)?;

        if transport.sequence_num_size_bytes() > 0 {
            todo!("Handle sequence number if exists and process");
        }
        secure_message_len += length.encode(secure_message).map_err(SessionError::Codec)?;

        secure_message_len += encode_u8_slice(&encrypted_data[..encrypted_size], secure_message)
            .map_err(SessionError::Codec)?;

        secure_message_len +=
            encode_u8_slice(tag.as_bytes(), secure_message).map_err(SessionError::Codec)?;

        if session_info.session_state == SessionState::Establishing {
            // If this is the response message for the FINISH request, set the session state to Established.
            session_info.set_session_state(SessionState::Established);
        }

        // If this is response message for END_SESSION request, clear the session.
        if session_info.session_state == SessionState::Terminating {
            self.delete_session(session_id)?;
            self.reset_active_session_id();
        }

        secure_message
            .push_data(secure_message_len)
            .map_err(SessionError::Codec)?;
        Ok(())
    }

    pub async fn decode_secure_message(
        &mut self,
        transport: &dyn SpdmTransport,
        secure_message: &mut MessageBuf<'_>,
        app_data_buffer: &mut [u8],
    ) -> SessionResult<usize> {
        let mut aead_data = [0u8; MAX_SPDM_AEAD_ASSOCIATED_DATA_SIZE];
        let mut aead_buf = MessageBuf::new(&mut aead_data);
        let mut plaintext_buffer = [0u8; MAX_SPDM_RESPONDER_BUF_SIZE];
        // Decode u32 session id first
        let session_id = u32::decode(secure_message).map_err(SessionError::Codec)?;

        let session_info = self.session_info_mut(session_id)?;

        let mut aead_len = session_id
            .encode(&mut aead_buf)
            .map_err(SessionError::Codec)?;

        if transport.sequence_num_size_bytes() > 0 {
            // Decode sequence number if exists and process
            todo!("Decode sequence number if exists and process");
        }

        let length = u16::decode(secure_message).map_err(SessionError::Codec)?;
        if length as usize > app_data_buffer.len() {
            return Err(SessionError::BufferTooSmall);
        }
        // prepare associated data
        aead_len += length.encode(&mut aead_buf).map_err(SessionError::Codec)?;
        let associated_data = aead_buf
            .message_slice(aead_len)
            .map_err(SessionError::Codec)?;

        // Secure message payload length may be bigger than the length field for alignment purposes
        if secure_message.msg_len() < length as usize {
            return Err(SessionError::DecodeAeadError);
        }

        let secure_msg_payload = secure_message
            .data_mut(length as usize)
            .map_err(SessionError::Codec)?;
        let tag_len = size_of::<Aes256GcmTag>();
        let encrypted_data_len = length as usize - tag_len;

        let encrypted_data = &secure_msg_payload[..encrypted_data_len];
        let tag_slice = &secure_msg_payload[encrypted_data_len..encrypted_data_len + tag_len];
        let tag: Aes256GcmTag = <Aes256GcmTag>::read_from_bytes(tag_slice)
            .map_err(|_| SessionError::DecodeAeadError)?;

        let decrypted_size = session_info
            .decrypt_secure_message(associated_data, encrypted_data, &mut plaintext_buffer, tag)
            .await?;

        let mut plaintext_msg = MessageBuf::from(&mut plaintext_buffer[..decrypted_size]);

        let app_data_len = u16::decode(&mut plaintext_msg).map_err(SessionError::Codec)? as usize;
        let app_data = plaintext_msg
            .data(app_data_len)
            .map_err(SessionError::Codec)?;

        self.set_active_session_id(session_id);
        app_data_buffer[..app_data_len].copy_from_slice(app_data);
        Ok(app_data_len)
    }
}
