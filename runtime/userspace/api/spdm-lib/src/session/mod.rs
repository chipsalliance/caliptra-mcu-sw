// Licensed under the Apache-2.0 license

//! Session management module for SPDM protocol

use libapi_caliptra::error::CaliptraApiError;

pub mod info;
pub mod key_schedule;

// Re-export main types
pub(crate) use info::{SessionInfo, SessionPolicy, SessionState, SessionType};
pub(crate) use key_schedule::{KeySchedule, KeyScheduleError, SessionKeyType};

pub const MAX_NUM_SESSIONS: usize = 1;

#[derive(Debug, PartialEq)]
pub enum SessionError {
    SessionsLimitReached,
    InvalidSessionId,
    DheSecretNotFound,
    HandshakeSecretNotFound,
    BufferTooSmall,
    KeySchedule(KeyScheduleError),
    CaliptraApi(CaliptraApiError),
}

pub type SessionResult<T> = Result<T, SessionError>;

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

    pub fn set_active_session_id(&mut self, session_id: u32) {
        self.active_session_id = Some(session_id);
    }

    pub fn reset_active_session_id(&mut self) {
        self.active_session_id = None;
    }

    pub fn active_session_id(&self) -> Option<u32> {
        self.active_session_id
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
