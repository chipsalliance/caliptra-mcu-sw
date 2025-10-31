//! High-level API functions for Caliptra commands
//! 
//! This module provides transport-agnostic, easy-to-use functions for interacting
//! with Caliptra devices. These functions handle session management, error handling,
//! and provide a clean interface for applications.

use caliptra_command_types::{CaliptraCommandId, CommandRequest, CommandResponse, CommandError};

pub mod device_info;

pub use device_info::*;

/// High-level result type for API functions
pub type CaliptraResult<T> = Result<T, CaliptraApiError>;

/// API-specific error types
#[derive(Debug, Clone, PartialEq)]
pub enum CaliptraApiError {
    /// OSAL error
    Osal(caliptra_osal::OsalError),
    /// Invalid parameter
    InvalidParameter(&'static str),
    /// Session not initialized
    SessionNotInitialized,
    /// Transport not available
    TransportNotAvailable,
    /// Command execution failed
    CommandFailed(&'static str),
}

impl From<caliptra_osal::OsalError> for CaliptraApiError {
    fn from(err: caliptra_osal::OsalError) -> Self {
        CaliptraApiError::Osal(err)
    }
}

impl From<caliptra_command_types::CommandError> for CaliptraApiError {
    fn from(_err: caliptra_command_types::CommandError) -> Self {
        CaliptraApiError::CommandFailed("Command execution failed")
    }
}

impl core::fmt::Display for CaliptraApiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CaliptraApiError::Osal(err) => write!(f, "OSAL error: {}", err),
            CaliptraApiError::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            CaliptraApiError::SessionNotInitialized => write!(f, "Session not initialized"),
            CaliptraApiError::TransportNotAvailable => write!(f, "Transport not available"),
            CaliptraApiError::CommandFailed(msg) => write!(f, "Command failed: {}", msg),
        }
    }
}

/// Trait for command execution that can be implemented by session types
pub trait CommandSession {
    type Error;
    
    /// Execute a command with the given request and return the response
    fn execute_command<Req: CommandRequest, Resp: CommandResponse>(
        &self,
        command_id: CaliptraCommandId,
        request: &Req,
    ) -> Result<Resp, Self::Error>;
}