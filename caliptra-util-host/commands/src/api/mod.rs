// Licensed under the Apache-2.0 license

//! High-level API functions for Caliptra commands
//!
//! This module provides transport-agnostic, easy-to-use functions for interacting
//! with Caliptra devices. These functions handle session management, error handling,
//! and provide a clean interface for applications.

// Re-export types that API consumers might need
// Note: These imports might appear unused but are used by other modules or re-exports

pub mod device_info;

pub use caliptra_util_host_session::CommandSession;
pub use device_info::*;

/// High-level result type for API functions
pub type CaliptraResult<T> = Result<T, CaliptraApiError>;

/// API-specific error types
#[derive(Debug, Clone, PartialEq)]
pub enum CaliptraApiError {
    /// OSAL error
    Osal(caliptra_util_host_osal::OsalError),
    /// Invalid parameter
    InvalidParameter(&'static str),
    /// Session not initialized
    SessionNotInitialized,
    /// Transport not available
    TransportNotAvailable,
    /// Command execution failed
    CommandFailed(&'static str),
    /// Session error (generic session layer error)
    SessionError(&'static str),
}

impl From<caliptra_util_host_osal::OsalError> for CaliptraApiError {
    fn from(err: caliptra_util_host_osal::OsalError) -> Self {
        CaliptraApiError::Osal(err)
    }
}

impl From<caliptra_util_host_command_types::CommandError> for CaliptraApiError {
    fn from(_err: caliptra_util_host_command_types::CommandError) -> Self {
        CaliptraApiError::CommandFailed("Command execution failed")
    }
}

impl From<&'static str> for CaliptraApiError {
    fn from(msg: &'static str) -> Self {
        CaliptraApiError::SessionError(msg)
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
            CaliptraApiError::SessionError(msg) => write!(f, "Session error: {}", msg),
        }
    }
}
