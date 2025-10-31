//! Caliptra Core Library
//!
//! Core execution layer with session management and command processing

#![no_std]

use caliptra_command_types::{CommandRequest, CommandResult, CommandError};
use caliptra_session::{CaliptraSession, SessionError, SessionResult};
use caliptra_transport::Transport;

pub mod executor;

pub use executor::*;
pub use caliptra_session::{SessionConfig, SessionState, SessionStatistics, SessionInfo, SessionProperty, SessionManager};

// Helper functions for the API layer

/// Execute a command through a session (helper function for API layer)
pub fn execute_command_with_session<T: Transport, Req: CommandRequest>(
    session: &mut CaliptraSession<T>,
    request: &Req,
) -> CommandResult<Req::Response> {
    caliptra_core_execute_command(session, request)
}

/// Core execution function for Caliptra commands
/// 
/// This is the main entry point that all high-level APIs should call.
/// Takes a command request struct and returns the corresponding response.
pub fn caliptra_core_execute_command<T: Transport, Req: CommandRequest>(
    session: &mut CaliptraSession<T>,
    request: &Req,
) -> CommandResult<Req::Response> {
    let mut executor = crate::executor::CommandExecutor::new(session)
        .map_err(|_e| CommandError::Custom("Failed to create executor"))?;
    executor.execute_command(request)
}

/// Core result type (alias for SessionResult)
pub type CoreResult<T> = SessionResult<T>;
pub type CoreError = SessionError;