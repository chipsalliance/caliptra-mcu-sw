// Licensed under the Apache-2.0 license

//! Command Error Types
//!
//! Error definitions for command processing

/// Command processing errors
#[derive(Debug, Clone, PartialEq)]
pub enum CommandError {
    /// Invalid command ID
    InvalidCommand,

    /// Invalid request data
    InvalidRequest,

    /// Invalid response data
    InvalidResponse,

    /// Response data too short
    InvalidResponseLength,

    /// Response data too long  
    ResponseTooLong,

    /// Serialization error
    SerializationError,

    /// Deserialization error
    DeserializationError,

    /// Checksum mismatch
    ChecksumMismatch,

    /// Command not supported
    Unsupported,

    /// Buffer too small for operation
    BufferTooSmall,

    /// Custom error message (static string only)
    Custom(&'static str),
}

impl core::fmt::Display for CommandError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CommandError::InvalidCommand => write!(f, "Invalid command"),
            CommandError::InvalidRequest => write!(f, "Invalid request"),
            CommandError::InvalidResponse => write!(f, "Invalid response"),
            CommandError::InvalidResponseLength => write!(f, "Invalid response length"),
            CommandError::ResponseTooLong => write!(f, "Response too long"),
            CommandError::SerializationError => write!(f, "Serialization error"),
            CommandError::DeserializationError => write!(f, "Deserialization error"),
            CommandError::ChecksumMismatch => write!(f, "Checksum mismatch"),
            CommandError::Unsupported => write!(f, "Command not supported"),
            CommandError::BufferTooSmall => write!(f, "Buffer too small"),
            CommandError::Custom(msg) => write!(f, "Command error: {}", msg),
        }
    }
}

/// Result type for command operations
pub type CommandResult<T> = Result<T, CommandError>;
