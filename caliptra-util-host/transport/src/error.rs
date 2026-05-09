// Licensed under the Apache-2.0 license

//! Transport error types

use caliptra_util_host_osal::OsalError;
use core::fmt;

pub type TransportResult<T> = Result<T, TransportError>;

#[derive(Debug, Clone)]
pub enum TransportError {
    /// Connection failed
    ConnectionFailed(Option<&'static str>),

    /// Send operation failed
    SendFailed(Option<&'static str>),

    /// Receive operation failed
    ReceiveFailed(Option<&'static str>),

    /// Operation timeout
    Timeout,

    /// Transport not supported
    NotSupported(&'static str),

    /// Invalid message format
    InvalidMessage,

    /// Transport disconnected
    Disconnected,

    /// Configuration error
    ConfigurationError(&'static str),

    /// Transport not found
    TransportNotFound(&'static str),

    /// Connection error
    ConnectionError(&'static str),

    /// I/O operation failed
    IoError(&'static str),

    /// Buffer error
    BufferError(&'static str),

    /// Message too large
    MessageTooLarge(&'static str),

    /// Parse error
    ParseError(&'static str),

    /// Factory error
    FactoryError(&'static str),

    /// Plugin error
    PluginError(&'static str),

    /// OSAL error
    OsalError(OsalError),

    /// Custom transport error
    Custom(&'static str),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::ConnectionFailed(msg) => {
                write!(f, "Connection failed")?;
                if let Some(msg) = msg {
                    write!(f, ": {}", msg)?;
                }
                Ok(())
            }
            TransportError::SendFailed(msg) => {
                write!(f, "Send failed")?;
                if let Some(msg) = msg {
                    write!(f, ": {}", msg)?;
                }
                Ok(())
            }
            TransportError::ReceiveFailed(msg) => {
                write!(f, "Receive failed")?;
                if let Some(msg) = msg {
                    write!(f, ": {}", msg)?;
                }
                Ok(())
            }
            TransportError::Timeout => write!(f, "Operation timeout"),
            TransportError::NotSupported(msg) => write!(f, "Transport not supported: {}", msg),
            TransportError::InvalidMessage => write!(f, "Invalid message format"),
            TransportError::Disconnected => write!(f, "Transport disconnected"),
            TransportError::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
            TransportError::TransportNotFound(name) => write!(f, "Transport not found: {}", name),
            TransportError::FactoryError(msg) => write!(f, "Factory error: {}", msg),
            TransportError::OsalError(err) => write!(f, "OSAL error: {}", err),
            TransportError::ConnectionError(msg) => write!(f, "Connection error: {}", msg),
            TransportError::IoError(msg) => write!(f, "I/O error: {}", msg),
            TransportError::BufferError(msg) => write!(f, "Buffer error: {}", msg),
            TransportError::MessageTooLarge(msg) => write!(f, "Message too large: {}", msg),
            TransportError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            TransportError::PluginError(msg) => write!(f, "Plugin error: {}", msg),
            TransportError::Custom(msg) => write!(f, "Custom error: {}", msg),
        }
    }
}

// std::error::Error trait not available in no_std

impl From<OsalError> for TransportError {
    fn from(err: OsalError) -> Self {
        TransportError::OsalError(err)
    }
}
