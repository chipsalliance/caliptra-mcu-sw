// Licensed under the Apache-2.0 license

//! Error types for OSAL
use core::fmt;

pub type OsalResult<T> = Result<T, OsalError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsalError {
    /// Memory allocation failed
    OutOfMemory,
    /// Invalid parameter
    InvalidParameter,
    /// Resource not available
    ResourceUnavailable,
    /// Operation timeout
    Timeout,
    /// Permission denied
    PermissionDenied,
    /// Resource already exists
    AlreadyExists,
    /// Resource not found
    NotFound,
    /// Operation would block
    WouldBlock,
    /// Interrupted system call
    Interrupted,
    /// IO error
    Io(IoErrorKind),
    /// Platform-specific error
    Platform(i32),
    /// Other error
    Other(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoErrorKind {
    NotFound,
    PermissionDenied,
    ConnectionRefused,
    ConnectionReset,
    ConnectionAborted,
    NotConnected,
    AddrInUse,
    AddrNotAvailable,
    BrokenPipe,
    AlreadyExists,
    WouldBlock,
    InvalidInput,
    InvalidData,
    TimedOut,
    WriteZero,
    Interrupted,
    UnexpectedEof,
    Other,
}

impl fmt::Display for OsalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OsalError::OutOfMemory => write!(f, "Out of memory"),
            OsalError::InvalidParameter => write!(f, "Invalid parameter"),
            OsalError::ResourceUnavailable => write!(f, "Resource unavailable"),
            OsalError::Timeout => write!(f, "Operation timeout"),
            OsalError::PermissionDenied => write!(f, "Permission denied"),
            OsalError::AlreadyExists => write!(f, "Resource already exists"),
            OsalError::NotFound => write!(f, "Resource not found"),
            OsalError::WouldBlock => write!(f, "Operation would block"),
            OsalError::Interrupted => write!(f, "Operation interrupted"),
            OsalError::Io(kind) => write!(f, "IO error: {:?}", kind),
            OsalError::Platform(code) => write!(f, "Platform error: {}", code),
            OsalError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OsalError {}

#[cfg(feature = "std")]
impl From<std::io::Error> for OsalError {
    fn from(err: std::io::Error) -> Self {
        let kind = match err.kind() {
            std::io::ErrorKind::NotFound => IoErrorKind::NotFound,
            std::io::ErrorKind::PermissionDenied => IoErrorKind::PermissionDenied,
            std::io::ErrorKind::ConnectionRefused => IoErrorKind::ConnectionRefused,
            std::io::ErrorKind::ConnectionReset => IoErrorKind::ConnectionReset,
            std::io::ErrorKind::ConnectionAborted => IoErrorKind::ConnectionAborted,
            std::io::ErrorKind::NotConnected => IoErrorKind::NotConnected,
            std::io::ErrorKind::AddrInUse => IoErrorKind::AddrInUse,
            std::io::ErrorKind::AddrNotAvailable => IoErrorKind::AddrNotAvailable,
            std::io::ErrorKind::BrokenPipe => IoErrorKind::BrokenPipe,
            std::io::ErrorKind::AlreadyExists => IoErrorKind::AlreadyExists,
            std::io::ErrorKind::WouldBlock => IoErrorKind::WouldBlock,
            std::io::ErrorKind::InvalidInput => IoErrorKind::InvalidInput,
            std::io::ErrorKind::InvalidData => IoErrorKind::InvalidData,
            std::io::ErrorKind::TimedOut => IoErrorKind::TimedOut,
            std::io::ErrorKind::WriteZero => IoErrorKind::WriteZero,
            std::io::ErrorKind::Interrupted => IoErrorKind::Interrupted,
            std::io::ErrorKind::UnexpectedEof => IoErrorKind::UnexpectedEof,
            _ => IoErrorKind::Other,
        };
        OsalError::Io(kind)
    }
}
