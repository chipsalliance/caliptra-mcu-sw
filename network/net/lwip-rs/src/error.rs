// Licensed under the Apache-2.0 license

//! Error types for lwip-rs

use core::fmt;

/// lwIP error type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i8)]
pub enum LwipError {
    /// No error, everything OK
    Ok = 0,
    /// Out of memory error
    OutOfMemory = -1,
    /// Buffer error
    Buffer = -2,
    /// Timeout
    Timeout = -3,
    /// Routing problem
    Routing = -4,
    /// Operation in progress
    InProgress = -5,
    /// Illegal value
    IllegalValue = -6,
    /// Operation would block
    WouldBlock = -7,
    /// Address in use
    AddressInUse = -8,
    /// Already connecting
    AlreadyConnecting = -9,
    /// Connection already established
    AlreadyConnected = -10,
    /// Not connected
    NotConnected = -11,
    /// Low-level netif error
    Interface = -12,
    /// Connection aborted
    Aborted = -13,
    /// Connection reset
    Reset = -14,
    /// Connection closed
    Closed = -15,
    /// Illegal argument
    IllegalArgument = -16,
    /// Unknown error
    Unknown = -127,
}

impl LwipError {
    /// Convert from raw error code
    pub fn from_raw(err: i8) -> Self {
        match err {
            0 => LwipError::Ok,
            -1 => LwipError::OutOfMemory,
            -2 => LwipError::Buffer,
            -3 => LwipError::Timeout,
            -4 => LwipError::Routing,
            -5 => LwipError::InProgress,
            -6 => LwipError::IllegalValue,
            -7 => LwipError::WouldBlock,
            -8 => LwipError::AddressInUse,
            -9 => LwipError::AlreadyConnecting,
            -10 => LwipError::AlreadyConnected,
            -11 => LwipError::NotConnected,
            -12 => LwipError::Interface,
            -13 => LwipError::Aborted,
            -14 => LwipError::Reset,
            -15 => LwipError::Closed,
            -16 => LwipError::IllegalArgument,
            _ => LwipError::Unknown,
        }
    }

    /// Check if this is an error
    pub fn is_err(&self) -> bool {
        *self != LwipError::Ok
    }

    /// Check if this is ok
    pub fn is_ok(&self) -> bool {
        *self == LwipError::Ok
    }
}

impl fmt::Display for LwipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LwipError::Ok => write!(f, "OK"),
            LwipError::OutOfMemory => write!(f, "Out of memory"),
            LwipError::Buffer => write!(f, "Buffer error"),
            LwipError::Timeout => write!(f, "Timeout"),
            LwipError::Routing => write!(f, "Routing problem"),
            LwipError::InProgress => write!(f, "Operation in progress"),
            LwipError::IllegalValue => write!(f, "Illegal value"),
            LwipError::WouldBlock => write!(f, "Would block"),
            LwipError::AddressInUse => write!(f, "Address in use"),
            LwipError::AlreadyConnecting => write!(f, "Already connecting"),
            LwipError::AlreadyConnected => write!(f, "Already connected"),
            LwipError::NotConnected => write!(f, "Not connected"),
            LwipError::Interface => write!(f, "Interface error"),
            LwipError::Aborted => write!(f, "Connection aborted"),
            LwipError::Reset => write!(f, "Connection reset"),
            LwipError::Closed => write!(f, "Connection closed"),
            LwipError::IllegalArgument => write!(f, "Illegal argument"),
            LwipError::Unknown => write!(f, "Unknown error"),
        }
    }
}

/// Result type for lwIP operations
pub type Result<T> = core::result::Result<T, LwipError>;

/// Convert raw error to Result
pub fn check_err(err: i8) -> Result<()> {
    let e = LwipError::from_raw(err);
    if e.is_ok() {
        Ok(())
    } else {
        Err(e)
    }
}
