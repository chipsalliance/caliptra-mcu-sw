// Licensed under the Apache-2.0 license

//! Error handling for Caliptra C bindings
//!
//! This module provides error types that align with the documented API design.

/// C-compatible error type that can be exported
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CaliptraError {
    Success = 0,
    Unknown = 1,
    InvalidArgument = 2,
    Timeout = 3,
    NotSupported = 4,
    Transport = 5,
    Protocol = 6,
    Device = 7,
    Memory = 8,
    Busy = 9,
    State = 10,
    IO = 11,
}

/// Error context for detailed error information
/// This matches the design document error context structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CaliptraErrorContext {
    pub error_code: CaliptraError,
    pub location: ErrorLocation,
    pub additional_info: u32,
    pub timestamp: u64, // Implementation-specific timestamp
}

/// Error location information (from design document)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ErrorLocation {
    Unknown = 0,
    Transport = 1,
    Session = 2,
    Command = 3,
    Protocol = 4,
    Device = 5,
}
