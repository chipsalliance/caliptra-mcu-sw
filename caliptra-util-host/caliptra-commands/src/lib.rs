//! Caliptra Commands Layer
//!
//! Command packing and zerocopy operations layer

#![no_std]

// Re-export command types for convenience
pub use caliptra_command_types::*;

pub mod packing;
pub mod api;

pub use packing::*;

/// Command execution result type alias
pub type CommandResult<T> = Result<T, CommandError>;