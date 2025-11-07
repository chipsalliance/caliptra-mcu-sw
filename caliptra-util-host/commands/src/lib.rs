// Licensed under the Apache-2.0 license

//! Caliptra Commands Layer
//!
//! Command packing and zerocopy operations layer

#![no_std]

// Re-export command types for convenience
pub use caliptra_util_host_command_types::*;

pub mod api;
pub mod packing;

pub use packing::*;

/// Command execution result type alias
pub type CommandResult<T> = Result<T, CommandError>;
