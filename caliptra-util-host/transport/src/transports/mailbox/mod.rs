// Licensed under the Apache-2.0 license

//! Mailbox Transport Module
//!
//! This module provides mailbox transport implementation with external mailbox protocol support.

pub mod checksum;
pub mod command_traits;
pub mod transport;

// Device Info Commands
pub mod device_info;

// Re-export main types
pub use transport::{Mailbox, MailboxDriver, MailboxError};

// Re-export command traits and utilities for use by other command modules
pub use command_traits::{
    process_command, process_command_with_metadata, ExternalCommandHandler,
    ExternalCommandMetadata, FromInternalRequest, ToInternalResponse, VariableSizeBytes,
};

// Re-export external command types for testing
pub use device_info::*;
