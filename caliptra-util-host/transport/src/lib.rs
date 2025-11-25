// Licensed under the Apache-2.0 license

//! Caliptra Transport Layer
//!
//! Transport abstraction for Caliptra device communication

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

// Alloc imports added as needed by specific modules

pub mod error;
pub mod transports;

// Re-export commonly used types
pub use error::{TransportError, TransportResult};

// Re-export mailbox types specifically
pub use transports::mailbox::{Mailbox, MailboxDriver, MailboxError};

/// Transport configuration
#[derive(Debug, Clone, Default)]
pub struct TransportConfig {
    pub max_message_size: usize,
    pub timeout_ms: u32,
}

impl TransportConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    pub fn with_timeout(mut self, timeout_ms: u32) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }
}

/// Transport trait for device communication
pub trait Transport: Send + Sync {
    fn connect(&mut self) -> TransportResult<()>;
    fn disconnect(&mut self) -> TransportResult<()>;
    fn send(&mut self, command_id: u32, data: &[u8]) -> TransportResult<()>;
    fn receive(&mut self, buffer: &mut [u8]) -> TransportResult<usize>;
    fn is_connected(&self) -> bool;
}
