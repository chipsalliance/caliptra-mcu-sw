// Licensed under the Apache-2.0 license

//! Mailbox Transport Implementation
//!
//! This module provides mailbox transport implementation with external mailbox protocol translation.

use super::dispatch::{get_command_handler, get_external_cmd_code};
use crate::{Transport, TransportError, TransportResult};

/// Maximum mailbox response buffer size in bytes.
pub const MAX_MBOX_RESP_BUF: usize = 8 * 1024;

/// Trait for hardware mailbox communication
pub trait MailboxDriver: Send + Sync {
    /// Send a command and return response data
    fn send_command(&mut self, external_cmd: u32, payload: &[u8]) -> Result<&[u8], MailboxError>;

    /// Check if mailbox is ready
    fn is_ready(&self) -> bool;

    /// Connect to mailbox
    fn connect(&mut self) -> Result<(), MailboxError>;

    /// Disconnect from mailbox
    fn disconnect(&mut self) -> Result<(), MailboxError>;
}

/// Mailbox error types
#[derive(Debug, Clone)]
pub enum MailboxError {
    NotReady,
    Timeout,
    InvalidCommand,
    CommunicationError,
    BufferOverflow,
    DeviceError(u32),
}

impl From<MailboxError> for TransportError {
    fn from(err: MailboxError) -> Self {
        match err {
            MailboxError::NotReady => TransportError::ConnectionFailed(Some("Mailbox not ready")),
            MailboxError::Timeout => TransportError::Timeout,
            MailboxError::InvalidCommand => TransportError::InvalidMessage,
            MailboxError::CommunicationError => {
                TransportError::ConnectionFailed(Some("Communication error"))
            }
            MailboxError::BufferOverflow => TransportError::BufferError("Buffer overflow"),
            MailboxError::DeviceError(_) => TransportError::ConnectionFailed(Some("Device error")),
        }
    }
}

/// Mailbox Transport using dynamic dispatch
pub struct Mailbox<'a> {
    mailbox: &'a mut dyn MailboxDriver,
    connected: bool,
    response_buffer: [u8; MAX_MBOX_RESP_BUF],
    response_len: usize,
    has_response: bool,
}

impl<'a> Mailbox<'a> {
    pub fn new(mailbox: &'a mut dyn MailboxDriver) -> Self {
        Self {
            mailbox,
            connected: false,
            response_buffer: [0; MAX_MBOX_RESP_BUF],
            response_len: 0,
            has_response: false,
        }
    }

    /// Process a command using static handler mapping
    fn process_command(&mut self, command_id: u32, payload: &[u8]) -> TransportResult<()> {
        // Look up command handler from static mapping
        if let Some(handler) = get_command_handler(command_id) {
            // Use the command-specific handler - mailbox is already &mut dyn MailboxDriver
            self.response_len = handler(payload, self.mailbox, &mut self.response_buffer)?;
            self.has_response = true;
            Ok(())
        } else {
            // Fallback: use the generic mapping and pass-through
            let external_cmd = get_external_cmd_code(command_id).ok_or(
                TransportError::NotSupported("Command not supported by mailbox transport"),
            )?;

            let response = self
                .mailbox
                .send_command(external_cmd, payload)
                .map_err(TransportError::from)?;

            // Store response in our buffer
            self.response_len = core::cmp::min(response.len(), self.response_buffer.len());
            self.response_buffer[..self.response_len]
                .copy_from_slice(&response[..self.response_len]);
            self.has_response = true;

            Ok(())
        }
    }
}

impl Transport for Mailbox<'_> {
    fn connect(&mut self) -> TransportResult<()> {
        self.mailbox.connect().map_err(TransportError::from)?;
        self.connected = true;
        Ok(())
    }

    fn disconnect(&mut self) -> TransportResult<()> {
        self.mailbox.disconnect().map_err(TransportError::from)?;
        self.connected = false;
        Ok(())
    }

    fn send(&mut self, command_id: u32, data: &[u8]) -> TransportResult<()> {
        if !self.connected {
            return Err(TransportError::Disconnected);
        }

        // Process command with translation - command_id passed separately, data is just the payload
        self.process_command(command_id, data)
    }

    fn receive(&mut self, buffer: &mut [u8]) -> TransportResult<usize> {
        if !self.connected {
            return Err(TransportError::Disconnected);
        }

        if !self.has_response {
            return Ok(0); // No data available
        }

        let copy_len = core::cmp::min(self.response_len, buffer.len());
        buffer[..copy_len].copy_from_slice(&self.response_buffer[..copy_len]);

        self.has_response = false; // Clear response after reading
        Ok(copy_len)
    }

    fn is_connected(&self) -> bool {
        self.connected && self.mailbox.is_ready()
    }
}
