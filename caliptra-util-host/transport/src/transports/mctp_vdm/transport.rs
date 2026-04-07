// Licensed under the Apache-2.0 license

//! MCTP VDM Transport Implementation
//!
//! This module provides the MCTP VDM transport with a trait-based driver
//! abstraction. The `MctpVdmDriver` trait defines the low-level interface
//! for sending/receiving MCTP VDM packets over any physical transport (I3C,
//! TCP socket for testing, etc.). The `MctpVdmTransport` struct implements
//! the `Transport` trait and handles command encoding/decoding.

use super::dispatch::get_command_handler;
use crate::{Transport, TransportError, TransportResult};

/// Maximum VDM response buffer size in bytes.
pub const MAX_VDM_RESP_BUF: usize = 2 * 1024;

/// Trait for MCTP VDM low-level communication.
///
/// Implementors of this trait provide the actual MCTP VDM packet transport
/// over a specific physical medium (e.g., I3C, TCP socket). The transport
/// layer handles MCTP framing and reassembly; this trait operates at the
/// VDM message level (after the MCTP common header byte).
pub trait MctpVdmDriver: Send + Sync {
    /// Send a VDM request and return the VDM response payload.
    ///
    /// `vdm_request` is the full VDM message (header + payload) *without*
    /// the MCTP common header byte. The returned slice is the VDM response
    /// message (header + payload), also without the MCTP common header.
    fn send_request(&mut self, vdm_request: &[u8]) -> Result<&[u8], MctpVdmError>;

    /// Check if the transport is ready.
    fn is_ready(&self) -> bool;

    /// Establish a connection.
    fn connect(&mut self) -> Result<(), MctpVdmError>;

    /// Close the connection.
    fn disconnect(&mut self) -> Result<(), MctpVdmError>;
}

/// MCTP VDM error types.
#[derive(Debug, Clone)]
pub enum MctpVdmError {
    /// Transport is not ready / not connected.
    NotReady,
    /// Timeout waiting for a response.
    Timeout,
    /// The command is not supported.
    InvalidCommand,
    /// Low-level communication failure.
    CommunicationError,
    /// Response buffer overflow.
    BufferOverflow,
    /// The device returned a non-success completion code.
    DeviceError(u32),
    /// Encoding / decoding error.
    CodecError,
}

impl From<MctpVdmError> for TransportError {
    fn from(err: MctpVdmError) -> Self {
        match err {
            MctpVdmError::NotReady => TransportError::ConnectionFailed(Some("MCTP VDM not ready")),
            MctpVdmError::Timeout => TransportError::Timeout,
            MctpVdmError::InvalidCommand => TransportError::InvalidMessage,
            MctpVdmError::CommunicationError => {
                TransportError::ConnectionFailed(Some("MCTP VDM communication error"))
            }
            MctpVdmError::BufferOverflow => TransportError::BufferError("Buffer overflow"),
            MctpVdmError::DeviceError(_) => {
                TransportError::ConnectionFailed(Some("MCTP VDM device error"))
            }
            MctpVdmError::CodecError => TransportError::InvalidMessage,
        }
    }
}

/// MCTP VDM Transport using dynamic dispatch via `MctpVdmDriver`.
pub struct MctpVdmTransport<'a> {
    driver: &'a mut dyn MctpVdmDriver,
    connected: bool,
    response_buffer: [u8; MAX_VDM_RESP_BUF],
    response_len: usize,
    has_response: bool,
}

impl<'a> MctpVdmTransport<'a> {
    pub fn new(driver: &'a mut dyn MctpVdmDriver) -> Self {
        Self {
            driver,
            connected: false,
            response_buffer: [0; MAX_VDM_RESP_BUF],
            response_len: 0,
            has_response: false,
        }
    }

    /// Process a command: encode internal request → VDM packet, send, decode response.
    fn process_command(&mut self, command_id: u32, payload: &[u8]) -> TransportResult<()> {
        if let Some(handler) = get_command_handler(command_id) {
            self.response_len = handler(payload, self.driver, &mut self.response_buffer)?;
            self.has_response = true;
            Ok(())
        } else {
            Err(TransportError::NotSupported(
                "Command not supported by MCTP VDM transport",
            ))
        }
    }
}

impl Transport for MctpVdmTransport<'_> {
    fn connect(&mut self) -> TransportResult<()> {
        self.driver.connect().map_err(TransportError::from)?;
        self.connected = true;
        Ok(())
    }

    fn disconnect(&mut self) -> TransportResult<()> {
        self.driver.disconnect().map_err(TransportError::from)?;
        self.connected = false;
        Ok(())
    }

    fn send(&mut self, command_id: u32, data: &[u8]) -> TransportResult<()> {
        if !self.connected {
            return Err(TransportError::Disconnected);
        }
        self.process_command(command_id, data)
    }

    fn receive(&mut self, buffer: &mut [u8]) -> TransportResult<usize> {
        if !self.connected {
            return Err(TransportError::Disconnected);
        }

        if !self.has_response {
            return Ok(0);
        }

        let copy_len = core::cmp::min(self.response_len, buffer.len());
        buffer[..copy_len].copy_from_slice(&self.response_buffer[..copy_len]);

        self.has_response = false;
        Ok(copy_len)
    }

    fn is_connected(&self) -> bool {
        self.connected && self.driver.is_ready()
    }
}
