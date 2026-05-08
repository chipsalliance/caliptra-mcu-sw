// Licensed under the Apache-2.0 license

//! SPDM VDM Transport Implementation
//!
//! This module provides the SPDM VDM transport with a trait-based driver
//! abstraction. The `SpdmVdmDriver` trait defines the low-level interface
//! for sending/receiving Caliptra VDM payloads over SPDM VENDOR_DEFINED
//! messages. The `SpdmVdmTransport` struct implements the `Transport` trait
//! and handles command encoding/decoding.

use super::dispatch::get_command_handler;
use super::protocol::MAX_VDM_RESPONSE_SIZE;
use crate::{Transport, TransportError, TransportResult};

/// Trait for SPDM VDM low-level communication.
///
/// Implementors of this trait provide the actual SPDM VENDOR_DEFINED_REQUEST
/// transport over a specific medium (e.g., TCP socket to SPDM bridge, PCIe DOE).
/// This trait operates at the Caliptra VDM payload level — the implementor handles
/// SPDM framing (vendor ID, registry ID, VENDOR_DEFINED_REQUEST wrapping).
///
/// Note: Only `Send` is required (not `Sync`) because SPDM sessions using libspdm
/// are inherently single-threaded due to global state.
pub trait SpdmVdmDriver: Send {
    /// Send a Caliptra VDM request payload and receive the response payload.
    ///
    /// `request` is the raw Caliptra VDM payload: [version, command_code, data...]
    /// The returned bytes are the VDM response payload: [version, command_code, completion_code, data...]
    ///
    /// The implementor wraps this in SPDM VENDOR_DEFINED_REQUEST with the OCP vendor ID
    /// and IANA registry ID, sends it, and strips the SPDM framing from the response.
    fn send_receive_vdm(
        &mut self,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, SpdmVdmError>;

    /// Check if the transport is ready.
    fn is_ready(&self) -> bool;

    /// Establish a connection (SPDM session setup).
    fn connect(&mut self) -> Result<(), SpdmVdmError>;

    /// Close the connection.
    fn disconnect(&mut self) -> Result<(), SpdmVdmError>;
}

/// SPDM VDM error types.
#[derive(Debug, Clone)]
pub enum SpdmVdmError {
    /// Transport is not ready / not connected.
    NotReady,
    /// Timeout waiting for a response.
    Timeout,
    /// The command is not supported over this transport.
    InvalidCommand,
    /// Low-level communication failure.
    CommunicationError,
    /// Response buffer overflow.
    BufferOverflow,
    /// The device returned a non-success VDM completion code.
    DeviceError(u8),
    /// Encoding / decoding error.
    CodecError,
    /// SPDM session error.
    SessionError,
}

impl From<SpdmVdmError> for TransportError {
    fn from(err: SpdmVdmError) -> Self {
        match err {
            SpdmVdmError::NotReady => TransportError::ConnectionFailed(Some("SPDM VDM not ready")),
            SpdmVdmError::Timeout => TransportError::Timeout,
            SpdmVdmError::InvalidCommand => {
                TransportError::NotSupported("SPDM VDM invalid command")
            }
            SpdmVdmError::CommunicationError => {
                TransportError::ConnectionFailed(Some("SPDM VDM communication error"))
            }
            SpdmVdmError::BufferOverflow => TransportError::BufferError("Buffer overflow"),
            SpdmVdmError::DeviceError(_) => {
                TransportError::ConnectionFailed(Some("SPDM VDM device error"))
            }
            SpdmVdmError::CodecError => TransportError::InvalidMessage,
            SpdmVdmError::SessionError => {
                TransportError::ConnectionFailed(Some("SPDM session error"))
            }
        }
    }
}

/// SPDM VDM Transport using dynamic dispatch via `SpdmVdmDriver`.
pub struct SpdmVdmTransport<'a> {
    driver: &'a mut dyn SpdmVdmDriver,
    connected: bool,
    response_buffer: [u8; MAX_VDM_RESPONSE_SIZE],
    response_len: usize,
    has_response: bool,
}

// Safety: SpdmVdmTransport is only used from a single thread (SPDM sessions are
// inherently single-threaded due to libspdm global state). The Sync bound is
// required by the Transport trait but the &mut reference prevents actual sharing.
unsafe impl Sync for SpdmVdmTransport<'_> {}

impl<'a> SpdmVdmTransport<'a> {
    pub fn new(driver: &'a mut dyn SpdmVdmDriver) -> Self {
        Self {
            driver,
            connected: false,
            response_buffer: [0; MAX_VDM_RESPONSE_SIZE],
            response_len: 0,
            has_response: false,
        }
    }

    /// Process a command: encode internal request → VDM payload, send, decode response.
    fn process_command(&mut self, command_id: u32, payload: &[u8]) -> TransportResult<()> {
        if let Some(handler) = get_command_handler(command_id) {
            self.response_len = handler(payload, self.driver, &mut self.response_buffer)?;
            self.has_response = true;
            Ok(())
        } else {
            Err(TransportError::NotSupported(
                "Command not supported by SPDM VDM transport",
            ))
        }
    }
}

impl Transport for SpdmVdmTransport<'_> {
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
