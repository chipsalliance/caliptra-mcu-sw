// Licensed under the Apache-2.0 license

//! Adapter that wraps `MctpVdmSocket` from `mcu-testing-common` and implements
//! the `MctpVdmDriver` trait from `caliptra-util-host-transport`.
//!
//! `MctpVdmTransport` (from common/testing) connects over TCP to the emulator's
//! I3C controller socket and performs real MCTP framing. This adapter simply
//! bridges that existing transport into the caliptra-util-host command framework.

use caliptra_util_host_transport::{MctpVdmDriver, MctpVdmError};
use mcu_testing_common::i3c::DynamicI3cAddress;
use mcu_testing_common::mctp_vdm_transport::{MctpVdmSocket, MctpVdmTransport, VdmTransportError};

const DRIVER_BUF_SIZE: usize = 4 * 1024;

/// Adapter that owns an `MctpVdmSocket` and implements `MctpVdmDriver`.
pub struct MctpVdmSocketDriver {
    /// Factory used to (re-)create sockets.
    transport: MctpVdmTransport,
    /// Active socket (created on `connect()`).
    socket: Option<MctpVdmSocket>,
    /// Internal buffer to hold the last response so we can return `&[u8]`.
    buffer: Vec<u8>,
}

impl MctpVdmSocketDriver {
    /// Create a new driver that will connect to the given I3C socket port and
    /// target address.
    pub fn new(port: u16, target_addr: DynamicI3cAddress) -> Self {
        Self {
            transport: MctpVdmTransport::new(port, target_addr),
            socket: None,
            buffer: vec![0u8; DRIVER_BUF_SIZE],
        }
    }
}

impl MctpVdmDriver for MctpVdmSocketDriver {
    fn send_request(&mut self, vdm_request: &[u8]) -> Result<&[u8], MctpVdmError> {
        let socket = self.socket.as_mut().ok_or(MctpVdmError::NotReady)?;

        let response = socket
            .send_request(vdm_request)
            .map_err(vdm_transport_err_to_driver_err)?;

        let copy_len = response.len().min(self.buffer.len());
        self.buffer[..copy_len].copy_from_slice(&response[..copy_len]);
        Ok(&self.buffer[..copy_len])
    }

    fn is_ready(&self) -> bool {
        self.socket.is_some()
    }

    fn connect(&mut self) -> Result<(), MctpVdmError> {
        let socket = self
            .transport
            .create_socket()
            .map_err(vdm_transport_err_to_driver_err)?;
        self.socket = Some(socket);
        Ok(())
    }

    fn disconnect(&mut self) -> Result<(), MctpVdmError> {
        self.socket = None;
        Ok(())
    }
}

fn vdm_transport_err_to_driver_err(e: VdmTransportError) -> MctpVdmError {
    match e {
        VdmTransportError::Disconnected => MctpVdmError::NotReady,
        VdmTransportError::Underflow => MctpVdmError::CommunicationError,
        VdmTransportError::Timeout => MctpVdmError::Timeout,
        VdmTransportError::InvalidResponse => MctpVdmError::CommunicationError,
        VdmTransportError::CodecError => MctpVdmError::CodecError,
        VdmTransportError::CommandFailed(_) => MctpVdmError::CommunicationError,
    }
}
