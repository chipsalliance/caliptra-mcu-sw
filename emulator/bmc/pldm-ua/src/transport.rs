// Licensed under the Apache-2.0 license

use core::fmt::{Display, Formatter};
use core::time::Duration;

// This module provides traits for representing the PLDM transport layer.
// The PldmTransport and PldmSocket traits define generic transport entities used by PLDM for communication.
// PldmTransport represents the virtual channel where PLDM messages are sent and received. An example of this is MCTP (Management Component Transport Protocol).
// PldmSocket is a binding between a source and destination entity within the transport layer.
// To communicate within the transport, a PldmSocket should be created from the transport, indicating the source and destination endpoints.
// The endpoint will be using the PldmSocket to send and receive PLDM messages.
//
//
//     Endpoint                           Endpoint
//        |                                   |
//        |                                   |
//    PldmSocket                          PldmSocket
// --------------------------------------------------------
//                     PldmTransport
// --------------------------------------------------------

pub trait PldmTransport<T: PldmSocket> {
    fn create_socket(&self, source: EndpointId, dest: EndpointId) -> Result<T, PldmTransportError>;
}

#[derive(Debug)]
pub enum PldmTransportError {
    Timeout,
    Disconnected,
    Underflow,
    NotInitialized,
}
pub const MAX_PLDM_PAYLOAD_SIZE: usize = 1024;

pub trait PldmSocket {
    /// Sends a payload over the PLDM socket.
    ///
    /// # Arguments
    ///
    /// * `payload` - A byte slice containing the data to be sent.
    ///
    /// # Returns
    ///
    /// * `Result<(), PldmTransportError>` - Returns `Ok(())` if the payload is sent successfully,
    ///   otherwise returns a `PldmTransportError`.
    fn send(&self, payload: &[u8]) -> Result<(), PldmTransportError>;

    /// Receives a packet from the PLDM socket.
    ///
    /// # Arguments
    ///
    /// * `timeout` - An optional `Duration` specifying the maximum time to wait for a packet.
    ///
    /// # Returns
    ///
    /// * `Result<RxPacket, PldmTransportError>` - Returns `Ok(RxPacket)` if a packet is received successfully,
    ///   otherwise returns a `PldmTransportError`.
    fn receive(&self, timeout: Option<Duration>) -> Result<RxPacket, PldmTransportError>;

    /// Establishes a connection for the PLDM socket.
    ///
    /// # Returns
    ///
    /// * `Result<(), PldmTransportError>` - Returns `Ok(())` if the connection is established successfully,
    ///   otherwise returns a `PldmTransportError`.
    fn connect(&self) -> Result<(), PldmTransportError>;

    /// Disconnects the PLDM socket.
    ///
    /// This method does not return a result and is expected to always succeed.
    fn disconnect(&self);

    /// Clones the PLDM socket. This allows the socket to be shared across multiple threads or tasks.
    ///
    /// # Returns
    ///
    /// * `Self` - Returns a new instance of the PLDM socket.
    fn clone(&self) -> Self;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct EndpointId(pub u8);
#[derive(Debug, Clone)]
pub struct Payload {
    pub data: [u8; MAX_PLDM_PAYLOAD_SIZE],
    pub len: usize,
}

impl Default for Payload {
    fn default() -> Self {
        Self {
            data: [0; MAX_PLDM_PAYLOAD_SIZE],
            len: 0,
        }
    }
}

impl Display for Payload {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Payload {{ data: {:?}, len: {} }}",
            &self.data[..self.len],
            self.len
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct TxPacket {
    pub src: EndpointId,
    pub dest: EndpointId,
    pub payload: Payload,
}

#[derive(Debug, Clone, Default)]
pub struct RxPacket {
    pub src: EndpointId,
    pub payload: Payload,
}

impl Display for RxPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "RxPacket {{ src: {:?}, payload: {} }}",
            self.src, self.payload
        )
    }
}
