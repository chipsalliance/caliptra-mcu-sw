// Licensed under the Apache-2.0 license

//! MCTP VDM Transport implementation for testing.
//!
//! This module provides transport abstraction for sending and receiving
//! MCTP VDM (Vendor Defined Messages) over I3C in the test environment.

use crate::i3c::DynamicI3cAddress;
use crate::i3c_socket::BufferedStream;
use crate::mctp_util::common::MctpUtil;
use mctp_vdm_common::codec::VdmCodec;
use mctp_vdm_common::protocol::header::{
    VdmCompletionCode, VdmMsgHeader, MCTP_VDM_MSG_TYPE, VDM_MSG_HEADER_LEN,
};
use std::net::{SocketAddr, TcpStream};
use zerocopy::{FromBytes, Immutable, IntoBytes};

// Maximum size of VDM message buffer (implementation-defined limit).
pub const MAX_VDM_PAYLOAD_SIZE: usize = 1024;

/// MCTP common header byte for VDM messages.
#[derive(Debug, Clone, Copy, Default)]
pub struct MctpVdmCommonHeader(pub u8);

impl MctpVdmCommonHeader {
    /// Create a new MCTP common header for VDM.
    pub fn new() -> Self {
        let mut hdr = MctpVdmCommonHeader(0);
        hdr.set_msg_type(MCTP_VDM_MSG_TYPE);
        hdr
    }

    /// Set the message type.
    pub fn set_msg_type(&mut self, msg_type: u8) {
        self.0 = (self.0 & 0x80) | (msg_type & 0x7F);
    }

    /// Get the message type.
    pub fn msg_type(&self) -> u8 {
        self.0 & 0x7F
    }
}

/// Error types for VDM transport operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VdmTransportError {
    /// Connection was lost or could not be established.
    Disconnected,
    /// Buffer underflow - received less data than expected.
    Underflow,
    /// Timeout waiting for response.
    Timeout,
    /// Invalid response received.
    InvalidResponse,
    /// Encoding/decoding error.
    CodecError,
    /// Response indicates failure.
    CommandFailed(VdmCompletionCode),
}

/// VDM socket for sending requests and receiving responses.
pub struct MctpVdmSocket {
    target_addr: u8,
    msg_tag: u8,
    stream: BufferedStream,
}

impl MctpVdmSocket {
    /// Create a new VDM socket connected to the given target.
    pub fn new(stream: BufferedStream, target_addr: u8) -> Self {
        MctpVdmSocket {
            target_addr,
            msg_tag: 0,
            stream,
        }
    }

    /// Send a VDM request and receive the response.
    ///
    /// The request should contain the full VDM payload (header + data).
    /// Returns the response payload (header + data).
    pub fn send_request(&mut self, request: &[u8]) -> Result<Vec<u8>, VdmTransportError> {
        let mut mctp_util = MctpUtil::new();
        mctp_util.set_pkt_payload_size(MAX_VDM_PAYLOAD_SIZE);

        // Build MCTP payload: common header + VDM request
        let mut mctp_payload: Vec<u8> = Vec::new();
        let mctp_common_header = MctpVdmCommonHeader::new();
        mctp_payload.push(mctp_common_header.0);
        mctp_payload.extend_from_slice(request);

        // Send request and wait for response
        mctp_util.new_req(self.msg_tag);
        let response = mctp_util
            .wait_for_responder(
                self.msg_tag,
                mctp_payload.as_mut_slice(),
                &mut self.stream,
                self.target_addr,
            )
            .ok_or(VdmTransportError::Timeout)?;

        // Increment message tag for next request
        self.msg_tag = (self.msg_tag + 1) & 0x07;

        // Skip MCTP common header and return VDM payload
        if response.len() <= 1 {
            return Err(VdmTransportError::Underflow);
        }

        Ok(response[1..].to_vec())
    }

    /// Send a typed VDM request and receive typed response.
    pub fn send_typed_request<Req, Resp>(
        &mut self,
        request: &Req,
    ) -> Result<Resp, VdmTransportError>
    where
        Req: IntoBytes + Immutable + ?Sized,
        Resp: FromBytes,
    {
        let request_bytes = request.as_bytes();
        let response_bytes = self.send_request(request_bytes)?;

        Resp::read_from_bytes(&response_bytes).map_err(|_| VdmTransportError::CodecError)
    }
}

/// VDM transport factory for creating sockets.
#[derive(Clone)]
pub struct MctpVdmTransport {
    port: u16,
    target_addr: DynamicI3cAddress,
}

impl MctpVdmTransport {
    /// Create a new VDM transport.
    pub fn new(port: u16, target_addr: DynamicI3cAddress) -> Self {
        Self { port, target_addr }
    }

    /// Create a new VDM socket.
    pub fn create_socket(&self) -> Result<MctpVdmSocket, VdmTransportError> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));
        let stream = TcpStream::connect(addr).map_err(|_| VdmTransportError::Disconnected)?;
        let stream = BufferedStream::new(stream);
        Ok(MctpVdmSocket::new(stream, self.target_addr.into()))
    }
}

/// Helper struct for building and sending VDM commands.
pub struct VdmClient {
    socket: MctpVdmSocket,
}

impl VdmClient {
    /// Create a new VDM client.
    pub fn new(socket: MctpVdmSocket) -> Self {
        VdmClient { socket }
    }

    /// Send a raw VDM request.
    pub fn send_raw(&mut self, request: &[u8]) -> Result<Vec<u8>, VdmTransportError> {
        self.socket.send_request(request)
    }

    /// Send a command with just the header (no payload).
    pub fn send_command(&mut self, command_code: u8) -> Result<Vec<u8>, VdmTransportError> {
        let header = VdmMsgHeader::new_request(command_code);
        let mut buffer = [0u8; VDM_MSG_HEADER_LEN];
        header
            .encode(&mut buffer)
            .map_err(|_| VdmTransportError::CodecError)?;
        self.socket.send_request(&buffer)
    }

    /// Send a command with payload.
    pub fn send_command_with_payload(
        &mut self,
        command_code: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, VdmTransportError> {
        let header = VdmMsgHeader::new_request(command_code);
        let mut buffer = vec![0u8; VDM_MSG_HEADER_LEN + payload.len()];
        header
            .encode(&mut buffer[..VDM_MSG_HEADER_LEN])
            .map_err(|_| VdmTransportError::CodecError)?;
        buffer[VDM_MSG_HEADER_LEN..].copy_from_slice(payload);
        self.socket.send_request(&buffer)
    }

    /// Parse a response to extract the completion code.
    pub fn parse_completion_code(response: &[u8]) -> Result<VdmCompletionCode, VdmTransportError> {
        if response.len() < VDM_MSG_HEADER_LEN + 4 {
            return Err(VdmTransportError::Underflow);
        }
        let completion_code_bytes = &response[VDM_MSG_HEADER_LEN..VDM_MSG_HEADER_LEN + 4];
        let completion_code = u32::from_le_bytes(
            completion_code_bytes
                .try_into()
                .map_err(|_| VdmTransportError::CodecError)?,
        );
        VdmCompletionCode::try_from(completion_code).map_err(|_| VdmTransportError::InvalidResponse)
    }

    /// Check if response indicates success.
    pub fn check_success(response: &[u8]) -> Result<(), VdmTransportError> {
        let code = Self::parse_completion_code(response)?;
        if code == VdmCompletionCode::Success {
            Ok(())
        } else {
            Err(VdmTransportError::CommandFailed(code))
        }
    }
}
