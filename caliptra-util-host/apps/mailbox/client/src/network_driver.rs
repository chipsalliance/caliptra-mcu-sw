// Licensed under the Apache-2.0 license

use caliptra_util_host_transport::{MailboxDriver, MailboxError};
use std::net::{SocketAddr, UdpSocket};

/// UDP-based mailbox driver for network communication
pub struct UdpTransportDriver {
    socket: Option<UdpSocket>,
    server_addr: SocketAddr,
    buffer: Vec<u8>,
    connected: bool,
}

impl UdpTransportDriver {
    pub fn new(server_addr: SocketAddr) -> Self {
        Self {
            socket: None,
            server_addr,
            buffer: vec![0u8; 4096],
            connected: false,
        }
    }
}

impl MailboxDriver for UdpTransportDriver {
    fn send_command(&mut self, external_cmd: u32, payload: &[u8]) -> Result<&[u8], MailboxError> {
        let socket = self.socket.as_ref().ok_or(MailboxError::NotReady)?;

        // Create a simple protocol: [4 bytes cmd][payload]
        let mut message = Vec::with_capacity(4 + payload.len());
        message.extend_from_slice(&external_cmd.to_le_bytes());
        message.extend_from_slice(payload);

        socket
            .send_to(&message, self.server_addr)
            .map_err(|_| MailboxError::CommunicationError)?;

        // Receive response
        let (bytes_received, _) = socket
            .recv_from(&mut self.buffer)
            .map_err(|_| MailboxError::CommunicationError)?;

        Ok(&self.buffer[..bytes_received])
    }

    fn is_ready(&self) -> bool {
        self.connected && self.socket.is_some()
    }

    fn connect(&mut self) -> Result<(), MailboxError> {
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(|_| MailboxError::CommunicationError)?;

        self.socket = Some(socket);
        self.connected = true;
        Ok(())
    }

    fn disconnect(&mut self) -> Result<(), MailboxError> {
        self.socket = None;
        self.connected = false;
        Ok(())
    }
}
