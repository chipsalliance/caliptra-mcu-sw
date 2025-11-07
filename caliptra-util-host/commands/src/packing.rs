// Licensed under the Apache-2.0 license

//! Command Packing and Unpacking
//!
//! Zerocopy-based serialization and deserialization of command arguments

use caliptra_util_host_command_types::{
    CommandError, CommandRequest, CommandResponse, CommandResult,
};
use zerocopy::{FromBytes, IntoBytes};

/// Pack a command request into a fixed buffer using zerocopy
pub fn pack_command_request<Req: CommandRequest>(
    request: &Req,
    buffer: &mut [u8],
) -> CommandResult<usize> {
    let data = IntoBytes::as_bytes(request);
    if buffer.len() < data.len() {
        return Err(CommandError::BufferTooSmall);
    }
    buffer[..data.len()].copy_from_slice(data);
    Ok(data.len())
}

/// Unpack a command request from bytes using zerocopy
pub fn unpack_command_request<Req: CommandRequest>(data: &[u8]) -> CommandResult<Req> {
    FromBytes::read_from_bytes(data).map_err(|_| CommandError::DeserializationError)
}

/// Pack a command response into a fixed buffer using zerocopy
pub fn pack_command_response<Resp: CommandResponse>(
    response: &Resp,
    buffer: &mut [u8],
) -> CommandResult<usize> {
    let data = IntoBytes::as_bytes(response);
    if buffer.len() < data.len() {
        return Err(CommandError::BufferTooSmall);
    }
    buffer[..data.len()].copy_from_slice(data);
    Ok(data.len())
}

/// Unpack a command response from bytes using zerocopy
pub fn unpack_command_response<Resp: CommandResponse>(data: &[u8]) -> CommandResult<Resp> {
    FromBytes::read_from_bytes(data).map_err(|_| CommandError::DeserializationError)
}

/// Maximum command packet size (4KB should be sufficient for most commands)
pub const MAX_COMMAND_PACKET_SIZE: usize = 4096;

/// Command packet structure for transport layer using fixed buffers
#[repr(C)]
#[derive(Debug, Clone)]
pub struct CommandPacket {
    /// Command ID
    pub command_id: u32,
    /// Request data length
    pub data_length: u32,
    /// Request data buffer (fixed size)
    pub data: [u8; MAX_COMMAND_PACKET_SIZE],
    /// Actual data length used
    pub used_length: usize,
}

impl CommandPacket {
    /// Create a new command packet from a request
    pub fn new<Req: CommandRequest>(request: &Req) -> CommandResult<Self> {
        let mut packet = CommandPacket {
            command_id: Req::COMMAND_ID as u32,
            data_length: 0,
            data: [0; MAX_COMMAND_PACKET_SIZE],
            used_length: 0,
        };

        let data_len = pack_command_request(request, &mut packet.data)?;
        packet.data_length = data_len as u32;
        packet.used_length = data_len;

        Ok(packet)
    }

    /// Extract request from packet
    pub fn extract_request<Req: CommandRequest>(&self) -> CommandResult<Req> {
        unpack_command_request(&self.data[..self.used_length])
    }

    /// Get the data slice with actual content
    pub fn get_data(&self) -> &[u8] {
        &self.data[..self.used_length]
    }
}
