// Licensed under the Apache-2.0 license

//! Common traits and macros for mailbox command processing
//!
//! This module contains generic traits and macros that can be used by all command types
//! to enable automatic protocol translation between internal Caliptra library format
//! and external mailbox protocol format.

use super::checksum::verify_checksum;
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Trait for handling variable-size serialization/deserialization
/// Default implementation uses zerocopy traits for fixed-size structs
/// Override for variable-size structs that need custom encoding
pub trait VariableSizeBytes: IntoBytes + FromBytes + Immutable + Sized {
    /// Serialize to bytes, returning the actual size used
    fn to_bytes_variable(&self, buffer: &mut [u8]) -> usize {
        // Default implementation: use full struct size with zerocopy
        let data = self.as_bytes();
        let copy_len = core::cmp::min(data.len(), buffer.len());
        buffer[..copy_len].copy_from_slice(&data[..copy_len]);
        copy_len
    }

    /// Deserialize from bytes with variable-size support
    fn from_bytes_variable(bytes: &[u8]) -> Result<Self, crate::TransportError> {
        // Default implementation: use zerocopy read_from_bytes
        match Self::read_from_bytes(bytes) {
            Ok(value) => Ok(value),
            Err(_) => Err(crate::TransportError::InvalidMessage),
        }
    }

    /// Create from MCU data with variable length (default does nothing special)
    fn from_mcu_data_default(bytes: &[u8]) -> Result<Self, crate::TransportError> {
        Self::from_bytes_variable(bytes)
    }
}

/// Trait for converting internal Caliptra commands to external mailbox format
pub trait FromInternalRequest<T> {
    /// Convert from internal request type to external request type
    /// The command_code is used for checksum calculation
    fn from_internal(internal: &T, command_code: u32) -> Self;
}

/// Trait for converting external mailbox responses to internal Caliptra format  
pub trait ToInternalResponse<T> {
    /// Convert from external response type to internal response type
    fn to_internal(&self) -> T;
}

/// Trait defining command metadata for external commands
pub trait ExternalCommandMetadata {
    type InternalRequest: IntoBytes + FromBytes + Immutable;
    type InternalResponse: IntoBytes + FromBytes + Immutable;
    type ExternalRequest: FromInternalRequest<Self::InternalRequest>
        + IntoBytes
        + FromBytes
        + Immutable;
    type ExternalResponse: ToInternalResponse<Self::InternalResponse> + VariableSizeBytes;

    /// Get the external mailbox command code
    const EXTERNAL_CMD_CODE: u32;
}

/// Trait for external command handlers that can process commands with automatic translation
pub trait ExternalCommandHandler {
    /// Process a command by converting internal request to external, sending to mailbox,
    /// receiving response, and converting back to internal format
    fn process_command(
        command_id: u32,
        payload: &[u8],
        mailbox: &mut dyn crate::transports::mailbox::transport::MailboxDriver,
        response_buffer: &mut [u8],
    ) -> Result<usize, crate::TransportError>;

    /// Get the external mailbox command code for this command
    fn get_external_cmd_code(command_id: u32) -> Option<u32>;
}

/// Generic command processor that works with any command implementing the required traits
/// Supports both fixed-size and variable-size responses using VariableSizeBytes trait
pub fn process_command<InternalReq, InternalResp, ExternalReq, ExternalResp>(
    external_cmd_code: u32,
    payload: &[u8],
    mailbox: &mut dyn crate::transports::mailbox::transport::MailboxDriver,
    response_buffer: &mut [u8],
) -> Result<usize, crate::TransportError>
where
    InternalReq: IntoBytes + FromBytes + Immutable,
    InternalResp: IntoBytes + FromBytes + Immutable,
    ExternalReq: FromInternalRequest<InternalReq> + IntoBytes + FromBytes + Immutable,
    ExternalResp: ToInternalResponse<InternalResp> + VariableSizeBytes,
{
    // Parse internal request from payload or create default
    let internal_req = if payload.is_empty() {
        // Create default request with zero values
        unsafe { core::mem::zeroed() }
    } else if payload.len() >= core::mem::size_of::<InternalReq>() {
        InternalReq::read_from_bytes(payload).map_err(|_| crate::TransportError::InvalidMessage)?
    } else {
        return Err(crate::TransportError::InvalidMessage);
    };

    // Convert to external format
    let external_req = ExternalReq::from_internal(&internal_req, external_cmd_code);

    // Send to mailbox
    let response = mailbox
        .send_command(external_cmd_code, external_req.as_bytes())
        .map_err(crate::TransportError::from)?;

    // Parse external response using variable-size aware parsing
    // Require at least 4 bytes for checksum
    if response.len() < 4 {
        return Err(crate::TransportError::InvalidMessage);
    }

    let external_resp = ExternalResp::from_bytes_variable(response)
        .map_err(|_| crate::TransportError::InvalidMessage)?;

    // Verify checksum in the response
    // All external responses have chksum as the first u32 field
    if response.len() >= 4 {
        let response_chksum =
            u32::from_le_bytes([response[0], response[1], response[2], response[3]]);
        // The checksum is calculated over everything after the checksum field
        let payload_data = &response[4..];
        // For responses, pass 0 as cmd parameter to verify_checksum
        if !verify_checksum(response_chksum, 0, payload_data) {
            return Err(crate::TransportError::InvalidMessage);
        }
    }

    // Convert back to internal format
    let internal_resp = external_resp.to_internal();
    let internal_resp_bytes = internal_resp.as_bytes();

    // Copy to response buffer
    let copy_len = core::cmp::min(internal_resp_bytes.len(), response_buffer.len());
    response_buffer[..copy_len].copy_from_slice(&internal_resp_bytes[..copy_len]);

    Ok(copy_len)
}

/// Generic command processor using command metadata
pub fn process_command_with_metadata<T: ExternalCommandMetadata>(
    payload: &[u8],
    mailbox: &mut dyn crate::transports::mailbox::transport::MailboxDriver,
    response_buffer: &mut [u8],
) -> Result<usize, crate::TransportError> {
    process_command::<
        T::InternalRequest,
        T::InternalResponse,
        T::ExternalRequest,
        T::ExternalResponse,
    >(T::EXTERNAL_CMD_CODE, payload, mailbox, response_buffer)
}

// ============================================================================
// Command Definition Macros
// ============================================================================

/// Macro to generate command metadata structs
#[macro_export]
macro_rules! define_command {
    ($cmd_struct:ident, $cmd_code:literal, $internal_req:ty, $internal_resp:ty, $external_req:ty, $external_resp:ty) => {
        pub struct $cmd_struct;
        impl ExternalCommandMetadata for $cmd_struct {
            type InternalRequest = $internal_req;
            type InternalResponse = $internal_resp;
            type ExternalRequest = $external_req;
            type ExternalResponse = $external_resp;
            const EXTERNAL_CMD_CODE: u32 = $cmd_code;
        }
    };
}

/// Macro to generate command handler mappings using CaliptraCommandId enum values  
#[macro_export]
macro_rules! command_mapping {
    ($(($enum_val:expr, $cmd_struct:ident)),* $(,)?) => {
        /// Static mapping from command ID to command handler function
        pub fn get_command_handler(command_id: u32) -> Option<fn(&[u8], &mut dyn $crate::transports::mailbox::transport::MailboxDriver, &mut [u8]) -> Result<usize, $crate::TransportError>> {
            match command_id {
                $(
                    x if x == ($enum_val as u32) => Some(process_command_with_metadata::<$cmd_struct>),
                )*
                _ => None,
            }
        }

        /// Get external command code for a given command ID
        pub fn get_external_cmd_code(command_id: u32) -> Option<u32> {
            match command_id {
                $(
                    x if x == ($enum_val as u32) => Some(<$cmd_struct as ExternalCommandMetadata>::EXTERNAL_CMD_CODE),
                )*
                _ => None,
            }
        }
    };
}

// Note: Macros are exported at the crate level with #[macro_export]
