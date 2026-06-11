// Licensed under the Apache-2.0 license

//! Device log commands for mailbox transport
//!
//! This module provides command definitions and implementations for log
//! retrieval commands using the mailbox transport protocol.

use super::checksum::calc_checksum;
use super::command_traits::*;
use caliptra_mcu_core_util_host_command_types::device_log::{
    DebugGetLogRequest, DebugGetLogResponse, MAX_DEBUG_LOG_DATA_SIZE,
};
use caliptra_mcu_core_util_host_command_types::CommonResponse;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub use super::command_traits::{process_command, process_command_with_metadata};

// ============================================================================
// MC_GET_LOG Command (0x4D47_4C47 - "MGLG")
// ============================================================================

/// Size of the device response `data` field, which holds the 4-byte `more_data`
/// prefix followed by the log bytes.
const EXT_DEBUG_LOG_DATA_SIZE: usize = MAX_DEBUG_LOG_DATA_SIZE;

/// Length of the `more_data` prefix at the start of the response data field.
const MORE_DATA_LEN: usize = 4;

/// External command: Get Log request
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdDebugGetLogRequest {
    /// Checksum over input data
    pub chksum: u32,
    /// Log type to retrieve
    pub log_type: u32,
}

/// External command: Get Log response
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdDebugGetLogResponse {
    /// Checksum field
    pub chksum: u32,
    /// FIPS approved or an error
    pub fips_status: u32,
    /// Length of data (4-byte more_data prefix + log bytes)
    pub data_len: u32,
    /// Response data: [more_data (u32 LE)][log bytes]
    pub data: [u8; EXT_DEBUG_LOG_DATA_SIZE],
}

impl FromInternalRequest<DebugGetLogRequest> for ExtCmdDebugGetLogRequest {
    fn from_internal(internal: &DebugGetLogRequest, command_code: u32) -> Self {
        let chksum = calc_checksum(command_code, internal.as_bytes());
        Self {
            chksum,
            log_type: internal.log_type,
        }
    }
}

impl ToInternalResponse<DebugGetLogResponse> for ExtCmdDebugGetLogResponse {
    fn to_internal(&self) -> DebugGetLogResponse {
        let device_data_len = (self.data_len as usize).min(EXT_DEBUG_LOG_DATA_SIZE);

        let more_data = if device_data_len >= MORE_DATA_LEN {
            u32::from_le_bytes([self.data[0], self.data[1], self.data[2], self.data[3]])
        } else {
            0
        };

        let frame_len = device_data_len.saturating_sub(MORE_DATA_LEN);
        let mut data = [0u8; MAX_DEBUG_LOG_DATA_SIZE];
        data[..frame_len].copy_from_slice(&self.data[MORE_DATA_LEN..MORE_DATA_LEN + frame_len]);

        DebugGetLogResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            more_data,
            data_len: frame_len as u32,
            data,
        }
    }
}

impl VariableSizeBytes for ExtCmdDebugGetLogRequest {}

impl VariableSizeBytes for ExtCmdDebugGetLogResponse {
    fn from_bytes_variable(bytes: &[u8]) -> Result<Self, crate::TransportError> {
        if bytes.len() < 12 {
            return Err(crate::TransportError::InvalidMessage);
        }

        let chksum = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let fips_status = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let data_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);

        let data_len_usize = data_len as usize;
        if data_len_usize > EXT_DEBUG_LOG_DATA_SIZE || bytes.len() < 12 + data_len_usize {
            return Err(crate::TransportError::InvalidMessage);
        }

        let mut data = [0u8; EXT_DEBUG_LOG_DATA_SIZE];
        data[..data_len_usize].copy_from_slice(&bytes[12..12 + data_len_usize]);

        Ok(ExtCmdDebugGetLogResponse {
            chksum,
            fips_status,
            data_len,
            data,
        })
    }

    fn to_bytes_variable(&self, buffer: &mut [u8]) -> usize {
        let header_size = 12;
        let actual_len = (self.data_len as usize).min(EXT_DEBUG_LOG_DATA_SIZE);
        let total_size = header_size + actual_len;

        if buffer.len() < total_size {
            return 0;
        }

        buffer[0..4].copy_from_slice(&self.chksum.to_le_bytes());
        buffer[4..8].copy_from_slice(&self.fips_status.to_le_bytes());
        buffer[8..12].copy_from_slice(&self.data_len.to_le_bytes());
        buffer[12..12 + actual_len].copy_from_slice(&self.data[..actual_len]);

        total_size
    }
}

// ============================================================================
// Command Metadata Definition
// ============================================================================

use crate::define_command;

define_command!(
    DebugGetLogCmd,
    0x4D47_4C47, // MC_GET_LOG - "MGLG"
    DebugGetLogRequest,
    DebugGetLogResponse,
    ExtCmdDebugGetLogRequest,
    ExtCmdDebugGetLogResponse
);
