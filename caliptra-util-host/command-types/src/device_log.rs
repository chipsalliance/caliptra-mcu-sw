// Licensed under the Apache-2.0 license

//! Device Log Commands
//!
//! Command structures for retrieving log data from the device (e.g. the
//! defmt debug log and the attestation log).

use crate::{CaliptraCommandId, CommandRequest, CommandResponse, CommonResponse};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Maximum log data size returned in a single page (matches MAX_RESP_DATA_SIZE on MCU side)
pub const MAX_DEBUG_LOG_DATA_SIZE: usize = 4 * 1024;

/// Debug log type
pub const LOG_TYPE_DEBUG: u32 = 0;
/// Attestation log type
pub const LOG_TYPE_ATTESTATION: u32 = 1;

/// Get Log request
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct DebugGetLogRequest {
    /// Log type to retrieve (0 = debug log, 1 = attestation log)
    pub log_type: u32,
}

/// Get Log response (single page)
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct DebugGetLogResponse {
    pub common: CommonResponse,
    /// Non-zero if more log data remains to be read in subsequent calls
    pub more_data: u32,
    /// Length of valid log bytes in `data`
    pub data_len: u32,
    /// Raw log bytes for this page (defmt rzCOBS frame stream for the debug log)
    pub data: [u8; MAX_DEBUG_LOG_DATA_SIZE],
}

impl CommandRequest for DebugGetLogRequest {
    type Response = DebugGetLogResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::DebugGetLog;
}

impl CommandResponse for DebugGetLogResponse {}
