// Licensed under the Apache-2.0 license

//! Cryptographic Delete command types
//!
//! This module defines the request/response structures for the CM Delete command
//! which deletes an encrypted CMK (Cryptographic Mailbox Key) from storage.

use crate::crypto_hmac::{Cmk, CMK_SIZE};
use crate::{CaliptraCommandId, CommandRequest, CommandResponse, CommonResponse};
use zerocopy::{FromBytes, Immutable, IntoBytes};

// ============================================================================
// Delete Command
// ============================================================================

/// Delete request - deletes an encrypted CMK from storage
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct DeleteRequest {
    /// CMK to delete
    pub cmk: Cmk,
}

impl Default for DeleteRequest {
    fn default() -> Self {
        Self {
            cmk: Cmk::new([0u8; CMK_SIZE]),
        }
    }
}

impl DeleteRequest {
    /// Create a new delete request for the given CMK
    pub fn new(cmk: &Cmk) -> Self {
        Self { cmk: cmk.clone() }
    }
}

/// Delete response - just contains FIPS status
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct DeleteResponse {
    /// Common response header
    pub common: CommonResponse,
}

impl Default for DeleteResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse { fips_status: 0 },
        }
    }
}

impl CommandRequest for DeleteRequest {
    type Response = DeleteResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::Delete;
}

impl CommandResponse for DeleteResponse {}
