// Licensed under the Apache-2.0 license

//! Cryptographic Delete command types
//!
//! This module defines the request/response structures for the CM Delete command
//! which deletes an encrypted CMK (Cryptographic Mailbox Key) from storage.

use crate::crypto_hmac::{Cmk, CMK_SIZE};
use crate::{CaliptraCommandId, CommandRequest, CommandResponse, CommonResponse};
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct DeleteRequest {
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
    pub fn new(cmk: &Cmk) -> Self {
        Self { cmk: cmk.clone() }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct DeleteResponse {
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
