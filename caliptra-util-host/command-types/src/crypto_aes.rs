// Licensed under the Apache-2.0 license

//! AES and Symmetric Crypto Commands
//!
//! Command structures for AES operations

use crate::{CaliptraCommandId, CommandRequest, CommandResponse, CommonResponse};
use zerocopy::{FromBytes, Immutable, IntoBytes};

// Placeholder AES commands - implement as needed
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct AesInitRequest {
    // Implementation TBD
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct AesInitResponse {
    pub common: CommonResponse,
    // Implementation TBD
}

impl CommandRequest for AesInitRequest {
    type Response = AesInitResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::AesInit;
}

impl CommandResponse for AesInitResponse {}
