// Licensed under the Apache-2.0 license

//! Cryptographic Hash Commands
//!
//! Command structures for SHA and HMAC operations

use crate::{CaliptraCommandId, CommandRequest, CommandResponse, CommonResponse};
use zerocopy::{FromBytes, Immutable, IntoBytes};

// Placeholder hash commands - implement as needed
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct HashInitRequest {
    // Implementation TBD
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct HashInitResponse {
    pub common: CommonResponse,
    // Implementation TBD
}

impl CommandRequest for HashInitRequest {
    type Response = HashInitResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::HashInit;
}

impl CommandResponse for HashInitResponse {}
