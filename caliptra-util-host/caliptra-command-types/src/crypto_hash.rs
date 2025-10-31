//! Cryptographic Hash Commands
//!
//! Command structures for SHA and HMAC operations

use crate::{CommandRequest, CommandResponse, CommonResponse, CaliptraCommandId};
use zerocopy::{AsBytes, FromBytes, FromZeroes};

// Placeholder hash commands - implement as needed
#[repr(C)]
#[derive(Debug, Clone, AsBytes, FromBytes, FromZeroes)]
pub struct HashInitRequest {
    // Implementation TBD
}

#[repr(C)]
#[derive(Debug, Clone, AsBytes, FromBytes, FromZeroes)]
pub struct HashInitResponse {
    pub common: CommonResponse,
    // Implementation TBD
}

impl CommandRequest for HashInitRequest {
    type Response = HashInitResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::HashInit;
}

impl CommandResponse for HashInitResponse {}