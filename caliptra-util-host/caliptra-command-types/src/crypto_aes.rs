//! AES and Symmetric Crypto Commands
//!
//! Command structures for AES operations

use crate::{CommandRequest, CommandResponse, CommonResponse, CaliptraCommandId};
use zerocopy::{AsBytes, FromBytes, FromZeroes};

// Placeholder AES commands - implement as needed
#[repr(C)]
#[derive(Debug, Clone, AsBytes, FromBytes, FromZeroes)]
pub struct AesInitRequest {
    // Implementation TBD
}

#[repr(C)]
#[derive(Debug, Clone, AsBytes, FromBytes, FromZeroes)]
pub struct AesInitResponse {
    pub common: CommonResponse,
    // Implementation TBD
}

impl CommandRequest for AesInitRequest {
    type Response = AesInitResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::AesInit;
}

impl CommandResponse for AesInitResponse {}