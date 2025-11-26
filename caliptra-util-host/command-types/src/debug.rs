// Licensed under the Apache-2.0 license

//! Debug Commands
//!
//! Command structures for debugging and diagnostics

use crate::{CaliptraCommandId, CommandRequest, CommandResponse, CommonResponse};
use zerocopy::{FromBytes, Immutable, IntoBytes};

// Placeholder debug commands - implement as needed
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct DebugEchoRequest {
    // Implementation TBD
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct DebugEchoResponse {
    pub common: CommonResponse,
    // Implementation TBD
}

impl CommandRequest for DebugEchoRequest {
    type Response = DebugEchoResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::DebugEcho;
}

impl CommandResponse for DebugEchoResponse {}
