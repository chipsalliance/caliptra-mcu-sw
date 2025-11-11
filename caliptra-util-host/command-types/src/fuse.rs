// Licensed under the Apache-2.0 license

//! Fuse Commands
//!
//! Command structures for fuse operations

use crate::{CaliptraCommandId, CommandRequest, CommandResponse, CommonResponse};
use zerocopy::{FromBytes, Immutable, IntoBytes};

// Placeholder fuse commands - implement as needed
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct FuseReadRequest {
    // Implementation TBD
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct FuseReadResponse {
    pub common: CommonResponse,
    // Implementation TBD
}

impl CommandRequest for FuseReadRequest {
    type Response = FuseReadResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::FuseRead;
}

impl CommandResponse for FuseReadResponse {}
