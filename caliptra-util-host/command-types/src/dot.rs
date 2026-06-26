// Licensed under the Apache-2.0 license

//! Device Ownership Transfer commands.

use crate::{CaliptraCommandId, CommandRequest, CommandResponse, CommonResponse};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Size of the DOT_BLOB authenticated by the ROM DOT flow.
pub const DOT_BLOB_SIZE: usize = 168;

/// Get DOT backup blob request.
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct GetDotBackupBlobRequest {
    // Empty request.
}

/// Get DOT backup blob response.
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct GetDotBackupBlobResponse {
    pub common: CommonResponse,
    pub blob: [u8; DOT_BLOB_SIZE],
}

impl CommandRequest for GetDotBackupBlobRequest {
    type Response = GetDotBackupBlobResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::GetDotBackupBlob;
}

impl CommandResponse for GetDotBackupBlobResponse {}
