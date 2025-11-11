// Licensed under the Apache-2.0 license

//! Asymmetric Crypto Commands
//!
//! Command structures for ECDSA, ECDH, LMS operations

use crate::{CaliptraCommandId, CommandRequest, CommandResponse, CommonResponse};
use zerocopy::{FromBytes, Immutable, IntoBytes};

// Placeholder asymmetric crypto commands - implement as needed
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct EcdsaSignRequest {
    // Implementation TBD
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct EcdsaSignResponse {
    pub common: CommonResponse,
    // Implementation TBD
}

impl CommandRequest for EcdsaSignRequest {
    type Response = EcdsaSignResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::EcdsaSign;
}

impl CommandResponse for EcdsaSignResponse {}
