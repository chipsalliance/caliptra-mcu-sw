// Licensed under the Apache-2.0 license

pub mod pci_sig;

// Licensed under the Apache-2.0 license

extern crate alloc;

use crate::codec::{CodecError, MessageBuf};
use crate::protocol::*;
use alloc::boxed::Box;
use async_trait::async_trait;

#[derive(Debug, PartialEq)]
pub enum VdmError {
    InvalidVendorId,
    InvalidRequestPayload,
    UnsupportedProtocol,
    InvalidVdmCommand,
    SessionRequired,
    Codec(CodecError),
}

pub type VdmResult<T> = Result<T, VdmError>;

#[async_trait]
pub trait VdmResponder {
    async fn response_size(&self, req_buf: &mut MessageBuf<'_>) -> VdmResult<usize>;
    async fn handle_request(
        &self,
        req_buf: &mut MessageBuf<'_>,
        offset: usize,
        rsp_buf: &mut MessageBuf<'_>,
    ) -> VdmResult<()>;
}

pub trait VdmRegistryMatcher {
    fn match_id(
        &self,
        standard_id: StandardsBodyId,
        vendor_id: &[u8],
        secure_session: bool,
    ) -> bool;
}

pub trait VdmProtocolMatcher {
    fn match_protocol(&self, protocol_id: u8) -> bool;
}

pub trait VdmProtocolHandler: VdmResponder + VdmProtocolMatcher + Sync {}

pub trait VdmHandler: VdmResponder + VdmRegistryMatcher + Sync {}
