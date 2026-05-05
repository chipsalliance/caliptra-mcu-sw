// Licensed under the Apache-2.0 license

extern crate alloc;
use alloc::boxed::Box;

use crate::codec::{CodecError, MessageBuf};
use crate::protocol::*;
use crate::vdm_handler::pci_sig::ide_km::driver::IdeDriverError;
use crate::vdm_handler::pci_sig::tdisp::driver::TdispDriverError;
use async_trait::async_trait;

pub mod iana;
pub mod pci_sig;

#[derive(Debug, PartialEq)]
pub enum VdmError {
    InvalidVendorId,
    InvalidRequestPayload,
    UnsupportedProtocol,
    InvalidVdmCommand,
    SessionRequired,
    UnsupportedRequest,
    UnsupportedTdispVersion,
    Codec(CodecError),
    /// Response is too large for the inline buffer. The handler has written
    /// the payload into the provided `large_rsp_buf`. The usize is the number
    /// of bytes written into that buffer.
    LargeResp(usize),
    Ide(IdeDriverError),
    Tdisp(TdispDriverError),
}

pub type VdmResult<T> = Result<T, VdmError>;

#[async_trait]
pub trait VdmResponder {
    /// Handle a VDM request and produce a response.
    ///
    /// # Arguments
    /// * `req_buf` - The decoded VDM request payload
    /// * `rsp_buf` - Buffer for inline (small) responses
    /// * `large_rsp_buf` - Shared buffer for large responses that exceed `rsp_buf` capacity.
    ///   On `Err(VdmError::LargeResp(n))`, the handler has written `n` bytes here.
    ///   Handlers that never produce large responses may ignore this parameter.
    ///
    /// # Returns
    /// `Ok(len)` for inline responses, or `Err(VdmError::LargeResp(n))` for large responses.
    async fn handle_request(
        &mut self,
        req_buf: &mut MessageBuf<'_>,
        rsp_buf: &mut MessageBuf<'_>,
        large_rsp_buf: &mut [u8],
    ) -> VdmResult<usize>;
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

pub trait VdmProtocolHandler: VdmResponder + VdmProtocolMatcher + Send + Sync {}

pub trait VdmHandler: VdmResponder + VdmRegistryMatcher + Send + Sync {}
