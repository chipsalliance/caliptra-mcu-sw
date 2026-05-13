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
    /// Streaming error (e.g., mailbox failure during chunk streaming).
    StreamError,
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

/// Trait for streaming large VDM request payloads directly to a backend
/// (e.g., Caliptra mailbox) without buffering the entire message.
///
/// When the SPDM CHUNK_SEND handler detects a streaming-eligible VDM command
/// in the first chunk, it calls these methods per-chunk instead of buffering
/// in `LargeMessageCtx`.
///
/// The VDM payload is expected to be in Caliptra RT mailbox format
/// (MailboxReqHeader + command-specific data), pre-built by the host with
/// checksum already computed.
#[async_trait]
pub trait VdmStreamHandler: Send + Sync {
    /// Check if a VDM command code supports streaming.
    /// Returns the mailbox command ID if streaming is supported, None otherwise.
    fn stream_supported(&self, vdm_command_code: u8) -> Option<u32>;

    /// Initialize a streaming session.
    /// Called with the first chunk's VDM payload data (mailbox command bytes).
    ///
    /// # Arguments
    /// * `mailbox_cmd` - The Caliptra RT mailbox command ID
    /// * `total_payload_len` - Total VDM payload length (excluding VDM headers)
    /// * `first_chunk_payload` - The VDM payload bytes from the first chunk
    async fn stream_init(
        &self,
        mailbox_cmd: u32,
        total_payload_len: usize,
        first_chunk_payload: &[u8],
    ) -> VdmResult<()>;

    /// Stream a subsequent chunk of VDM payload data.
    async fn stream_chunk(&self, chunk_data: &[u8]) -> VdmResult<()>;

    /// Finalize the streaming session and execute the mailbox command.
    /// Returns the response data length written to `rsp_buf`.
    async fn stream_finish(
        &self,
        mailbox_cmd: u32,
        rsp_buf: &mut [u8],
    ) -> VdmResult<usize>;

    /// Abort a streaming session (called on error).
    async fn stream_abort(&self);
}
