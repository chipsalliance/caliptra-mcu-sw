// Licensed under the Apache-2.0 license

extern crate alloc;

use crate::codec::{CodecError, MessageBuf};
use crate::protocol::*;
use crate::vdm_handler::iana::ocp::envelope_signed_csr_rsp::EnvelopeSignedCsrRspCtx;
use crate::vdm_handler::iana::ocp::get_eat_rsp::GetEatRspCtx;
use crate::vdm_handler::pci_sig::ide_km::driver::IdeDriverError;
use alloc::boxed::Box;
use async_trait::async_trait;

pub mod iana;
pub mod pci_sig;

#[derive(Debug, PartialEq)]
pub enum VdmLargeRespCtx {
    Unsupported,
    EnvelopeSignedCsr(EnvelopeSignedCsrRspCtx),
    Evidence(GetEatRspCtx),
}

#[derive(Debug, PartialEq)]
pub enum VdmError {
    InvalidVendorId,
    InvalidRequestPayload,
    UnsupportedProtocol,
    InvalidVdmCommand,
    SessionRequired,
    UnsupportedRequest,
    Codec(CodecError),
    LargeResp(usize, VdmLargeRespCtx),
    IdeKmDriver(IdeDriverError),
}

pub type VdmResult<T> = Result<T, VdmError>;

#[async_trait]
pub trait VdmResponder {
    async fn handle_request(
        &mut self,
        req_buf: &mut MessageBuf<'_>,
        rsp_buf: &mut MessageBuf<'_>,
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
