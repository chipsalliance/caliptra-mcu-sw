// Licensed under the Apache-2.0 license

extern crate alloc;

use crate::codec::{Codec, CommonCodec, MessageBuf};
use crate::protocol::*;
use crate::vdm_handler::{
    VdmError, VdmProtocolHandler, VdmRegistryMatcher, VdmResponder, VdmResult,
};
use alloc::boxed::Box;
use async_trait::async_trait;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub mod ide_km;
pub mod tdisp;

pub const MAX_PCI_SIG_PROTOCOLS: usize = 2; // IDE-KM and TDISP

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub(crate) struct PciSigProtocolHdr {
    pub(crate) protocol_id: u8,
}

impl CommonCodec for PciSigProtocolHdr {}

pub struct PciSigCmdHandler<'a> {
    vendor_id: u16,
    protocol_handlers: [Option<&'a (dyn VdmProtocolHandler + Sync)>; MAX_PCI_SIG_PROTOCOLS],
}

impl VdmRegistryMatcher for PciSigCmdHandler<'_> {
    fn match_id(
        &self,
        standard_id: StandardsBodyId,
        vendor_id: &[u8],
        secure_session: bool,
    ) -> bool {
        standard_id == StandardsBodyId::PciSig
            && vendor_id == self.vendor_id.to_le_bytes()
            && secure_session
    }
}

impl<'a> PciSigCmdHandler<'a> {
    #[allow(dead_code)]
    pub fn new(
        vendor_id: u16,
        protocol_handlers: [Option<&'a (dyn VdmProtocolHandler + Sync)>; MAX_PCI_SIG_PROTOCOLS],
    ) -> Self {
        PciSigCmdHandler {
            vendor_id,
            protocol_handlers,
        }
    }
}

#[async_trait]
impl VdmResponder for PciSigCmdHandler<'_> {
    async fn handle_request(
        &self,
        req_buf: &mut MessageBuf<'_>,
        rsp_buf: &mut MessageBuf<'_>,
    ) -> VdmResult<usize> {
        let pcisig_hdr = PciSigProtocolHdr::decode(req_buf).map_err(VdmError::Codec)?;
        let protocol_id = pcisig_hdr.protocol_id;

        for handler in self.protocol_handlers.into_iter().flatten() {
            if handler.match_protocol(protocol_id) {
                let mut len = protocol_id.encode(rsp_buf).map_err(VdmError::Codec)?;
                len += handler.handle_request(req_buf, rsp_buf).await?;
                return Ok(len);
            }
        }
        Err(VdmError::UnsupportedProtocol)
    }
}
