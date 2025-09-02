// Licensed under the Apache-2.0 license

extern crate alloc;

use crate::codec::{Codec, MessageBuf};
use crate::protocol::*;
use crate::vdm_handler::{
    VdmError, VdmHandler, VdmProtocolHandler, VdmProtocolMatcher, VdmRegistryMatcher, VdmResponder,
    VdmResult,
};
use alloc::boxed::Box;
use async_trait::async_trait;

pub mod ide_km;
pub mod tdisp;

pub const MAX_PCI_SIG_PROTOCOLS: usize = 2; // IDE-KM and TDISP

enum ProtocolId {
    IdeKm = 0x00,
    Tdisp = 0x01,
}

impl TryFrom<u8> for ProtocolId {
    type Error = VdmError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if x == ProtocolId::IdeKm as u8 => Ok(ProtocolId::IdeKm),
            x if x == ProtocolId::Tdisp as u8 => Ok(ProtocolId::Tdisp),
            _ => Err(VdmError::UnsupportedProtocol),
        }
    }
}

pub struct PciSigCmdHandler<'a> {
    vendor_id: u16,
    protocol_handlers: [Option<&'a (dyn VdmProtocolHandler + Sync)>; MAX_PCI_SIG_PROTOCOLS],
}

impl<'a> VdmRegistryMatcher for PciSigCmdHandler<'a> {
    fn match_id(
        &self,
        standard_id: StandardsBodyId,
        vendor_id: &[u8],
        secure_session: bool,
    ) -> bool {
        standard_id == StandardsBodyId::PciSig
            && vendor_id == &self.vendor_id.to_le_bytes()
            && secure_session
    }
}

impl<'a> PciSigCmdHandler<'a> {
    fn new(
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
impl<'a> VdmResponder for PciSigCmdHandler<'a> {
    async fn response_size(&self, req_buf: &mut MessageBuf<'_>) -> VdmResult<usize> {
        let protocol_id = u8::decode(req_buf).map_err(VdmError::Codec)?;
        for handler in self.protocol_handlers {
            if let Some(handler) = handler {
                if handler.match_protocol(protocol_id) {
                    return handler.response_size(req_buf).await;
                }
            }
        }
        Err(VdmError::UnsupportedProtocol)
    }

    async fn handle_request(
        &self,
        req_buf: &mut MessageBuf<'_>,
        offset: usize,
        rsp_buf: &mut MessageBuf<'_>,
    ) -> VdmResult<()> {
        let protocol_id = u8::decode(req_buf).map_err(VdmError::Codec)?;
        for handler in self.protocol_handlers {
            if let Some(handler) = handler {
                if handler.match_protocol(protocol_id) {
                    return handler.handle_request(req_buf, offset, rsp_buf).await;
                }
            }
        }
        Err(VdmError::UnsupportedProtocol)
    }
}
