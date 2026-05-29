// Licensed under the Apache-2.0 license

//! PCI-SIG VDM top-level dispatch for SPDM-Lite.

pub mod tdisp;

use crate::{
    SpdmResult, SpdmVdmBackend, StandardsBodyId, VdmRequest, VdmResponseBuffers, VdmResponseKind,
    SPDM_INVALID_REQUEST, SPDM_UNSPECIFIED, SPDM_UNSUPPORTED_REQUEST,
};

/// PCI-SIG protocol identifier for IDE-KM.
pub const IDE_KM_PROTOCOL_ID: u8 = 0x00;
/// PCI-SIG protocol identifier for TDISP.
pub const TDISP_PROTOCOL_ID: u8 = 0x01;

/// PCI-SIG VDM backend that dispatches protocol-id `0x01` to TDISP.
///
/// The first byte of the PCI-SIG VDM payload is the PCI-SIG protocol id.  This
/// backend preserves that top-level byte and delegates the remaining payload to
/// the size-conscious TDISP responder.
pub struct PciSigTdispVdm<D> {
    vendor_id: u16,
    tdisp: tdisp::TdispResponder<D>,
}

impl<D> PciSigTdispVdm<D> {
    /// Creates a PCI-SIG/TISP VDM backend for `vendor_id`.
    pub const fn new(vendor_id: u16, tdisp: tdisp::TdispResponder<D>) -> Self {
        Self { vendor_id, tdisp }
    }

    #[inline]
    fn matches_envelope(&self, req: &VdmRequest<'_>) -> bool {
        req.standard_id == StandardsBodyId::PciSig
            && req.vendor_id == self.vendor_id.to_le_bytes()
            && req.secure_session
    }
}

impl<D> SpdmVdmBackend for PciSigTdispVdm<D>
where
    D: tdisp::TdispDriver,
{
    fn match_request(&self, req: &VdmRequest<'_>) -> bool {
        self.matches_envelope(req) && req.payload.first().copied() == Some(TDISP_PROTOCOL_ID)
    }

    async fn handle_request(
        &self,
        req: VdmRequest<'_>,
        rsp: VdmResponseBuffers<'_>,
    ) -> SpdmResult<VdmResponseKind> {
        if !self.matches_envelope(&req) {
            return Err(SPDM_UNSUPPORTED_REQUEST);
        }
        let Some((&protocol_id, payload)) = req.payload.split_first() else {
            return Err(SPDM_INVALID_REQUEST);
        };
        if protocol_id != TDISP_PROTOCOL_ID {
            return Err(SPDM_UNSUPPORTED_REQUEST);
        }
        let inline = rsp.inline;
        let Some(tdisp_inline) = inline.get_mut(1..) else {
            return Err(SPDM_UNSPECIFIED);
        };
        let response = self
            .tdisp
            .handle_tdisp_payload(payload, tdisp_inline)
            .await?;
        match response {
            VdmResponseKind::Inline(len) => {
                inline[0] = protocol_id;
                Ok(VdmResponseKind::Inline(len + 1))
            }
            VdmResponseKind::Large(_) => Err(SPDM_UNSPECIFIED),
        }
    }
}
