// Licensed under the Apache-2.0 license

//! GET_TDISP_CAPABILITIES command handler.

use mcu_spdm_lite_codec::errors::SPDM_UNSPECIFIED;
use mcu_spdm_lite_traits::{McuResult, SpdmPalAlloc, SpdmPalIo};

use crate::pci_sig::tdisp::protocol::{
    tdisp_error_code, TdispMessageHeader, TdispReqCapabilities, TdispRespCapabilities,
    TDISP_CAPS_RSP_LEN, TDISP_ERROR_UNSPECIFIED, TDISP_HEADER_LEN,
};
use crate::pci_sig::tdisp::{TdispDriver, TdispHandlerResult, TdispResponder};

pub(crate) async fn handle<D, Alloc, Io>(
    tdisp: &TdispResponder<D>,
    _req_hdr: TdispMessageHeader,
    req_payload: &[u8],
    scratch: &Alloc,
    io: &Io,
    out: &mut [u8],
) -> McuResult<TdispHandlerResult>
where
    D: TdispDriver,
    Alloc: SpdmPalAlloc,
    Io: SpdmPalIo,
{
    let req_caps = TdispReqCapabilities::decode(req_payload)?;
    let mut rsp_caps = TdispRespCapabilities::default();
    match tdisp
        .driver
        .get_capabilities(req_caps, scratch, io, &mut rsp_caps)
        .await
    {
        Ok(0) => {
            rsp_caps.encode(
                out.get_mut(TDISP_HEADER_LEN..TDISP_HEADER_LEN + TDISP_CAPS_RSP_LEN)
                    .ok_or(SPDM_UNSPECIFIED)?,
            )?;
            Ok(TdispHandlerResult::Response(TDISP_CAPS_RSP_LEN))
        }
        Ok(e) => Ok(TdispHandlerResult::Error(tdisp_error_code(e), 0)),
        Err(_) => Ok(TdispHandlerResult::Error(TDISP_ERROR_UNSPECIFIED, 0)),
    }
}
