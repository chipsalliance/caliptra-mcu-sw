// Licensed under the Apache-2.0 license

//! GET_TDISP_CAPABILITIES command handler.

use mcu_spdm_lite_codec::errors::SPDM_UNSPECIFIED;
use mcu_spdm_lite_traits::{McuResult, SpdmPalAlloc};

use crate::pci_sig::tdisp::{TdispDriver, TdispHandlerResult, TdispResponder};
use mcu_spdm_lite_codec::vendor_defined::pci_sig::tdisp::{
    tdisp_error_code, TdispMessageHeader, TdispReqCapabilities, TdispRespCapabilities,
    TDISP_CAPS_RSP_LEN, TDISP_ERROR_UNSPECIFIED, TDISP_HEADER_LEN,
};

pub(crate) async fn handle<D, Alloc>(
    tdisp: &TdispResponder<D>,
    _req_hdr: TdispMessageHeader,
    req_payload: &[u8],
    scratch: &Alloc,
    out: &mut [u8],
) -> McuResult<TdispHandlerResult>
where
    D: TdispDriver,
    Alloc: SpdmPalAlloc,
{
    let req_caps = TdispReqCapabilities::decode(req_payload)?;
    let mut rsp_caps = TdispRespCapabilities::default();
    match tdisp
        .driver
        .get_capabilities(req_caps, scratch, &mut rsp_caps)
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
