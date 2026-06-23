// Licensed under the Apache-2.0 license

//! STOP_INTERFACE command handler.

use mcu_spdm_lite_traits::{McuResult, SpdmPalAlloc};

use crate::pci_sig::tdisp::{TdispDriver, TdispHandlerResult, TdispResponder};
use mcu_spdm_lite_codec::vendor_defined::pci_sig::tdisp::{
    tdisp_error_code, TdispMessageHeader, TDISP_ERROR_UNSPECIFIED,
};

pub(crate) async fn handle<D, Alloc>(
    tdisp: &TdispResponder<D>,
    req_hdr: TdispMessageHeader,
    scratch: &Alloc,
) -> McuResult<TdispHandlerResult>
where
    D: TdispDriver,
    Alloc: SpdmPalAlloc,
{
    match tdisp
        .driver
        .stop_interface(req_hdr.interface_id.function_id, scratch)
        .await
    {
        Ok(0) => Ok(TdispHandlerResult::Response(0)),
        Ok(e) => Ok(TdispHandlerResult::Error(tdisp_error_code(e), 0)),
        Err(_) => Ok(TdispHandlerResult::Error(TDISP_ERROR_UNSPECIFIED, 0)),
    }
}
