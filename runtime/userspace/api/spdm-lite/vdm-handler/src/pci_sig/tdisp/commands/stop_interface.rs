// Licensed under the Apache-2.0 license

//! STOP_INTERFACE command handler.

use mcu_spdm_lite_traits::{McuResult, SpdmPalAlloc, SpdmPalIo};

use crate::pci_sig::tdisp::protocol::{
    tdisp_error_code, TdispMessageHeader, TDISP_ERROR_UNSPECIFIED,
};
use crate::pci_sig::tdisp::{TdispDriver, TdispHandlerResult, TdispResponder};

pub(crate) async fn handle<D, Alloc, Io>(
    tdisp: &TdispResponder<D>,
    req_hdr: TdispMessageHeader,
    scratch: &Alloc,
    io: &Io,
) -> McuResult<TdispHandlerResult>
where
    D: TdispDriver,
    Alloc: SpdmPalAlloc,
    Io: SpdmPalIo,
{
    match tdisp
        .driver
        .stop_interface(req_hdr.interface_id.function_id, scratch, io)
        .await
    {
        Ok(0) => Ok(TdispHandlerResult::Response(0)),
        Ok(e) => Ok(TdispHandlerResult::Error(tdisp_error_code(e), 0)),
        Err(_) => Ok(TdispHandlerResult::Error(TDISP_ERROR_UNSPECIFIED, 0)),
    }
}
