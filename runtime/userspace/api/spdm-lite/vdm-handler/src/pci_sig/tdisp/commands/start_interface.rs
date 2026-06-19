// Licensed under the Apache-2.0 license

//! START_INTERFACE command handler.

use mcu_spdm_lite_traits::{McuResult, SpdmPalAlloc, SpdmPalIo};

use crate::pci_sig::tdisp::protocol::{
    ct_eq, tdisp_error_code, TdispMessageHeader, TDISP_ERROR_INVALID_INTERFACE,
    TDISP_ERROR_INVALID_INTERFACE_STATE, TDISP_ERROR_UNSPECIFIED,
};
use crate::pci_sig::tdisp::{TdispDriver, TdispHandlerResult, TdispResponder};

pub(crate) async fn handle<D, Alloc, Io>(
    tdisp: &TdispResponder<D>,
    req_hdr: TdispMessageHeader,
    req_payload: &[u8],
    scratch: &Alloc,
    io: &Io,
) -> McuResult<TdispHandlerResult>
where
    D: TdispDriver,
    Alloc: SpdmPalAlloc,
    Io: SpdmPalIo,
{
    let Some(interface_state) = tdisp.state.interface_state(req_hdr.interface_id) else {
        return Ok(TdispHandlerResult::Error(TDISP_ERROR_INVALID_INTERFACE, 0));
    };
    let Some(expected_nonce) = interface_state.start_interface_nonce else {
        return Ok(TdispHandlerResult::Error(
            TDISP_ERROR_INVALID_INTERFACE_STATE,
            0,
        ));
    };
    if !ct_eq(&expected_nonce, req_payload) {
        return Ok(TdispHandlerResult::Error(
            TDISP_ERROR_INVALID_INTERFACE_STATE,
            0,
        ));
    }
    match tdisp
        .driver
        .start_interface(req_hdr.interface_id.function_id, scratch, io)
        .await
    {
        Ok(0) => {
            tdisp.state.set_nonce(req_hdr.interface_id, None);
            Ok(TdispHandlerResult::Response(0))
        }
        Ok(e) => Ok(TdispHandlerResult::Error(tdisp_error_code(e), 0)),
        Err(_) => Ok(TdispHandlerResult::Error(TDISP_ERROR_UNSPECIFIED, 0)),
    }
}
