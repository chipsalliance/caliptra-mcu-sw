// Licensed under the Apache-2.0 license

//! STOP_INTERFACE command handler.

use caliptra_mcu_spdm_traits::{McuResult, SpdmPalAlloc};

use crate::pci_sig::tdisp::{TdispDriver, TdispHandlerResult, TdispResponder};
use caliptra_mcu_spdm_codec::vendor_defined::pci_sig::tdisp::{
    tdisp_error_code, TdiStatus, TdispMessageHeader, TDISP_ERROR_UNSPECIFIED,
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
    let result = tdisp
        .driver
        .stop_interface(req_hdr.interface_id.function_id, scratch)
        .await;

    // STOP ends tracking of the interface; the requester sends GET_TDISP_VERSION before
    // using it again. After a rejected STOP the TDI may still be CONFIG_LOCKED, RUN or
    // ERROR, so the interface and any pending LOCK nonce stay tracked unless the driver
    // reports CONFIG_UNLOCKED.
    let unlocked = match result {
        Ok(0) => true,
        _ => {
            let mut tdi_status = TdiStatus::Reserved;
            let query = tdisp
                .driver
                .get_device_interface_state(
                    req_hdr.interface_id.function_id,
                    scratch,
                    &mut tdi_status,
                )
                .await;
            query == Ok(0) && tdi_status == TdiStatus::ConfigUnlocked
        }
    };
    if unlocked {
        tdisp.state.release_interface(req_hdr.interface_id);
    }

    match result {
        Ok(0) => Ok(TdispHandlerResult::Response(0)),
        Ok(e) => Ok(TdispHandlerResult::Error(tdisp_error_code(e), 0)),
        Err(_) => Ok(TdispHandlerResult::Error(TDISP_ERROR_UNSPECIFIED, 0)),
    }
}
