// Licensed under the Apache-2.0 license

//! LOCK_INTERFACE command handler.

use mcu_spdm_lite_codec::errors::SPDM_UNSPECIFIED;
use mcu_spdm_lite_traits::{McuResult, SpdmPalAlloc};

use crate::pci_sig::tdisp::{TdispDriver, TdispHandlerResult, TdispResponder};
use mcu_spdm_lite_codec::vendor_defined::pci_sig::tdisp::{
    tdisp_error_code, TdispLockInterfaceParam, TdispMessageHeader, START_INTERFACE_NONCE_SIZE,
    TDISP_ERROR_INSUFFICIENT_ENTROPY, TDISP_ERROR_INVALID_INTERFACE, TDISP_ERROR_UNSPECIFIED,
    TDISP_HEADER_LEN,
};

pub(crate) async fn handle<D, Alloc>(
    tdisp: &TdispResponder<D>,
    req_hdr: TdispMessageHeader,
    req_payload: &[u8],
    scratch: &Alloc,
    out: &mut [u8],
) -> McuResult<TdispHandlerResult>
where
    D: TdispDriver,
    Alloc: SpdmPalAlloc,
{
    if tdisp.state.interface_state(req_hdr.interface_id).is_none() {
        return Ok(TdispHandlerResult::Error(TDISP_ERROR_INVALID_INTERFACE, 0));
    }

    let nonce = out
        .get_mut(TDISP_HEADER_LEN..TDISP_HEADER_LEN + START_INTERFACE_NONCE_SIZE)
        .ok_or(SPDM_UNSPECIFIED)?;
    let nonce: &mut [u8; START_INTERFACE_NONCE_SIZE] =
        nonce.try_into().map_err(|_| SPDM_UNSPECIFIED)?;
    if tdisp
        .driver
        .generate_start_interface_nonce(scratch, nonce)
        .await
        .is_err()
    {
        return Ok(TdispHandlerResult::Error(
            TDISP_ERROR_INSUFFICIENT_ENTROPY,
            0,
        ));
    }
    tdisp.state.set_nonce(req_hdr.interface_id, Some(*nonce));

    let param = TdispLockInterfaceParam::decode(req_payload)?;
    match tdisp
        .driver
        .lock_interface(req_hdr.interface_id.function_id, param, scratch)
        .await
    {
        Ok(0) => Ok(TdispHandlerResult::Response(START_INTERFACE_NONCE_SIZE)),
        Ok(e) => Ok(TdispHandlerResult::Error(tdisp_error_code(e), 0)),
        Err(_) => Ok(TdispHandlerResult::Error(TDISP_ERROR_UNSPECIFIED, 0)),
    }
}
