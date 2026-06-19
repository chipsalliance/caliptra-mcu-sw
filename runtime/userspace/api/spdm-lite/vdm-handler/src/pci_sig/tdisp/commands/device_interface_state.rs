// Licensed under the Apache-2.0 license

//! GET_DEVICE_INTERFACE_STATE command handler.

use mcu_spdm_lite_codec::errors::SPDM_UNSPECIFIED;
use mcu_spdm_lite_traits::{McuResult, SpdmPalAlloc, SpdmPalIo};

use crate::pci_sig::tdisp::protocol::{
    tdisp_error_code, TdiStatus, TdispMessageHeader, TDISP_ERROR_INVALID_INTERFACE_STATE,
    TDISP_ERROR_UNSPECIFIED, TDISP_HEADER_LEN,
};
use crate::pci_sig::tdisp::{TdispDriver, TdispHandlerResult, TdispResponder};

pub(crate) async fn handle<D, Alloc, Io>(
    tdisp: &TdispResponder<D>,
    req_hdr: TdispMessageHeader,
    scratch: &Alloc,
    io: &Io,
    out: &mut [u8],
) -> McuResult<TdispHandlerResult>
where
    D: TdispDriver,
    Alloc: SpdmPalAlloc,
    Io: SpdmPalIo,
{
    let mut tdi_status = TdiStatus::Reserved;
    match tdisp
        .driver
        .get_device_interface_state(
            req_hdr.interface_id.function_id,
            scratch,
            io,
            &mut tdi_status,
        )
        .await
    {
        Ok(0) if tdi_status != TdiStatus::Reserved => {
            *out.get_mut(TDISP_HEADER_LEN).ok_or(SPDM_UNSPECIFIED)? = tdi_status as u8;
            Ok(TdispHandlerResult::Response(1))
        }
        Ok(0) => Ok(TdispHandlerResult::Error(
            TDISP_ERROR_INVALID_INTERFACE_STATE,
            0,
        )),
        Ok(e) => Ok(TdispHandlerResult::Error(tdisp_error_code(e), 0)),
        Err(_) => Ok(TdispHandlerResult::Error(TDISP_ERROR_UNSPECIFIED, 0)),
    }
}
