// Licensed under the Apache-2.0 license

//! GET_DEVICE_INTERFACE_REPORT command handler.

use caliptra_mcu_spdm_codec::errors::SPDM_UNSPECIFIED;
use caliptra_mcu_spdm_traits::{McuResult, SpdmPalAlloc};

use crate::pci_sig::tdisp::{TdispDriver, TdispHandlerResult, TdispResponder};
use caliptra_mcu_spdm_codec::vendor_defined::pci_sig::tdisp::{
    tdisp_error_code, DeviceInterfaceReportReq, TdispMessageHeader,
    DEVICE_INTERFACE_REPORT_RSP_HDR_LEN, TDISP_ERROR_INVALID_INTERFACE,
    TDISP_ERROR_INVALID_REQUEST, TDISP_ERROR_UNSPECIFIED, TDISP_HEADER_LEN,
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
    let req = DeviceInterfaceReportReq::decode(req_payload)?;

    let mut report_len = 0u16;
    match tdisp
        .driver
        .get_device_interface_report_len(req_hdr.interface_id.function_id, scratch, &mut report_len)
        .await
    {
        Ok(0) if req.offset as usize >= report_len as usize => {
            return Ok(TdispHandlerResult::Error(TDISP_ERROR_INVALID_REQUEST, 0));
        }
        Ok(0) => {}
        Ok(e) => return Ok(TdispHandlerResult::Error(tdisp_error_code(e), 0)),
        Err(_) => return Ok(TdispHandlerResult::Error(TDISP_ERROR_UNSPECIFIED, 0)),
    }

    let payload = out.get_mut(TDISP_HEADER_LEN..).ok_or(SPDM_UNSPECIFIED)?;
    let max_report = payload
        .len()
        .checked_sub(DEVICE_INTERFACE_REPORT_RSP_HDR_LEN)
        .ok_or(SPDM_UNSPECIFIED)?;
    let max_report = max_report.min(u16::MAX as usize) as u16;
    let remaining = report_len.saturating_sub(req.offset);
    let portion = remaining.min(req.length).min(max_report);
    let rsp_hdr = payload
        .get_mut(..DEVICE_INTERFACE_REPORT_RSP_HDR_LEN)
        .ok_or(SPDM_UNSPECIFIED)?;
    rsp_hdr[0..2].copy_from_slice(&portion.to_le_bytes());
    rsp_hdr[2..4].copy_from_slice(&remaining.saturating_sub(portion).to_le_bytes());

    let portion = portion as usize;
    let report_portion = payload
        .get_mut(DEVICE_INTERFACE_REPORT_RSP_HDR_LEN..DEVICE_INTERFACE_REPORT_RSP_HDR_LEN + portion)
        .ok_or(SPDM_UNSPECIFIED)?;

    let mut copied = 0usize;
    match tdisp
        .driver
        .get_device_interface_report(
            req_hdr.interface_id.function_id,
            req.offset,
            scratch,
            report_portion,
            &mut copied,
        )
        .await
    {
        Ok(0) if copied == portion => Ok(TdispHandlerResult::Response(
            DEVICE_INTERFACE_REPORT_RSP_HDR_LEN + copied,
        )),
        Ok(0) => Ok(TdispHandlerResult::Error(TDISP_ERROR_UNSPECIFIED, 0)),
        Ok(e) => Ok(TdispHandlerResult::Error(tdisp_error_code(e), 0)),
        Err(_) => Ok(TdispHandlerResult::Error(TDISP_ERROR_UNSPECIFIED, 0)),
    }
}
