// Licensed under the Apache-2.0 license

//! GET_TDISP_VERSION command handler.

use caliptra_mcu_spdm_codec::errors::SPDM_UNSPECIFIED;
use caliptra_mcu_spdm_traits::McuResult;

use crate::pci_sig::tdisp::{TdispHandlerResult, TdispResponder};
use caliptra_mcu_spdm_codec::vendor_defined::pci_sig::tdisp::{
    TdispMessageHeader, TDISP_ERROR_INVALID_INTERFACE, TDISP_HEADER_LEN,
};

pub(crate) fn handle<D>(
    tdisp: &TdispResponder<D>,
    req_hdr: TdispMessageHeader,
    out: &mut [u8],
) -> McuResult<TdispHandlerResult> {
    if !tdisp.state.init_interface(req_hdr.interface_id) {
        return Ok(TdispHandlerResult::Error(TDISP_ERROR_INVALID_INTERFACE, 0));
    }

    let payload = out.get_mut(TDISP_HEADER_LEN..).ok_or(SPDM_UNSPECIFIED)?;
    let needed = 1usize
        .checked_add(tdisp.supported_versions.len())
        .ok_or(SPDM_UNSPECIFIED)?;
    let payload = payload.get_mut(..needed).ok_or(SPDM_UNSPECIFIED)?;
    payload[0] = tdisp.supported_versions.len() as u8;
    for (dst, version) in payload[1..].iter_mut().zip(tdisp.supported_versions.iter()) {
        *dst = version.to_u8();
    }
    Ok(TdispHandlerResult::Response(needed))
}
