// Licensed under the Apache-2.0 license

use crate::error_response;
use crate::vdm_handler::pci_sig::tdisp::protocol::*;
use crate::vdm_handler::pci_sig::tdisp::{TdispCmdResult, TdispResponder};
use crate::vdm_handler::VdmResult;

pub(crate) async fn handle_stop_interface_request(
    tdisp_responder: &mut TdispResponder<'_>,
    req_hdr: &TdispMessageHeader,
) -> VdmResult<TdispCmdResult> {
    let function_id = req_hdr.interface_id.function_id;

    match tdisp_responder.driver.stop_interface(function_id).await {
        Ok(0) => Ok(TdispCmdResult::Response(0)),
        Ok(err_code) => error_response!(err_code.into()),
        Err(_) => error_response!(TdispError::Unspecified),
    }
}
