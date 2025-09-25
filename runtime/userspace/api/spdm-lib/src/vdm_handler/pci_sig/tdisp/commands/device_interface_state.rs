// Licensed under the Apache-2.0 license

use crate::codec::{Codec, MessageBuf};
use crate::error_response;
use crate::vdm_handler::pci_sig::tdisp::protocol::*;
use crate::vdm_handler::pci_sig::tdisp::{TdispCmdResult, TdispResponder};
use crate::vdm_handler::{VdmError, VdmResult};

pub(crate) async fn handle_get_device_interface_state(
    tdisp_responder: &mut TdispResponder<'_>,
    req_hdr: &TdispMessageHeader,
    rsp_buf: &mut MessageBuf<'_>,
) -> VdmResult<TdispCmdResult> {
    let function_id = req_hdr.interface_id.function_id;
    let mut tdi_status = TdiStatus::Reserved;

    match tdisp_responder
        .driver
        .get_device_interface_state(function_id, &mut tdi_status)
        .await
    {
        Ok(0) => {
            if tdi_status != TdiStatus::Reserved {
                let state_val = tdi_status as u8;
                let len = state_val.encode(rsp_buf).map_err(VdmError::Codec)?;
                rsp_buf.push_data(len).map_err(VdmError::Codec)?;
                Ok(TdispCmdResult::Response(len))
            } else {
                error_response!(TdispError::InvalidInterfaceState)
            }
        }
        Ok(e) => error_response!(e.into()),
        Err(_) => error_response!(TdispError::Unspecified),
    }
}
