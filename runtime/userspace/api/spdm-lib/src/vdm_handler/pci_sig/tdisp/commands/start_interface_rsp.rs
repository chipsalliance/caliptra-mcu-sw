// Licensed under the Apache-2.0 license

use crate::codec::{decode_u8_slice, MessageBuf};
use crate::error_response;
use crate::vdm_handler::pci_sig::tdisp::protocol::*;
use crate::vdm_handler::pci_sig::tdisp::state::START_INTERFACE_NONCE_SIZE;
use crate::vdm_handler::pci_sig::tdisp::{TdispCmdResult, TdispResponder};
use crate::vdm_handler::{VdmError, VdmResult};
use constant_time_eq::constant_time_eq;

pub(crate) async fn handle_start_interface_request(
    tdisp_responder: &mut TdispResponder<'_>,
    req_hdr: &TdispMessageHeader,
    req_buf: &mut MessageBuf<'_>,
) -> VdmResult<TdispCmdResult> {
    let mut start_intf_nonce = [0u8; START_INTERFACE_NONCE_SIZE];
    decode_u8_slice(req_buf, &mut start_intf_nonce).map_err(VdmError::Codec)?;

    let interface_id = req_hdr.interface_id;

    let intf_state = match tdisp_responder.state.interface_state_mut(interface_id) {
        Some(state) => state,
        None => return error_response!(TdispError::InvalidInterface),
    };

    let local_start_interface_nonce = match intf_state.start_interface_nonce() {
        Some(nonce) => nonce,
        None => return error_response!(TdispError::InvalidInterfaceState),
    };

    if !constant_time_eq(local_start_interface_nonce, &start_intf_nonce) {
        return error_response!(TdispError::InvalidInterfaceState);
    }

    match tdisp_responder
        .driver
        .start_interface(interface_id.function_id)
        .await
    {
        Ok(0) => {
            intf_state.set_start_interface_nonce(None);
            Ok(TdispCmdResult::Response(0))
        }
        Ok(err_code) => error_response!(err_code.into()),
        Err(_) => error_response!(TdispError::Unspecified),
    }
}
