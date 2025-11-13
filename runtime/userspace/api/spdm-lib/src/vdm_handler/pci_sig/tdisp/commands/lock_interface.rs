// Licensed under the Apache-2.0 license

use crate::codec::{encode_u8_slice, Codec, MessageBuf};
use crate::error_response;
use crate::vdm_handler::pci_sig::tdisp::protocol::*;
use crate::vdm_handler::pci_sig::tdisp::{TdispCmdResult, TdispResponder};
use crate::vdm_handler::{VdmError, VdmResult};
use libapi_caliptra::crypto::rng::Rng;

pub(crate) async fn handle_lock_interface(
    tdisp_responder: &mut TdispResponder<'_>,
    req_hdr: &TdispMessageHeader,
    req_buf: &mut MessageBuf<'_>,
    rsp_buf: &mut MessageBuf<'_>,
) -> VdmResult<TdispCmdResult> {
    let interface_state = match tdisp_responder
        .state
        .interface_state_mut(req_hdr.interface_id)
    {
        Some(state) => state,
        None => return error_response!(TdispError::InvalidInterface),
    };

    let mut start_interface_nonce = [0u8; START_INTERFACE_NONCE_SIZE];
    if Rng::generate_random_number(&mut start_interface_nonce)
        .await
        .is_err()
    {
        return error_response!(TdispError::InsufficientEntropy);
    }

    interface_state.set_start_interface_nonce(Some(start_interface_nonce));

    let lock_interface_param = TdispLockInterfaceParam::decode(req_buf).map_err(VdmError::Codec)?;

    match tdisp_responder
        .driver
        .lock_interface(req_hdr.interface_id.function_id, lock_interface_param)
        .await
    {
        Ok(0) => {
            let len = encode_u8_slice(&start_interface_nonce, rsp_buf).map_err(VdmError::Codec)?;
            rsp_buf.push_data(len).map_err(VdmError::Codec)?;
            Ok(TdispCmdResult::Response(len))
        }
        Ok(err_code) => error_response!(err_code.into()),
        Err(_) => error_response!(TdispError::Unspecified),
    }
}
