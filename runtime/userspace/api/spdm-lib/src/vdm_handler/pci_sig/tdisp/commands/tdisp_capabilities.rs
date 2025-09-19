// Licensed under the Apache-2.0 license

use crate::codec::{Codec, MessageBuf};
use crate::error_response;
use crate::vdm_handler::pci_sig::tdisp::protocol::*;
use crate::vdm_handler::pci_sig::tdisp::{TdispCmdResult, TdispResponder};
use crate::vdm_handler::{VdmError, VdmResult};

pub(crate) async fn handle_get_tdisp_capabilities(
    tdisp_responder: &mut TdispResponder<'_>,
    req_buf: &mut MessageBuf<'_>,
    rsp_buf: &mut MessageBuf<'_>,
) -> VdmResult<TdispCmdResult> {
    let requester_caps = TdispReqCapabilities::decode(req_buf).map_err(VdmError::Codec)?;
    let mut responder_caps = TdispRespCapabilities::default();
    match tdisp_responder
        .driver
        .get_capabilities(requester_caps, &mut responder_caps)
        .await
    {
        Ok(0) => {
            let len = responder_caps.encode(rsp_buf).map_err(VdmError::Codec)?;
            rsp_buf.push_data(len).map_err(VdmError::Codec)?;
            Ok(TdispCmdResult::Response(len))
        }
        Ok(err_code) => error_response!(err_code.into()),
        Err(_) => error_response!(TdispError::Unspecified),
    }
}
