// Licensed under the Apache-2.0 license

use crate::codec::{Codec, MessageBuf};
use crate::error_response;
use crate::vdm_handler::pci_sig::tdisp::protocol::*;
use crate::vdm_handler::pci_sig::tdisp::{TdispCmdResult, TdispResponder};
use crate::vdm_handler::{VdmError, VdmResult};

pub(crate) fn handle_get_tdisp_version(
    tdisp_responder: &mut TdispResponder<'_>,
    req_hdr: &TdispMessageHeader,
    rsp_buf: &mut MessageBuf<'_>,
) -> VdmResult<TdispCmdResult> {
    let interface_id = req_hdr.interface_id;
    if !tdisp_responder.state.init_interface(interface_id) {
        return error_response!(TdispError::InvalidInterface);
    }

    let version_count = tdisp_responder.supported_versions.len() as u8;
    let mut len = version_count.encode(rsp_buf).map_err(VdmError::Codec)?;
    for version in tdisp_responder.supported_versions {
        len += version.to_u8().encode(rsp_buf).map_err(VdmError::Codec)?;
    }

    rsp_buf.push_data(len).map_err(VdmError::Codec)?;

    Ok(TdispCmdResult::Response(len))
}
