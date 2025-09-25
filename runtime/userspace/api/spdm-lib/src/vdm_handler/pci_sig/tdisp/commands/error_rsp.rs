// Licensed under the Apache-2.0 license

use crate::codec::{encode_u8_slice, Codec, CommonCodec, MessageBuf};
use crate::vdm_handler::pci_sig::tdisp::protocol::*;
use crate::vdm_handler::{VdmError, VdmResult};
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(FromBytes, IntoBytes, Immutable, Default)]
#[repr(C)]
struct ErrorResponsePayload {
    error_code: u32,
    error_data: u32,
}

impl CommonCodec for ErrorResponsePayload {}

pub(crate) fn generate_error_response(
    version: u8,
    interface_id: InterfaceId,
    error_code: TdispError,
    error_data: u32,
    ext_err_data: Option<&[u8]>,
    rsp_buf: &mut MessageBuf<'_>,
) -> VdmResult<usize> {
    // Reset any payload that is encoded so far
    rsp_buf.reset_payload();

    let payload = ErrorResponsePayload {
        error_code: error_code as u32,
        error_data,
    };
    let mut len = payload.encode(rsp_buf).map_err(VdmError::Codec)?;

    if let Some(ext_data) = ext_err_data {
        if !ext_data.is_empty() {
            len += encode_u8_slice(ext_data, rsp_buf).map_err(VdmError::Codec)?;
        }
    }

    // Encode header at the start of the buffer
    let rsp_hdr = TdispMessageHeader::new(version, TdispCommand::ErrorResponse, interface_id);
    len += rsp_hdr.encode(rsp_buf).map_err(VdmError::Codec)?;

    Ok(len)
}
