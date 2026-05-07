// Licensed under the Apache-2.0 license

use crate::codec::{encode_u8_slice, Codec, CommonCodec, MessageBuf};
use crate::vdm_handler::iana::ocp::caliptra_vdm::protocol::{
    CaliptraCompletionCode, CaliptraVdmCmdResult, CaliptraVdmCommand, CaliptraVdmMsgHeader,
    CALIPTRA_VDM_COMMAND_VERSION,
};
use crate::vdm_handler::{VdmError, VdmResult};
use caliptra_mcu_common_commands::CaliptraCmdHandler;
use core::mem::size_of;
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct ExportIdevidCsrReq {
    algorithm: u32,
}

impl CommonCodec for ExportIdevidCsrReq {}

pub(crate) async fn handle_export_idevid_csr(
    handler: &dyn CaliptraCmdHandler,
    req_buf: &mut MessageBuf<'_>,
    rsp_buf: &mut MessageBuf<'_>,
    large_rsp_buf: &mut [u8],
) -> VdmResult<CaliptraVdmCmdResult> {
    let req = ExportIdevidCsrReq::decode(req_buf).map_err(VdmError::Codec)?;

    // VDM large-response header: [command_version(1), response_code(1), status(1), data_len(4)]
    let large_hdr_len = size_of::<CaliptraVdmMsgHeader>() + 1 + 4; // 7

    if large_rsp_buf.len() < large_hdr_len {
        return Ok(CaliptraVdmCmdResult::ErrorResponse(
            CaliptraCompletionCode::InsufficientResources,
        ));
    }

    // Use the tail of large_rsp_buf as scratch space for the CSR data.
    let csr_buf = &mut large_rsp_buf[large_hdr_len..];
    let data_len = match handler.export_idevid_csr(req.algorithm, csr_buf).await {
        Ok(len) => len,
        Err(e) => return Ok(CaliptraVdmCmdResult::ErrorResponse(e)),
    };

    // Normal-response VDM payload: [completion_code(1), data_len(4), csr_data...]
    let normal_payload_len = 1 + 4 + data_len;

    if normal_payload_len <= rsp_buf.tailroom() {
        // Response fits in the normal SPDM message — no chunking needed.
        let mut len = (CaliptraCompletionCode::Success as u8)
            .encode(rsp_buf)
            .map_err(VdmError::Codec)?;
        len += (data_len as u32).encode(rsp_buf).map_err(VdmError::Codec)?;
        len += encode_u8_slice(&csr_buf[..data_len], rsp_buf).map_err(VdmError::Codec)?;
        Ok(CaliptraVdmCmdResult::Response(len))
    } else {
        // Too large — format in large_rsp_buf and return LargeResp for chunking.
        let total_resp_len = large_hdr_len + data_len;
        let mut offset = 0;
        large_rsp_buf[offset] = CALIPTRA_VDM_COMMAND_VERSION;
        offset += 1;
        large_rsp_buf[offset] = CaliptraVdmCommand::ExportIdevidCsr.response_code();
        offset += 1;
        large_rsp_buf[offset] = CaliptraCompletionCode::Success as u8;
        offset += 1;
        large_rsp_buf[offset..offset + 4].copy_from_slice(&(data_len as u32).to_le_bytes());
        // CSR data is already at large_rsp_buf[large_hdr_len..large_hdr_len + data_len]
        Err(VdmError::LargeResp(total_resp_len))
    }
}
