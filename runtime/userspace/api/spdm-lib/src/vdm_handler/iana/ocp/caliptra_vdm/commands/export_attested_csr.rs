// Licensed under the Apache-2.0 license

use crate::codec::{Codec, CommonCodec, MessageBuf};
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
struct ExportAttestedCsrReq {
    device_key_id: u32,
    algorithm: u32,
    nonce: [u8; 32],
}

impl CommonCodec for ExportAttestedCsrReq {}

pub(crate) async fn handle_export_attested_csr(
    handler: &dyn CaliptraCmdHandler,
    req_buf: &mut MessageBuf<'_>,
    _rsp_buf: &mut MessageBuf<'_>,
    large_rsp_buf: &mut [u8],
) -> VdmResult<CaliptraVdmCmdResult> {
    let req = ExportAttestedCsrReq::decode(req_buf).map_err(VdmError::Codec)?;

    // VDM response header layout: [command_version(1), response_code(1), status(1), data_len(4)]
    let hdr_len = size_of::<CaliptraVdmMsgHeader>() + 1 + 4; // 2 + 1 + 4 = 7

    // Ensure buffer has room for at least the header
    if large_rsp_buf.len() < hdr_len {
        return Ok(CaliptraVdmCmdResult::ErrorResponse(
            CaliptraCompletionCode::InsufficientResources,
        ));
    }

    // Write CSR data directly into large_rsp_buf past the header region
    let csr_buf = &mut large_rsp_buf[hdr_len..];
    match handler
        .export_attested_csr(req.device_key_id, req.algorithm, &req.nonce, csr_buf)
        .await
    {
        Ok(data_len) => {
            let total_resp_len = hdr_len + data_len;

            // Write VDM header at the front
            let mut offset = 0;
            large_rsp_buf[offset] = CALIPTRA_VDM_COMMAND_VERSION;
            offset += 1;
            large_rsp_buf[offset] = CaliptraVdmCommand::ExportAttestedCsr.response_code();
            offset += 1;
            large_rsp_buf[offset] = CaliptraCompletionCode::Success as u8;
            offset += 1;
            large_rsp_buf[offset..offset + 4].copy_from_slice(&(data_len as u32).to_le_bytes());

            Err(VdmError::LargeResp(total_resp_len))
        }
        Err(e) => Ok(CaliptraVdmCmdResult::ErrorResponse(e)),
    }
}
