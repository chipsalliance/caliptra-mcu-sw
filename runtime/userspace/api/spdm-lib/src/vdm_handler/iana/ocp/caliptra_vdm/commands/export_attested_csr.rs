// Licensed under the Apache-2.0 license

use crate::codec::{encode_u8_slice, Codec, CommonCodec, MessageBuf};
use crate::vdm_handler::iana::ocp::caliptra_vdm::protocol::{
    CaliptraVdmCmdResult, CaliptraVdmError,
};
use crate::vdm_handler::{VdmError, VdmResult};
use caliptra_mcu_external_cmds_common::{
    AttestedCsrData, CommandError, UnifiedCommandHandler, MAX_ATTESTED_CSR_DATA_LEN,
};
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
    handler: &dyn UnifiedCommandHandler,
    req_buf: &mut MessageBuf<'_>,
    rsp_buf: &mut MessageBuf<'_>,
) -> VdmResult<CaliptraVdmCmdResult> {
    let req = ExportAttestedCsrReq::decode(req_buf).map_err(VdmError::Codec)?;

    let mut csr_data = AttestedCsrData::default();
    match handler
        .export_attested_csr(req.device_key_id, req.algorithm, &req.nonce, &mut csr_data)
        .await
    {
        Ok(()) => {
            let data_len = csr_data.len.min(MAX_ATTESTED_CSR_DATA_LEN);
            let mut len = (CaliptraVdmError::Success as u8)
                .encode(rsp_buf)
                .map_err(VdmError::Codec)?;
            len += (data_len as u32).encode(rsp_buf).map_err(VdmError::Codec)?;
            len += encode_u8_slice(&csr_data.data[..data_len], rsp_buf).map_err(VdmError::Codec)?;
            Ok(CaliptraVdmCmdResult::Response(len))
        }
        Err(CommandError::InvalidParams) => Ok(CaliptraVdmCmdResult::ErrorResponse(
            CaliptraVdmError::InvalidData,
        )),
        Err(CommandError::NotSupported) => Ok(CaliptraVdmCmdResult::ErrorResponse(
            CaliptraVdmError::InvalidCommand,
        )),
        Err(CommandError::Busy) => Ok(CaliptraVdmCmdResult::ErrorResponse(
            CaliptraVdmError::NotReady,
        )),
        Err(_) => Ok(CaliptraVdmCmdResult::ErrorResponse(
            CaliptraVdmError::GeneralError,
        )),
    }
}
