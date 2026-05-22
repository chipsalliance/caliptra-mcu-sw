// Licensed under the Apache-2.0 license

use crate::codec::{encode_u8_slice, Codec, CommonCodec, MessageBuf};
use crate::vdm_handler::iana::ocp::caliptra_vdm::protocol::{
    CaliptraCompletionCode, CaliptraVdmCmdResult,
};
use crate::vdm_handler::{VdmError, VdmResult};
use caliptra_mcu_common_commands::{CaliptraCmdHandler, GetLogResult, LogType};
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub(crate) const MAX_LOG_DATA_SIZE: usize = 900;

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct GetDebugLogReq {}

impl CommonCodec for GetDebugLogReq {}

pub(crate) async fn handle_get_debug_log(
    handler: &dyn CaliptraCmdHandler,
    _req_buf: &mut MessageBuf<'_>,
    rsp_buf: &mut MessageBuf<'_>,
) -> VdmResult<CaliptraVdmCmdResult> {
    let mut scratch = [0u8; MAX_LOG_DATA_SIZE];
    match handler.get_log(LogType::Debug as u32, &mut scratch).await {
        Ok(GetLogResult {
            bytes_written,
            more_data,
        }) => {
            let mut len = (CaliptraCompletionCode::Success as u8)
                .encode(rsp_buf)
                .map_err(VdmError::Codec)?;
            len += (if more_data { 1u8 } else { 0u8 })
                .encode(rsp_buf)
                .map_err(VdmError::Codec)?;
            len += (bytes_written as u32)
                .encode(rsp_buf)
                .map_err(VdmError::Codec)?;
            len += encode_u8_slice(&scratch[..bytes_written], rsp_buf).map_err(VdmError::Codec)?;
            Ok(CaliptraVdmCmdResult::Response(len))
        }
        Err(e) => Ok(CaliptraVdmCmdResult::ErrorResponse(e)),
    }
}
