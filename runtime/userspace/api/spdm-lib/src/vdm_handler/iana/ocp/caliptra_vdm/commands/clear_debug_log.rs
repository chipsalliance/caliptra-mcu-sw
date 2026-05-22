// Licensed under the Apache-2.0 license

use crate::codec::{Codec, CommonCodec, MessageBuf};
use crate::vdm_handler::iana::ocp::caliptra_vdm::protocol::{
    CaliptraCompletionCode, CaliptraVdmCmdResult,
};
use crate::vdm_handler::{VdmError, VdmResult};
use caliptra_mcu_common_commands::{CaliptraCmdHandler, LogType};
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct ClearDebugLogReq {}

impl CommonCodec for ClearDebugLogReq {}

pub(crate) async fn handle_clear_debug_log(
    handler: &dyn CaliptraCmdHandler,
    _req_buf: &mut MessageBuf<'_>,
    rsp_buf: &mut MessageBuf<'_>,
) -> VdmResult<CaliptraVdmCmdResult> {
    match handler.clear_log(LogType::Debug as u32).await {
        Ok(()) => {
            let len = (CaliptraCompletionCode::Success as u8)
                .encode(rsp_buf)
                .map_err(VdmError::Codec)?;
            Ok(CaliptraVdmCmdResult::Response(len))
        }
        Err(e) => Ok(CaliptraVdmCmdResult::ErrorResponse(e)),
    }
}
