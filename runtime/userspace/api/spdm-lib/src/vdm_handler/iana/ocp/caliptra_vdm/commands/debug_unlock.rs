// Licensed under the Apache-2.0 license

use crate::codec::{encode_u8_slice, Codec, MessageBuf};
use crate::vdm_handler::iana::ocp::caliptra_vdm::protocol::{
    CaliptraCompletionCode, CaliptraVdmCmdResult,
};
use crate::vdm_handler::{VdmError, VdmResult};
use caliptra_mcu_common_commands::{CaliptraCmdHandler, DebugUnlockChallenge};

pub(crate) async fn handle_request_debug_unlock(
    handler: &dyn CaliptraCmdHandler,
    req_buf: &mut MessageBuf<'_>,
    rsp_buf: &mut MessageBuf<'_>,
) -> VdmResult<CaliptraVdmCmdResult> {
    let unlock_level = u8::decode(req_buf).map_err(VdmError::Codec)?;

    let mut challenge = DebugUnlockChallenge::default();
    match handler
        .request_debug_unlock(unlock_level, &mut challenge)
        .await
    {
        Ok(()) => {
            let mut len = (CaliptraCompletionCode::Success as u8)
                .encode(rsp_buf)
                .map_err(VdmError::Codec)?;
            len += encode_u8_slice(&challenge.unique_device_identifier, rsp_buf)
                .map_err(VdmError::Codec)?;
            len += encode_u8_slice(&challenge.challenge, rsp_buf).map_err(VdmError::Codec)?;
            Ok(CaliptraVdmCmdResult::Response(len))
        }
        Err(e) => Ok(CaliptraVdmCmdResult::ErrorResponse(e)),
    }
}

pub(crate) async fn handle_authorize_debug_unlock_token(
    handler: &dyn CaliptraCmdHandler,
    req_buf: &mut MessageBuf<'_>,
    rsp_buf: &mut MessageBuf<'_>,
) -> VdmResult<CaliptraVdmCmdResult> {
    // Read the remaining request bytes as token data
    let token_len = req_buf.data_len();
    let token_data = req_buf.data(token_len).map_err(VdmError::Codec)?;

    match handler.authorize_debug_unlock_token(token_data).await {
        Ok(()) => {
            let len = (CaliptraCompletionCode::Success as u8)
                .encode(rsp_buf)
                .map_err(VdmError::Codec)?;
            Ok(CaliptraVdmCmdResult::Response(len))
        }
        Err(e) => Ok(CaliptraVdmCmdResult::ErrorResponse(e)),
    }
}
