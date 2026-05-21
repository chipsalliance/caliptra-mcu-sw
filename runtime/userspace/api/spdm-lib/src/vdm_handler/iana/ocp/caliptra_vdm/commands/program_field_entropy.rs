// Licensed under the Apache-2.0 license

use crate::codec::{Codec, MessageBuf};
use crate::vdm_handler::iana::ocp::caliptra_vdm::protocol::{
    CaliptraCompletionCode, CaliptraVdmCmdResult,
};
use crate::vdm_handler::{VdmError, VdmResult};
use caliptra_mcu_common_commands::{CaliptraCmdHandler, CommandAuthorizer};

/// CaliptraCommandId::FeProg — the command ID used in the SPDM VDM namespace
/// for HMAC computation. Must match the host-side value.
const FE_PROG_CMD_ID: u32 = 0x8011;

/// Handle ProgramFieldEntropy with authorization via [`CommandAuthorizer`].
///
/// VDM wire format request:  [version, 0x10, partition(4 LE), mac(48)]
/// VDM wire format response: [version, 0x10, completion_code]
///
/// Delegates MAC verification to the provided [`CommandAuthorizer::verify_mac`]
/// using the SPDM VDM command ID namespace.
pub(crate) async fn handle_program_field_entropy(
    handler: &dyn CaliptraCmdHandler,
    req_buf: &mut MessageBuf<'_>,
    rsp_buf: &mut MessageBuf<'_>,
    cmd_authorizer: &mut &mut (dyn CommandAuthorizer + Send + Sync),
) -> VdmResult<CaliptraVdmCmdResult> {
    let partition = u32::decode(req_buf).map_err(VdmError::Codec)?;

    // Read the 48-byte MAC from the request
    let mac_len = 48;
    let received_mac = req_buf.data(mac_len).map_err(VdmError::Codec)?;

    // Verify MAC using the SPDM VDM command ID
    if cmd_authorizer
        .verify_mac(FE_PROG_CMD_ID, &partition.to_le_bytes(), received_mac)
        .await
        .is_err()
    {
        return Ok(CaliptraVdmCmdResult::ErrorResponse(
            CaliptraCompletionCode::AccessDenied,
        ));
    }

    // Authorization verified — execute the command
    match handler.program_field_entropy(partition).await {
        Ok(()) => {
            let len = (CaliptraCompletionCode::Success as u8)
                .encode(rsp_buf)
                .map_err(VdmError::Codec)?;
            Ok(CaliptraVdmCmdResult::Response(len))
        }
        Err(e) => Ok(CaliptraVdmCmdResult::ErrorResponse(e)),
    }
}
