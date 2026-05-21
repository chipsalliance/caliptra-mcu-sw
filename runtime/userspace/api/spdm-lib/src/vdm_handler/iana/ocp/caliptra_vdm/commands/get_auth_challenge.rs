// Licensed under the Apache-2.0 license

use crate::codec::{encode_u8_slice, Codec, MessageBuf};
use crate::vdm_handler::iana::ocp::caliptra_vdm::protocol::{
    CaliptraCompletionCode, CaliptraVdmCmdResult,
};
use crate::vdm_handler::{VdmError, VdmResult};
use caliptra_mcu_libapi_caliptra::crypto::rng::Rng;

/// Handle GetAuthCmdChallenge — generate a random 32-byte challenge nonce
/// and store it for subsequent authorized command verification.
///
/// VDM wire format request:  [version, 0x12]  (no additional payload)
/// VDM wire format response: [version, 0x12, completion_code, challenge(32)]
pub(crate) async fn handle_get_auth_challenge(
    _req_buf: &mut MessageBuf<'_>,
    rsp_buf: &mut MessageBuf<'_>,
    challenge_store: &mut Option<[u8; 32]>,
) -> VdmResult<CaliptraVdmCmdResult> {
    let mut challenge = [0u8; 32];

    Rng::generate_random_number(&mut challenge)
        .await
        .map_err(|_| VdmError::UnsupportedRequest)?;

    // Store the challenge for later HMAC verification
    *challenge_store = Some(challenge);

    // Encode response: [completion_code, challenge(32)]
    let mut len = (CaliptraCompletionCode::Success as u8)
        .encode(rsp_buf)
        .map_err(VdmError::Codec)?;
    len += encode_u8_slice(&challenge, rsp_buf).map_err(VdmError::Codec)?;

    Ok(CaliptraVdmCmdResult::Response(len))
}
