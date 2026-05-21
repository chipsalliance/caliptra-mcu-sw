// Licensed under the Apache-2.0 license

use crate::codec::{Codec, MessageBuf};
use crate::vdm_handler::iana::ocp::caliptra_vdm::protocol::{
    CaliptraCompletionCode, CaliptraVdmCmdResult,
};
use crate::vdm_handler::{VdmError, VdmResult};
use caliptra_mcu_common_commands::CaliptraCmdHandler;
use caliptra_mcu_libapi_caliptra::crypto::hmac::Hmac;
use caliptra_mcu_libapi_caliptra::crypto::import::{CmKeyUsage, Import};
use constant_time_eq::constant_time_eq;
use zerocopy::IntoBytes;

/// CaliptraCommandId::FeProg — must match the host-side value used in HMAC computation.
const FE_PROG_CMD_ID: u32 = 0x8011;

/// Shared HMAC key for authorized command verification.
/// NOTE: In production, this should come from a provisioned OTP secret.
const AUTH_CMD_HMAC_KEY: [u8; 48] = [
    0x72, 0xec, 0x12, 0x02, 0x77, 0x69, 0xb9, 0xdc, 0x04, 0xbd, 0xd0, 0xc0, 0x86, 0xca, 0x1b,
    0x20, 0x2f, 0x47, 0x1e, 0xee, 0xf2, 0x8c, 0x2d, 0xa8, 0xc5, 0x4c, 0x75, 0xc2, 0x48, 0xa6,
    0x80, 0x0a, 0x11, 0xbf, 0xd5, 0xcd, 0x09, 0xed, 0x57, 0x0c, 0xb4, 0xc2, 0xa1, 0x37, 0x6b,
    0xa2, 0xcb, 0xcd,
];

/// Handle ProgramFieldEntropy with HMAC-SHA384 authorization.
///
/// VDM wire format request:  [version, 0x10, partition(4 LE), mac(48)]
/// VDM wire format response: [version, 0x10, completion_code]
///
/// Verification follows the same format as the MCU mailbox path:
///   HMAC-SHA384(key, cmd_id(BE,4) || partition(LE,4) || challenge(32))
pub(crate) async fn handle_program_field_entropy(
    handler: &dyn CaliptraCmdHandler,
    req_buf: &mut MessageBuf<'_>,
    rsp_buf: &mut MessageBuf<'_>,
    challenge: Option<[u8; 32]>,
) -> VdmResult<CaliptraVdmCmdResult> {
    let partition = u32::decode(req_buf).map_err(VdmError::Codec)?;

    // Read the 48-byte MAC from the request
    let mac_len = 48;
    let received_mac = req_buf.data(mac_len).map_err(VdmError::Codec)?;

    // Consume the stored challenge (one-time use)
    let challenge = match challenge {
        Some(c) => c,
        None => {
            return Ok(CaliptraVdmCmdResult::ErrorResponse(
                CaliptraCompletionCode::AccessDenied,
            ));
        }
    };

    // Import the HMAC key using Caliptra crypto API
    let import_resp = Import::import(CmKeyUsage::Hmac, &AUTH_CMD_HMAC_KEY)
        .await
        .map_err(|_| VdmError::UnsupportedRequest)?;

    // Build HMAC message: cmd_id(BE,4) || partition(LE,4) || challenge(32)
    let mut buf = arrayvec::ArrayVec::<u8, 40>::new();
    buf.extend(FE_PROG_CMD_ID.to_be_bytes());
    buf.extend(partition.to_le_bytes());
    buf.extend(challenge);

    // Compute HMAC-SHA384
    let hmac_resp = Hmac::hmac(&import_resp.cmk, buf.as_slice())
        .await
        .map_err(|_| VdmError::UnsupportedRequest)?;

    let computed_mac = &hmac_resp.mac.as_bytes()[..48];

    if !constant_time_eq(computed_mac, received_mac) {
        return Ok(CaliptraVdmCmdResult::ErrorResponse(
            CaliptraCompletionCode::AccessDenied,
        ));
    }

    // HMAC verified — execute the command
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
