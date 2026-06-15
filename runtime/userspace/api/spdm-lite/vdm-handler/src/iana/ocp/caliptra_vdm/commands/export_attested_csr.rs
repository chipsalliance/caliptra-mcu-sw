// Licensed under the Apache-2.0 license

//! EXPORT_ATTESTED_CSR (0x0F): exports an attested CSR.
//!
//! This is the largest Caliptra VDM response and exercises the inline-or-large
//! response path. The CSR bytes are fetched (via the device-ops hook) into the
//! `large` staging buffer's tail, then framed inline when the whole response
//! fits one transport frame, otherwise as a chunked large response.

use mcu_spdm_lite_traits::{SpdmPalAlloc, SpdmPalIo};

use crate::iana::ocp::caliptra_vdm::protocol::{
    CaliptraCompletionCode, CaliptraVdmCmdResult, CALIPTRA_VDM_COMMAND_VERSION,
};
use crate::iana::ocp::caliptra_vdm::CaliptraVdmCommands;

/// Request payload: `device_key_id` (u32 LE) | `algorithm` (u32 LE) | `nonce` (32 bytes).
const REQ_LEN: usize = 4 + 4 + 32;

/// Length of the `csr_len` (u32 LE) field in the response payload.
const CSR_LEN_FIELD: usize = 4;

/// Complete VDM payload header preceding the CSR bytes in the large buffer:
/// `[command_version, command_code, completion_code, csr_len (u32 LE)]`.
const CSR_PAYLOAD_HEADER_LEN: usize = 2 + 1 + CSR_LEN_FIELD;

/// Inline payload prefix (after the 2-byte VDM header the dispatcher already
/// wrote): `[completion_code, csr_len (u32 LE)]`.
const INLINE_PREFIX_LEN: usize = 1 + CSR_LEN_FIELD;

/// Handles an EXPORT_ATTESTED_CSR command.
///
/// `inline_payload` is the inline buffer region after the 2-byte VDM header
/// (receives `[completion, csr_len, csr_data]`). `large` is the worst-case
/// staging buffer; when present, the CSR is fetched into its tail and either
/// copied back inline (if it fits one frame) or framed in place as a large
/// response.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle<H, A, I>(
    cmds: &H,
    req: &[u8],
    command_code: u8,
    inline_payload: &mut [u8],
    large: &mut [u8],
    scratch: &A,
    io: &I,
) -> CaliptraVdmCmdResult
where
    H: CaliptraVdmCommands,
    A: SpdmPalAlloc,
    I: SpdmPalIo,
{
    if req.len() != REQ_LEN {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    }
    let device_key_id = u32::from_le_bytes([req[0], req[1], req[2], req[3]]);
    let algorithm = u32::from_le_bytes([req[4], req[5], req[6], req[7]]);
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&req[8..REQ_LEN]);

    // Prefer the worst-case `large` staging buffer when the stack provisioned
    // one; otherwise only a single-frame inline response is possible.
    if large.len() > CSR_PAYLOAD_HEADER_LEN {
        let data_len = match cmds
            .export_attested_csr(
                device_key_id,
                algorithm,
                &nonce,
                scratch,
                io,
                &mut large[CSR_PAYLOAD_HEADER_LEN..],
            )
            .await
        {
            Ok(n) => n,
            Err(code) => return CaliptraVdmCmdResult::Error(code),
        };

        if INLINE_PREFIX_LEN + data_len <= inline_payload.len() {
            // Fits one frame: emit inline `[completion, csr_len, csr_data]`.
            inline_payload[0] = CaliptraCompletionCode::Success as u8;
            inline_payload[1..INLINE_PREFIX_LEN].copy_from_slice(&(data_len as u32).to_le_bytes());
            inline_payload[INLINE_PREFIX_LEN..INLINE_PREFIX_LEN + data_len]
                .copy_from_slice(&large[CSR_PAYLOAD_HEADER_LEN..CSR_PAYLOAD_HEADER_LEN + data_len]);
            CaliptraVdmCmdResult::Response(INLINE_PREFIX_LEN + data_len)
        } else {
            // Too large for one frame: frame the complete VDM payload header in
            // `large`; the CSR data is already at large[CSR_PAYLOAD_HEADER_LEN..].
            large[0] = CALIPTRA_VDM_COMMAND_VERSION;
            large[1] = command_code;
            large[2] = CaliptraCompletionCode::Success as u8;
            large[3..CSR_PAYLOAD_HEADER_LEN].copy_from_slice(&(data_len as u32).to_le_bytes());
            CaliptraVdmCmdResult::Large(CSR_PAYLOAD_HEADER_LEN + data_len)
        }
    } else {
        // No large staging buffer (chunking unavailable): inline only.
        if inline_payload.len() <= INLINE_PREFIX_LEN {
            return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
        }
        let data_len = match cmds
            .export_attested_csr(
                device_key_id,
                algorithm,
                &nonce,
                scratch,
                io,
                &mut inline_payload[INLINE_PREFIX_LEN..],
            )
            .await
        {
            Ok(n) => n,
            Err(code) => return CaliptraVdmCmdResult::Error(code),
        };
        inline_payload[0] = CaliptraCompletionCode::Success as u8;
        inline_payload[1..INLINE_PREFIX_LEN].copy_from_slice(&(data_len as u32).to_le_bytes());
        CaliptraVdmCmdResult::Response(INLINE_PREFIX_LEN + data_len)
    }
}
