// Licensed under the Apache-2.0 license

//! EXPORT_ATTESTED_CSR (0x08): exports an attested CSR.
//!
//! This is the largest Caliptra VDM response and exercises the inline-or-large
//! response path. The CSR bytes are fetched through the shared command handler
//! into the `large` staging buffer's tail, then framed inline when the whole
//! response fits one transport frame, otherwise as a chunked large response.

use caliptra_mcu_common_commands::CaliptraCmdHandler;
use caliptra_mcu_spdm_traits::SpdmPalAlloc;

use caliptra_mcu_spdm_codec::vendor_defined::iana::ocp::caliptra::{
    CaliptraCompletionCode, CaliptraVdmCmdResult, CALIPTRA_VDM_COMMAND_VERSION,
};

const ATTESTED_REQ_LEN: usize = 4 + 4 + 32;
const CSR_LEN_FIELD: usize = 4;
const CSR_PAYLOAD_HEADER_LEN: usize = 2 + 1 + CSR_LEN_FIELD;
const INLINE_PREFIX_LEN: usize = 1 + CSR_LEN_FIELD;

fn finish_staged_csr_response(
    command_code: u8,
    inline_payload: &mut [u8],
    large: &mut [u8],
    data_len: usize,
) -> CaliptraVdmCmdResult {
    if data_len > large.len().saturating_sub(CSR_PAYLOAD_HEADER_LEN) {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
    }

    if INLINE_PREFIX_LEN + data_len <= inline_payload.len() {
        inline_payload[0] = CaliptraCompletionCode::Success as u8;
        inline_payload[1..INLINE_PREFIX_LEN].copy_from_slice(&(data_len as u32).to_le_bytes());
        inline_payload[INLINE_PREFIX_LEN..INLINE_PREFIX_LEN + data_len]
            .copy_from_slice(&large[CSR_PAYLOAD_HEADER_LEN..CSR_PAYLOAD_HEADER_LEN + data_len]);
        CaliptraVdmCmdResult::Response(INLINE_PREFIX_LEN + data_len)
    } else {
        large[0] = CALIPTRA_VDM_COMMAND_VERSION;
        large[1] = command_code;
        large[2] = CaliptraCompletionCode::Success as u8;
        large[3..CSR_PAYLOAD_HEADER_LEN].copy_from_slice(&(data_len as u32).to_le_bytes());
        CaliptraVdmCmdResult::Large(CSR_PAYLOAD_HEADER_LEN + data_len)
    }
}

fn finish_inline_csr_response(inline_payload: &mut [u8], data_len: usize) -> CaliptraVdmCmdResult {
    if INLINE_PREFIX_LEN + data_len > inline_payload.len() {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
    }
    inline_payload[0] = CaliptraCompletionCode::Success as u8;
    inline_payload[1..INLINE_PREFIX_LEN].copy_from_slice(&(data_len as u32).to_le_bytes());
    CaliptraVdmCmdResult::Response(INLINE_PREFIX_LEN + data_len)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle<H, A>(
    cmds: &H,
    req: &[u8],
    command_code: u8,
    inline_payload: &mut [u8],
    large: &mut [u8],
    scratch: &A,
) -> CaliptraVdmCmdResult
where
    H: CaliptraCmdHandler,
    A: SpdmPalAlloc,
{
    if req.len() != ATTESTED_REQ_LEN {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    }
    let device_key_id = u32::from_le_bytes([req[0], req[1], req[2], req[3]]);
    let algorithm = u32::from_le_bytes([req[4], req[5], req[6], req[7]]);
    let nonce: &[u8; 32] = match req[8..].try_into() {
        Ok(nonce) => nonce,
        Err(_) => return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize),
    };

    if large.len() > CSR_PAYLOAD_HEADER_LEN {
        let data_len = match cmds
            .export_attested_csr(
                scratch,
                device_key_id,
                algorithm,
                nonce,
                &mut large[CSR_PAYLOAD_HEADER_LEN..],
            )
            .await
        {
            Ok(n) => n,
            Err(code) => {
                return CaliptraVdmCmdResult::Error(super::map_common_completion(code));
            }
        };
        finish_staged_csr_response(command_code, inline_payload, large, data_len)
    } else {
        if inline_payload.len() < INLINE_PREFIX_LEN {
            return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
        }
        let data_len = match cmds
            .export_attested_csr(
                scratch,
                device_key_id,
                algorithm,
                nonce,
                &mut inline_payload[INLINE_PREFIX_LEN..],
            )
            .await
        {
            Ok(n) => n,
            Err(code) => {
                return CaliptraVdmCmdResult::Error(super::map_common_completion(code));
            }
        };
        finish_inline_csr_response(inline_payload, data_len)
    }
}
