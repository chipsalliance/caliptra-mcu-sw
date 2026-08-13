// Licensed under the Apache-2.0 license

//! GET_ATTESTATION (0x05): returns signed attestation evidence.
//!
//! The request names the `evidence_format` to return. A build serves only the
//! formats enabled at compile time; the wire field selects among those.
//!
//! A request with `evidence_format == 0` is a discovery query and returns the
//! responder's supported-format bitmap instead of evidence.
//!
//! Evidence can exceed one transport frame, so this command uses the same
//! inline-or-large framing as `EXPORT_ATTESTED_CSR`.

use caliptra_mcu_common_commands::{
    AsymAlgo, CaliptraCmdHandler, EvidenceFormat, PkiEntitySlot, ATTESTATION_NONCE_LEN,
    EVIDENCE_FORMAT_QUERY,
};
use caliptra_mcu_spdm_traits::SpdmPalAlloc;

use caliptra_mcu_spdm_codec::vendor_defined::iana::ocp::caliptra::{
    CaliptraCompletionCode, CaliptraVdmCmdResult, CALIPTRA_VDM_COMMAND_VERSION,
};

/// `evidence_format:u32 | algorithm:u32 | pki_entity_slot:u32 | nonce:u8[32]`
const GET_ATTESTATION_REQ_LEN: usize = 4 + 4 + 4 + ATTESTATION_NONCE_LEN;

/// Byte offset of the nonce within the request body.
const NONCE_OFFSET: usize = 12;

/// Response fields preceding the evidence bytes: `evidence_format:u32 | data_len:u32`.
const RESP_FIELDS_LEN: usize = 4 + 4;

/// Inline response prefix: `completion:u8 | evidence_format:u32 | data_len:u32`.
pub(crate) const INLINE_PREFIX_LEN: usize = 1 + RESP_FIELDS_LEN;

/// Large response prefix: the VDM header plus the inline prefix, i.e.
/// `command_version:u8 | command_code:u8 | completion:u8 | evidence_format:u32 | data_len:u32`.
pub(crate) const LARGE_PREFIX_LEN: usize = 2 + INLINE_PREFIX_LEN;

/// Decodes the `(format, algorithm)` pair from a GET_ATTESTATION request body.
///
/// Returns `None` for a malformed request, a discovery query, or an
/// unrecognized format/algorithm value — none of which need an evidence buffer.
/// Used both by the request handler and by the backend's large-response
/// capacity hook, so that the reservation and the generation agree on exactly
/// which pair was asked for.
pub(crate) fn decode_format(req: &[u8]) -> Option<(EvidenceFormat, AsymAlgo)> {
    if req.len() != GET_ATTESTATION_REQ_LEN {
        return None;
    }
    let format = u32::from_le_bytes([req[0], req[1], req[2], req[3]]);
    let algorithm = u32::from_le_bytes([req[4], req[5], req[6], req[7]]);
    Some((
        EvidenceFormat::try_from(format).ok()?,
        AsymAlgo::try_from(algorithm).ok()?,
    ))
}

fn write_fields(buf: &mut [u8], format: u32, data_len: usize) {
    buf[..4].copy_from_slice(&format.to_le_bytes());
    buf[4..RESP_FIELDS_LEN].copy_from_slice(&(data_len as u32).to_le_bytes());
}

/// Answers a discovery query with the responder's supported-format bitmap.
///
/// The bitmap is carried in the data field so that a requester can decode the
/// query response with the same parser it uses for evidence.
fn handle_query<H: CaliptraCmdHandler>(inline_payload: &mut [u8]) -> CaliptraVdmCmdResult {
    const BITMAP_LEN: usize = 4;
    if inline_payload.len() < INLINE_PREFIX_LEN + BITMAP_LEN {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
    }
    inline_payload[0] = CaliptraCompletionCode::Success as u8;
    write_fields(&mut inline_payload[1..], EVIDENCE_FORMAT_QUERY, BITMAP_LEN);
    inline_payload[INLINE_PREFIX_LEN..INLINE_PREFIX_LEN + BITMAP_LEN]
        .copy_from_slice(&H::SUPPORTED_EVIDENCE_FORMATS.to_le_bytes());
    CaliptraVdmCmdResult::Response(INLINE_PREFIX_LEN + BITMAP_LEN)
}

/// Frames evidence that was generated into the tail of the `large` buffer,
/// preferring an inline response when the whole thing fits one frame.
fn finish_staged(
    command_code: u8,
    inline_payload: &mut [u8],
    large: &mut [u8],
    format: EvidenceFormat,
    data_len: usize,
) -> CaliptraVdmCmdResult {
    if data_len > large.len().saturating_sub(LARGE_PREFIX_LEN) {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
    }

    if INLINE_PREFIX_LEN + data_len <= inline_payload.len() {
        inline_payload[0] = CaliptraCompletionCode::Success as u8;
        write_fields(&mut inline_payload[1..], format as u32, data_len);
        inline_payload[INLINE_PREFIX_LEN..INLINE_PREFIX_LEN + data_len]
            .copy_from_slice(&large[LARGE_PREFIX_LEN..LARGE_PREFIX_LEN + data_len]);
        CaliptraVdmCmdResult::Response(INLINE_PREFIX_LEN + data_len)
    } else {
        large[0] = CALIPTRA_VDM_COMMAND_VERSION;
        large[1] = command_code;
        large[2] = CaliptraCompletionCode::Success as u8;
        write_fields(&mut large[3..], format as u32, data_len);
        CaliptraVdmCmdResult::Large(LARGE_PREFIX_LEN + data_len)
    }
}

fn finish_inline(
    inline_payload: &mut [u8],
    format: EvidenceFormat,
    data_len: usize,
) -> CaliptraVdmCmdResult {
    if INLINE_PREFIX_LEN + data_len > inline_payload.len() {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
    }
    inline_payload[0] = CaliptraCompletionCode::Success as u8;
    write_fields(&mut inline_payload[1..], format as u32, data_len);
    CaliptraVdmCmdResult::Response(INLINE_PREFIX_LEN + data_len)
}

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
    if req.len() != GET_ATTESTATION_REQ_LEN {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    }

    let format_raw = u32::from_le_bytes([req[0], req[1], req[2], req[3]]);
    if format_raw == EVIDENCE_FORMAT_QUERY {
        return handle_query::<H>(inline_payload);
    }

    let algorithm_raw = u32::from_le_bytes([req[4], req[5], req[6], req[7]]);
    let entity_raw = u32::from_le_bytes([req[8], req[9], req[10], req[11]]);
    let Ok(format) = EvidenceFormat::try_from(format_raw) else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidParameter);
    };
    let Ok(algorithm) = AsymAlgo::try_from(algorithm_raw) else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidParameter);
    };
    let Ok(entity) = PkiEntitySlot::try_from(entity_raw) else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidParameter);
    };
    let Ok(nonce) = <&[u8; ATTESTATION_NONCE_LEN]>::try_from(&req[NONCE_OFFSET..]) else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    };

    // A pair this build cannot serve is rejected before any buffer is touched,
    // and reported distinctly from a malformed request.
    let needed = H::attestation_evidence_len(format, algorithm);
    if needed == 0 {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::UnsupportedOperation);
    }

    // The staging buffer is reserved from the same per-format bound, so if it
    // was provisioned at all it is large enough. When chunking is unavailable
    // the command still succeeds for evidence small enough to fit one frame.
    if large.len() > LARGE_PREFIX_LEN {
        let data_len = match cmds
            .get_attestation(
                scratch.pool(),
                format,
                algorithm,
                entity,
                nonce,
                &mut large[LARGE_PREFIX_LEN..],
            )
            .await
        {
            Ok(n) => n,
            Err(code) => return CaliptraVdmCmdResult::Error(super::map_common_completion(code)),
        };
        finish_staged(command_code, inline_payload, large, format, data_len)
    } else {
        if inline_payload.len() < INLINE_PREFIX_LEN {
            return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
        }
        let data_len = match cmds
            .get_attestation(
                scratch.pool(),
                format,
                algorithm,
                entity,
                nonce,
                &mut inline_payload[INLINE_PREFIX_LEN..],
            )
            .await
        {
            Ok(n) => n,
            Err(code) => return CaliptraVdmCmdResult::Error(super::map_common_completion(code)),
        };
        finish_inline(inline_payload, format, data_len)
    }
}
