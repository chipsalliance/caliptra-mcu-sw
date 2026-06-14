// Licensed under the Apache-2.0 license

//! VENDOR_DEFINED request dispatch.
//!
//! [`handle_vendor_defined_request`] decodes the SPDM VENDOR_DEFINED envelope, selects
//! the stack's [`SpdmVdmBackend`] via [`SpdmVdmBackend::match_id`], runs it, and frames
//! the VENDOR_DEFINED_RESPONSE. It is called from the `VENDOR_DEFINED_REQUEST` arm of
//! both the plaintext (`dispatch`) and secured (`handle_secured_inner`) paths, mirroring
//! how `GET_MEASUREMENTS` is handled.

use mcu_spdm_lite_codec::{
    decode_vendor_defined_req, ReqRespCode, ResponseBody, SpdmMsgHdrPdu, SpdmVersion,
    VendorDefinedRspBody,
};
use mcu_spdm_lite_traits::{
    PalBytes, SpdmPal, SpdmPalIoTransport, SpdmVdmBackend, VdmRegistry, VdmResponse,
    VdmResponseBuffer,
};
use zerocopy::{FromBytes, IntoBytes};

use crate::build::build_response;
use crate::chunk;
use crate::error::{SpdmResult, SPDM_INVALID_REQUEST, SPDM_UNSPECIFIED, SPDM_UNSUPPORTED_REQUEST};
use crate::stack::ConnectionState;

/// Decodes a VENDOR_DEFINED request, dispatches it to `vdm`, and frames the
/// VENDOR_DEFINED_RESPONSE.
///
/// `spdm_msg` is the canonical SPDM message (common header + body): for plaintext
/// it is `io.request()`; for a secured message it is the decrypted payload.
///
/// Returns the framed response buffer and its SPDM-payload length.
pub(crate) async fn handle_vendor_defined_request<'a, Pal: SpdmPal, V: SpdmVdmBackend>(
    vdm: &V,
    state: &mut ConnectionState<Pal::State>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    spdm_msg: &[u8],
    secure_session: bool,
) -> SpdmResult<(PalBytes<'a, Pal>, usize)> {
    let (hdr, body) = SpdmMsgHdrPdu::ref_from_prefix(spdm_msg).map_err(|_| SPDM_INVALID_REQUEST)?;
    let version = SpdmVersion::from_u8(hdr.version).unwrap_or(state.version);

    let decoded = decode_vendor_defined_req(body).map_err(|_| SPDM_INVALID_REQUEST)?;
    let registry = VdmRegistry {
        standard_id: decoded.standard_id,
        vendor_id: decoded.vendor_id,
        secure_session,
    };
    // The stack carries a single VDM backend (one vendor namespace per stack:
    // MCTP -> OCP, DOE -> PCI-SIG), so `match_id` is an accept/reject gate, not a
    // selector among several handlers. To serve multiple vendors on one stack
    // later, `V` can be a composite `SpdmVdmBackend` (e.g. tuple impls) that loops
    // over its members internally; this dispatch site stays unchanged.
    if !vdm.match_id(&registry) {
        return Err(SPDM_UNSUPPORTED_REQUEST.with_data(ReqRespCode::VENDOR_DEFINED_REQUEST.0));
    }

    // Inline capacity: one SPDM frame minus the SPDM header + VENDOR_DEFINED
    // response envelope prefix (param1|param2|standard_id|vendor_id_len|vendor_id|
    // resp_len).
    let frame = state.effective_data_transfer_size(pal);
    let envelope = SpdmMsgHdrPdu::SIZE + 2 + 2 + 1 + decoded.vendor_id.len() + 2;
    let inline_cap = frame.saturating_sub(envelope);
    let mut inline_buf = pal.alloc_bytes(io, inline_cap)?;

    // Large staging buffer: provisioned only when the backend can emit responses
    // that overflow a single frame AND chunking is available. Sized so the full
    // buffered message (envelope + payload) fits both the large-response store and
    // the negotiated max SPDM message size; empty otherwise (forcing inline).
    let large_cap = if V::USES_LARGE_RESPONSE && state.chunking_enabled() {
        state
            .effective_max_spdm_msg_size(pal)
            .min(pal.large_capacity())
            .saturating_sub(envelope)
    } else {
        0
    };
    let mut large_buf = pal.alloc_bytes(io, large_cap)?;

    let outcome = {
        let rsp = VdmResponseBuffer {
            inline: &mut inline_buf[..],
            large: &mut large_buf[..],
            alloc: pal,
            io,
        };
        vdm.handle_request(decoded.payload, rsp).await?
    };

    match outcome {
        VdmResponse::Inline(n) => {
            if n > inline_buf.len() {
                return Err(SPDM_UNSPECIFIED);
            }
            let rsp_body = VendorDefinedRspBody {
                standard_id: decoded.standard_id,
                vendor_id: decoded.vendor_id,
                payload: &inline_buf[..n],
            };
            let spdm_len = rsp_body.encoded_size();
            let buf = build_response(pal, io, version, &rsp_body)?;
            Ok((buf, spdm_len))
        }
        VdmResponse::Large(n) => {
            if n > large_buf.len() {
                return Err(SPDM_UNSPECIFIED);
            }
            handle_large_vendor_defined_response(
                state,
                pal,
                io,
                version,
                decoded.standard_id,
                decoded.vendor_id,
                &large_buf[..n],
            )
            .await
        }
    }
}

/// Frames a VENDOR_DEFINED_RESPONSE that overflows a single transport frame into
/// the buffered large-response store and starts chunked delivery.
///
/// `payload` is the complete Caliptra VDM payload the backend wrote into the large
/// staging buffer. The full SPDM message `[SPDM header][VENDOR_DEFINED envelope]
/// [payload]` is written into the store at increasing offsets (mirroring
/// `handle_large_measurements_response`); `CHUNK_GET` then serves it over multiple
/// requests. Returns the `SPDM_LARGE_RESPONSE` handshake PDU (spdm_len 0).
#[allow(clippy::too_many_arguments)]
async fn handle_large_vendor_defined_response<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    version: SpdmVersion,
    standard_id: u16,
    vendor_id: &[u8],
    payload: &[u8],
) -> SpdmResult<(PalBytes<'a, Pal>, usize)> {
    let prefix_len = SpdmMsgHdrPdu::SIZE + 2 + 2 + 1 + vendor_id.len() + 2;
    let full_len = prefix_len
        .checked_add(payload.len())
        .ok_or(SPDM_UNSPECIFIED)?;
    chunk::validate_buffered_large_response(state, pal, full_len)?;
    // Reserve the pinned large buffer before framing the response into it; it is
    // released (RAII free + zero) once CHUNK_GET ships the final chunk.
    pal.large_begin(full_len)?;

    // Write the full SPDM message into the large-response store at offsets,
    // matching VendorDefinedRspBody's wire layout.
    let mut offset = 0usize;
    let hdr = SpdmMsgHdrPdu::new(version, ReqRespCode::VENDOR_DEFINED_RESPONSE);
    offset = write_large_vdm_bytes(pal, offset, hdr.as_bytes())?;
    offset = write_large_vdm_bytes(pal, offset, &[0u8, 0u8])?; // param1, param2
    offset = write_large_vdm_bytes(pal, offset, &standard_id.to_le_bytes())?;
    offset = write_large_vdm_bytes(pal, offset, &[vendor_id.len() as u8])?;
    offset = write_large_vdm_bytes(pal, offset, vendor_id)?;
    let resp_len = u16::try_from(payload.len()).map_err(|_| SPDM_UNSPECIFIED)?;
    offset = write_large_vdm_bytes(pal, offset, &resp_len.to_le_bytes())?;
    offset = write_large_vdm_bytes(pal, offset, payload)?;
    if offset != full_len {
        return Err(SPDM_UNSPECIFIED);
    }

    let resp = chunk::start_buffered_large_response(state, pal, io, full_len)?;
    Ok((resp, 0))
}

fn write_large_vdm_bytes<Pal: SpdmPal>(
    pal: &Pal,
    offset: usize,
    bytes: &[u8],
) -> SpdmResult<usize> {
    let next = offset.checked_add(bytes.len()).ok_or(SPDM_UNSPECIFIED)?;
    pal.large_write(offset, bytes)
        .map_err(|_| SPDM_UNSPECIFIED)?;
    Ok(next)
}
