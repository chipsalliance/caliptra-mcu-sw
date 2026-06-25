// Licensed under the Apache-2.0 license

//! VENDOR_DEFINED request dispatch.
//!
//! [`handle_vendor_defined_request`] decodes the SPDM VENDOR_DEFINED envelope, selects
//! the stack's [`SpdmVdmBackend`] via [`SpdmVdmBackend::match_id`], runs it, and frames
//! the VENDOR_DEFINED_RESPONSE. It is called from the `VENDOR_DEFINED_REQUEST` arm of
//! both the plaintext (`dispatch`) and secured (`handle_secured_inner`) paths, mirroring
//! how `GET_MEASUREMENTS` is handled.

use caliptra_mcu_spdm_codec::{
    decode_vendor_defined_req, ReqRespCode, ResponseBody, SpdmMsgHdrPdu, SpdmVersion,
    VendorDefinedRspBody, WireWriter,
};
use caliptra_mcu_spdm_traits::{
    PalBytes, SpdmPal, SpdmPalAlloc, SpdmPalIoTransport, SpdmVdmBackend, VdmRegistry, VdmResponse,
    VdmResponseBuffer,
};
use zerocopy::FromBytes;

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
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
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

    // Large staging buffer: provisioned only when chunking is available and the
    // matched backend says this request can emit a response that overflows one
    // frame. This keeps inline-only VDMs from consuming scarce scratch space.
    let large_cap = if V::USES_LARGE_RESPONSE && state.chunking_enabled() {
        let requested = vdm.large_response_capacity(decoded.payload);
        if requested > inline_cap {
            state
                .effective_max_spdm_msg_size(pal)
                .min(pal.large_capacity())
                .saturating_sub(envelope)
                .min(requested)
        } else {
            0
        }
    } else {
        0
    };

    // WipeOnDrop ensures that the allocated large buffer gets zero-wiped
    // and freed under any exit path.
    let mut large_guard = if large_cap > 0 {
        Some(chunk::WipeOnDrop {
            buf: Some(pal.alloc_large_buf(envelope + large_cap)?),
        })
    } else {
        None
    };

    let outcome = {
        let large_slice: &mut [u8] = match large_guard.as_mut() {
            Some(guard) => guard
                .buf
                .as_deref_mut()
                .and_then(|buf| buf.get_mut(envelope..envelope + large_cap))
                .ok_or(SPDM_UNSPECIFIED)?,
            None => &mut [],
        };
        let rsp = VdmResponseBuffer {
            inline: &mut inline_buf[..],
            large: large_slice,
            alloc: pal,
            io,
        };
        vdm.handle_request(decoded.payload, rsp).await?
    };

    match outcome {
        VdmResponse::Inline(n) => {
            // Drop large_guard here; its Drop impl auto-zeroizes!
            drop(large_guard);
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
            let Some(mut guard) = large_guard else {
                return Err(SPDM_UNSPECIFIED);
            };
            if n > large_cap {
                return Err(SPDM_UNSPECIFIED);
            }
            let mut buf = guard.buf.take().ok_or(SPDM_UNSPECIFIED)?;
            // Backend has written its payload at static_buf[envelope..envelope+n].
            // Frame the VENDOR_DEFINED envelope in-place at offset 0.
            write_vendor_defined_envelope(
                version,
                decoded.standard_id,
                decoded.vendor_id,
                n,
                &mut buf[..envelope],
            )?;
            let full_len = envelope + n;
            state.large_msg_ctx.set_buffer(buf);
            let (resp, spdm_len) =
                match chunk::start_buffered_large_response(state, pal, io, full_len) {
                    Ok(res) => res,
                    Err(err) => {
                        state.large_msg_ctx.reset();
                        return Err(err);
                    }
                };
            Ok((resp, spdm_len))
        }
    }
}

/// Decodes a reassembled large VENDOR_DEFINED request and writes the complete
/// SPDM VENDOR_DEFINED_RESPONSE into `out`.
///
/// This is used for `CHUNK_SEND`'s `ResponseToLargeRequest`. The persistent
/// large-message buffer is still occupied by the reassembled request, so large
/// VDM responses are intentionally disabled here; handlers get only the inline
/// response area and must return [`VdmResponse::Inline`].
pub(crate) async fn handle_large_vendor_defined_request<Pal: SpdmPal, V: SpdmVdmBackend>(
    vdm: &V,
    state: &ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    spdm_msg: &[u8],
    secure_session: bool,
    out: &mut [u8],
) -> SpdmResult<usize> {
    let (hdr, body) = SpdmMsgHdrPdu::ref_from_prefix(spdm_msg).map_err(|_| SPDM_INVALID_REQUEST)?;
    let version = SpdmVersion::from_u8(hdr.version).unwrap_or(state.version);

    let decoded = decode_vendor_defined_req(body).map_err(|_| SPDM_INVALID_REQUEST)?;
    let registry = VdmRegistry {
        standard_id: decoded.standard_id,
        vendor_id: decoded.vendor_id,
        secure_session,
    };
    if !vdm.match_id(&registry) {
        return Err(SPDM_UNSUPPORTED_REQUEST.with_data(ReqRespCode::VENDOR_DEFINED_REQUEST.0));
    }

    let envelope_len = SpdmMsgHdrPdu::SIZE + 2 + 2 + 1 + decoded.vendor_id.len() + 2;
    if envelope_len > out.len() {
        return Err(SPDM_UNSPECIFIED);
    }
    let inline_cap = out.len() - envelope_len;
    let mut empty_large = [];
    let outcome = {
        let rsp = VdmResponseBuffer {
            inline: &mut out[envelope_len..envelope_len + inline_cap],
            large: &mut empty_large,
            alloc: pal,
            io,
        };
        vdm.handle_request(decoded.payload, rsp).await?
    };
    let VdmResponse::Inline(payload_len) = outcome else {
        return Err(SPDM_UNSPECIFIED);
    };
    if payload_len > inline_cap {
        return Err(SPDM_UNSPECIFIED);
    }

    write_vendor_defined_envelope(
        version,
        decoded.standard_id,
        decoded.vendor_id,
        payload_len,
        &mut out[..envelope_len],
    )?;
    Ok(envelope_len + payload_len)
}

/// Frames the VENDOR_DEFINED_RESPONSE envelope (SPDM header + param1/param2 +
/// standard_id + vendor_id + resp_len) directly into `out` (which must be sized
/// to the envelope). The backend's payload is expected to follow at the same
/// buffer's offset `out.len()`.
pub(crate) fn write_vendor_defined_envelope(
    version: SpdmVersion,
    standard_id: u16,
    vendor_id: &[u8],
    payload_len: usize,
    out: &mut [u8],
) -> SpdmResult<()> {
    let envelope_len = SpdmMsgHdrPdu::SIZE + 2 + 2 + 1 + vendor_id.len() + 2;
    if out.len() != envelope_len {
        return Err(SPDM_UNSPECIFIED);
    }
    let resp_len = u16::try_from(payload_len).map_err(|_| SPDM_UNSPECIFIED)?;
    let hdr = SpdmMsgHdrPdu::new(version, ReqRespCode::VENDOR_DEFINED_RESPONSE);

    let mut w = WireWriter::new(out);
    w.write(&hdr).map_err(|_| SPDM_UNSPECIFIED)?;
    w.write_bytes(&[0u8, 0u8]).map_err(|_| SPDM_UNSPECIFIED)?; // param1, param2
    w.write_bytes(&standard_id.to_le_bytes())
        .map_err(|_| SPDM_UNSPECIFIED)?;
    w.write_bytes(&[vendor_id.len() as u8])
        .map_err(|_| SPDM_UNSPECIFIED)?;
    w.write_bytes(vendor_id).map_err(|_| SPDM_UNSPECIFIED)?;
    w.write_bytes(&resp_len.to_le_bytes())
        .map_err(|_| SPDM_UNSPECIFIED)?;
    Ok(())
}
