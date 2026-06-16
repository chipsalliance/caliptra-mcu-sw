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
    PalBytes, SpdmPal, SpdmPalAlloc, SpdmPalIoTransport, SpdmVdmBackend, VdmRegistry, VdmResponse,
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

    // Large staging buffer: provisioned only when the backend can emit responses
    // that overflow a single frame AND chunking is available. Sized so the full
    // buffered message (envelope + payload) fits both the large-response store and
    // the negotiated max SPDM message size; empty otherwise (forcing inline).
    let large_cap = if V::USES_LARGE_RESPONSE && state.chunking_enabled() {
        state
            .effective_max_spdm_msg_size(pal)
            .min(pal.large_capacity())
            .saturating_sub(envelope)
            .min(V::LARGE_RESPONSE_CAPACITY)
    } else {
        0
    };

    // Take the persistent large-message buffer directly (no scratch hop): the
    // backend writes its payload at offsets [envelope..envelope+large_cap] in
    // the same static slice that `CHUNK_GET` will later serve from. The envelope
    // is written into [0..envelope] only after the backend reports `Large(n)`.
    // The guard must be dropped before invoking any other `large_*` PAL method
    // (e.g. `chunk::start_buffered_large_response` calls `large_capacity`).
    let mut large_guard = if large_cap > 0 {
        Some(pal.alloc_large_buf(envelope + large_cap)?)
    } else {
        None
    };

    let outcome = {
        let large_slice: &mut [u8] = match large_guard.as_deref_mut() {
            Some(buf) => &mut buf[envelope..envelope + large_cap],
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
            // Drop the static-buffer guard early; not needed for inline.
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
            // Backend has written its payload at static_buf[envelope..envelope+n].
            // Frame the VENDOR_DEFINED envelope in-place at offset 0.
            write_vendor_defined_envelope(
                version,
                decoded.standard_id,
                decoded.vendor_id,
                n,
                &mut guard[..envelope],
            )?;
            let full_len = envelope + n;
            state.large_buf = Some(guard);
            chunk::validate_buffered_large_response::<Pal>(state, pal, full_len)?;
            let resp = chunk::start_buffered_large_response(state, pal, io, full_len)?;
            Ok((resp, 0))
        }
    }
}

/// Frames the VENDOR_DEFINED_RESPONSE envelope (SPDM header + param1/param2 +
/// standard_id + vendor_id + resp_len) directly into `out` (which must be sized
/// to the envelope). The backend's payload is expected to follow at the same
/// buffer's offset `out.len()`.
fn write_vendor_defined_envelope(
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

    let mut o = 0usize;
    let mut put = |bytes: &[u8]| -> SpdmResult<()> {
        let end = o.checked_add(bytes.len()).ok_or(SPDM_UNSPECIFIED)?;
        out.get_mut(o..end)
            .ok_or(SPDM_UNSPECIFIED)?
            .copy_from_slice(bytes);
        o = end;
        Ok(())
    };

    put(hdr.as_bytes())?;
    put(&[0u8, 0u8])?; // param1, param2
    put(&standard_id.to_le_bytes())?;
    put(&[vendor_id.len() as u8])?;
    put(vendor_id)?;
    put(&resp_len.to_le_bytes())?;
    Ok(())
}
