// Licensed under the Apache-2.0 license

//! Shared response-building helper used by every SPDM handler.
//!
//! [`build_response`] allocates one contiguous buffer big enough for
//! `transport_header || spdm_common_header || body`, asks the body to
//! encode itself at the right offset, and hands the owning
//! [`PalBytes`] back to the handler — which returns it unchanged to
//! the dispatcher.
//!
//! Centralising this here means handlers never compute byte offsets,
//! never touch the PAL allocator directly, and never forget to
//! reserve the transport-framing header.

use caliptra_mcu_spdm_codec::{
    ReqRespCode, ResponseBody, SpdmMsgHdrPdu, SpdmVersion, WireWriter, SHA384_HASH_SIZE,
};
use caliptra_mcu_spdm_traits::{
    PalBytes, SigningInput, SpdmPal, SpdmPalAlloc, SpdmPalAsymAlgo, SpdmPalHashAlgo,
    SpdmPalIoTransport,
};

use crate::chunk;
use crate::error::{SpdmError, SpdmResult, SPDM_UNSPECIFIED};
use crate::stack::ConnectionState;

/// Copy a fixed-size array `src` into `buf` at `pos`, returning the advanced
/// cursor.
///
/// Bounds are checked once via [`slice::first_chunk_mut`]; the const-`M` copy
/// then carries no length check. An out-of-range write (unreachable for the
/// fixed-layout signing-context builders) is a no-op rather than a panic, so
/// this stays free of `panic_bounds_check` in the RoT codepath.
pub(crate) fn write_fixed<const M: usize>(buf: &mut [u8], pos: usize, src: &[u8; M]) -> usize {
    if let Some(slot) = buf.get_mut(pos..).and_then(|s| s.first_chunk_mut::<M>()) {
        *slot = *src;
    }
    pos.saturating_add(M)
}

/// Allocate a buffer of `raw_len` bytes, rounded up to the transport's
/// [`send_len_alignment`](SpdmPalIoTransport::send_len_alignment).
/// Padding bytes are zeroed.
pub(crate) fn alloc_padded<'a, Pal: SpdmPal>(
    pal: &'a Pal,
    io: &Pal::Io<'_>,
    raw_len: usize,
) -> SpdmResult<PalBytes<'a, Pal>> {
    let align = pal.send_len_alignment();
    debug_assert!(align > 0 && align.is_power_of_two());
    let alloc_len = (raw_len + align - 1) & !(align - 1);
    let mut buf = pal.alloc_bytes(io, alloc_len)?;
    for b in &mut buf[raw_len..alloc_len] {
        *b = 0;
    }
    Ok(buf)
}

/// Round `len` up to the transport's
/// [`send_len_alignment`](caliptra_mcu_spdm_traits::SpdmPalIoTransport::send_len_alignment).
pub(crate) fn align_send_len<Pal: SpdmPal>(pal: &Pal, len: usize) -> SpdmResult<usize> {
    let align = pal.send_len_alignment();
    if align == 0 {
        return Err(SPDM_UNSPECIFIED);
    }
    len.checked_add(align - 1)
        .map(|n| (n / align) * align)
        .ok_or(SPDM_UNSPECIFIED)
}

/// Zero `buf[start..end]`.
pub(crate) fn zero_slice(buf: &mut [u8], start: usize, end: usize) -> SpdmResult<()> {
    let dst = buf.get_mut(start..end).ok_or(SPDM_UNSPECIFIED)?;
    dst.fill(0);
    Ok(())
}

/// Move `buf[src..src + len]` down to offset 0, dropping transport headroom.
pub(crate) fn shift_left(buf: &mut [u8], src: usize, len: usize) -> SpdmResult<()> {
    let end = src.checked_add(len).ok_or(SPDM_UNSPECIFIED)?;
    if end > buf.len() || len > buf.len() {
        return Err(SPDM_UNSPECIFIED);
    }

    // SAFETY: Bounds are checked above and `ptr::copy` handles overlapping
    // ranges, which is required when removing transport headroom in-place.
    unsafe {
        core::ptr::copy(buf.as_ptr().add(src), buf.as_mut_ptr(), len);
    }
    Ok(())
}

/// Allocates and encodes an SPDM response.
///
/// The returned buffer is laid out as:
///
/// ```text
///   [ transport header | SPDM common header | response body ]
///         header_size                              body.encoded_size()
/// ```
///
/// The transport header is left uninitialised — the PAL transport
/// fills it in-place inside `send_response`.
///
/// # Parameters
///
/// * `pal` — Reference to the responder's [`SpdmPal`]. Used both as
///   the allocator (for the response buffer) and as the source of
///   `header_size()`.
/// * `io` — The current request's I/O handle. Forwarded to
///   [`SpdmPalAlloc::alloc_bytes`] so the PAL can scope the
///   allocation to this exchange.
/// * `version` — SPDM version to put in the common-header `version`
///   byte (DSP0274 §10.1).
/// * `body` — The response body that will be encoded after the common
///   header. Anything implementing [`ResponseBody`] works.
///
/// # Returns
///
/// * `Ok(PalBytes)` — Owning handle to the fully-encoded response,
///   ready to pass to
///   [`SpdmPalIoTransport::send_response`](caliptra_mcu_spdm_traits::SpdmPalIoTransport::send_response).
/// * `Err(SpdmError)` — Either the PAL allocator was exhausted (mapped
///   to [`SPDM_BUSY`](crate::error::SPDM_BUSY)) or the codec failed
///   while encoding the body (mapped to
///   [`SPDM_INVALID_REQUEST`](crate::error::SPDM_INVALID_REQUEST));
///   conversions are handled implicitly by `?`.
///   Allocates and encodes an SPDM response.
///
/// Marked `#[inline(never)]` to keep handler-level code out of the
/// dispatcher's async state machine. Each `B` still produces its own
/// monomorphisation, but they're emitted as separate functions rather
/// than inlined four times into one giant `poll`.
#[inline(never)]
pub(crate) fn build_response<'a, Pal, B>(
    pal: &'a Pal,
    io: &Pal::Io<'_>,
    version: SpdmVersion,
    body: &B,
) -> SpdmResult<PalBytes<'a, Pal>>
where
    Pal: SpdmPal,
    B: ResponseBody,
{
    let head = pal.header_size();
    let raw_len = head + body.encoded_size();
    let mut buf = alloc_padded(pal, io, raw_len)?;
    body.encode_with_header(version, &mut WireWriter::new(&mut buf[head..]))?;
    Ok(buf)
}

/// Encodes an SPDM ERROR PDU into an existing buffer.
pub(crate) fn encode_error_response(
    out: &mut [u8],
    version: SpdmVersion,
    error: SpdmError,
) -> SpdmResult<usize> {
    let extended_data = error.extended_data();
    let mut w = WireWriter::new(out);
    w.write(&SpdmMsgHdrPdu::new(version, ReqRespCode::ERROR))?;
    w.write(&[error.spec_byte(), error.error_data()])?;
    w.write(extended_data)?;
    Ok(SpdmMsgHdrPdu::SIZE + 2 + extended_data.len())
}

/// Non-generic helper for the error path. Builds an ERROR PDU without going
/// through the generic [`build_response`], saving one monomorphisation and
/// keeping the dispatcher's error branch tiny.
#[inline(never)]
pub(crate) fn build_error_response<'a, Pal: SpdmPal>(
    pal: &'a Pal,
    io: &Pal::Io<'_>,
    version: SpdmVersion,
    error: SpdmError,
) -> SpdmResult<PalBytes<'a, Pal>> {
    let head = pal.header_size();
    let raw_len = head + SpdmMsgHdrPdu::SIZE + 2 + error.extended_data().len();
    let mut buf = alloc_padded(pal, io, raw_len)?;
    encode_error_response(&mut buf[head..], version, error)?;
    Ok(buf)
}

pub(crate) const SPDM_PREFIX_LEN: usize = 64;
pub(crate) const SPDM_CONTEXT_LEN: usize = 36;
pub(crate) const SPDM_SIGNING_CONTEXT_LEN: usize = SPDM_PREFIX_LEN + SPDM_CONTEXT_LEN;

/// Construct the 100-byte SPDM signing context into `out`.
///
/// Layout: 4 × "dmtf-spdm-v<x>.<y>.*" (prefix, 64 B) || zero-pad || op (36 B).
pub(crate) fn build_spdm_signing_context(
    version: SpdmVersion,
    op: &[u8],
    out: &mut [u8; SPDM_SIGNING_CONTEXT_LEN],
) -> SpdmResult<()> {
    if op.len() > SPDM_CONTEXT_LEN {
        return Err(SPDM_UNSPECIFIED);
    }
    out.fill(0);
    let ver_str: &[u8; 5] = match version {
        SpdmVersion::V10 => b"1.0.*",
        SpdmVersion::V11 => b"1.1.*",
        SpdmVersion::V12 => b"1.2.*",
        SpdmVersion::V13 => b"1.3.*",
        SpdmVersion::V14 => b"1.4.*",
    };
    let base = b"dmtf-spdm-v";
    let mut pos = 0;
    for _ in 0..4 {
        out[pos..pos + base.len()].copy_from_slice(base);
        pos += base.len();
        out[pos..pos + ver_str.len()].copy_from_slice(ver_str);
        pos += ver_str.len();
    }
    let pad = SPDM_CONTEXT_LEN - op.len();
    out[SPDM_PREFIX_LEN + pad..].copy_from_slice(op);
    Ok(())
}

#[cfg(test)]
pub(crate) fn spdm_signing_context(
    version: SpdmVersion,
    op: &[u8],
) -> SpdmResult<[u8; SPDM_SIGNING_CONTEXT_LEN]> {
    let mut ctx = [0u8; SPDM_SIGNING_CONTEXT_LEN];
    build_spdm_signing_context(version, op, &mut ctx)?;
    Ok(ctx)
}

async fn compute_tbs_hash<Pal: SpdmPal>(
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    signing_ctx: &[u8; SPDM_SIGNING_CONTEXT_LEN],
    transcript_hash: &mut [u8; SHA384_HASH_SIZE],
) -> mcu_error::McuResult<()> {
    let mut state = pal
        .hash_init(io, SpdmPalHashAlgo::Sha384, signing_ctx)
        .await?;
    pal.hash_update(io, &mut state, transcript_hash).await?;
    pal.hash_finish(io, &mut state, transcript_hash).await
}

/// Sign a transcript hash with either ECDSA P-384 or ML-DSA-87.
///
/// Computes TBS hash for ECDSA or delegates pure message + context to ML-DSA.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn sign_transcript<Pal: SpdmPal>(
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    slot_id: u8,
    asym_algo: SpdmPalAsymAlgo,
    version: SpdmVersion,
    context: &'static [u8],
    transcript_hash: &mut [u8; SHA384_HASH_SIZE],
    sig_slot: &mut [u8],
    expected_sig_len: usize,
) -> SpdmResult<()> {
    let mut signing_ctx = [0u8; SPDM_SIGNING_CONTEXT_LEN];
    build_spdm_signing_context(version, context, &mut signing_ctx)?;
    let signing_input = match asym_algo {
        SpdmPalAsymAlgo::EccP384 => {
            compute_tbs_hash(pal, io, &signing_ctx, transcript_hash)
                .await
                .map_err(|_| SPDM_UNSPECIFIED)?;
            SigningInput::EccP384Digest(transcript_hash)
        }
        SpdmPalAsymAlgo::MlDsa87 => SigningInput::Mldsa87Message {
            context,
            prefix: &signing_ctx,
            hash: transcript_hash,
        },
    };
    let sig_len = pal
        .sign(io, slot_id, asym_algo, signing_input, sig_slot)
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;
    if sig_len != expected_sig_len {
        return Err(SPDM_UNSPECIFIED);
    }
    Ok(())
}

/// Finish a response allocated in a large buffer: either convert to standard
/// response if within transfer size, or start chunking.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn finish_buffered_response<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    mut guard: chunk::WipeOnDrop<<Pal as SpdmPalAlloc>::LargeBuf>,
    head: usize,
    spdm_len: usize,
    raw_len: usize,
    padded_len: usize,
    use_normal_response: bool,
) -> SpdmResult<(PalBytes<'a, Pal>, usize)> {
    let buf = guard.buf.as_mut().ok_or(SPDM_UNSPECIFIED)?;
    if use_normal_response {
        zero_slice(buf, raw_len, padded_len)?;
        let final_buf = guard.buf.take().ok_or(SPDM_UNSPECIFIED)?;
        let resp = pal
            .large_buf_into_bytes(final_buf, padded_len)
            .map_err(|_| SPDM_UNSPECIFIED)?;
        return Ok((resp, spdm_len));
    }

    shift_left(buf, head, spdm_len)?;
    let final_buf = guard.buf.take().ok_or(SPDM_UNSPECIFIED)?;
    state.large_msg_ctx.set_buffer(final_buf);
    let (resp, spdm_len) = match chunk::start_buffered_large_response(state, pal, io, spdm_len) {
        Ok(res) => res,
        Err(err) => {
            state.large_msg_ctx.reset();
            return Err(err);
        }
    };
    Ok((resp, spdm_len))
}
