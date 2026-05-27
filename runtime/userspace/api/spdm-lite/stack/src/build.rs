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

use mcu_spdm_lite_codec::{ResponseBody, SpdmVersion, WireWriter};
use mcu_spdm_lite_traits::{PalBytes, SpdmPal};

use crate::error::SpdmResult;

/// Allocate a buffer of `raw_len` bytes, rounded up to the transport's
/// [`send_len_alignment`](SpdmPalIoTransport::send_len_alignment).
/// Padding bytes are zeroed.
fn alloc_padded<'a, Pal: SpdmPal>(
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
///   [`SpdmPalIoTransport::send_response`](mcu_spdm_lite_traits::SpdmPalIoTransport::send_response).
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

/// Non-generic helper for the error path. Builds an ERROR PDU
/// (DSP0274 §10.10) without going through the generic
/// [`build_response`] — saves one monomorphisation worth of code and
/// keeps the dispatcher's error branch tiny.
#[inline(never)]
pub(crate) fn build_error_response<'a, Pal: SpdmPal>(
    pal: &'a Pal,
    io: &Pal::Io<'_>,
    version: SpdmVersion,
    error_code: u8,
    error_data: u8,
    extended_data: &[u8],
) -> SpdmResult<PalBytes<'a, Pal>> {
    use mcu_spdm_lite_codec::{ReqRespCode, SpdmMsgHdrPdu};
    let head = pal.header_size();
    let raw_len = head + SpdmMsgHdrPdu::SIZE + 2 + extended_data.len();
    let mut buf = alloc_padded(pal, io, raw_len)?;
    let mut w = WireWriter::new(&mut buf[head..]);
    w.write(&SpdmMsgHdrPdu::new(version, ReqRespCode::ERROR))?;
    w.write(&[error_code, error_data])?;
    w.write(extended_data)?;
    Ok(buf)
}
