// Licensed under the Apache-2.0 license

//! GET_VERSION → VERSION handler (DSP0274 §10.2).
//!
//! Per spec the VERSION response's SPDMVersion field is **always
//! V1.0** — version negotiation happens later, in GET_CAPABILITIES.
//! GET_VERSION is legal in any phase: the dispatcher calls
//! [`ConnectionState::reset_negotiation`] before invoking us so that
//! GET_VERSION always resets the connection.

use caliptra_mcu_spdm_codec::{ResponseBody, SpdmMsgHdrPdu, SpdmVersion, VersionRsp};
use caliptra_mcu_spdm_traits::{PalBytes, SpdmPal, SpdmPalAlloc, SpdmPalIo};
use zerocopy::FromBytes;

use crate::build::build_response;
use crate::error::{SpdmResult, SPDM_INVALID_REQUEST, SPDM_VERSION_MISMATCH};
use crate::stack::{ConnectionState, Phase};

/// Versions advertised by the responder, in descending order of preference.
///
/// V1.2 is the floor because our CAPABILITIES / ALGORITHMS request
/// bodies only support the V1.2+ wire shape.
pub(crate) const SUPPORTED_VERSIONS: &[SpdmVersion] =
    &[SpdmVersion::V14, SpdmVersion::V13, SpdmVersion::V12];

/// Validate a GET_VERSION request without mutating connection or session state.
///
/// The dispatcher uses this before applying the protocol-mandated connection
/// reset so malformed GET_VERSION requests leave existing state untouched.
pub(crate) fn validate_get_version(req: &[u8]) -> SpdmResult<()> {
    let (hdr, rest) = SpdmMsgHdrPdu::ref_from_prefix(req).map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != SpdmVersion::V10.to_u8() {
        return Err(SPDM_VERSION_MISMATCH);
    }
    if rest.len() < 2 {
        return Err(SPDM_INVALID_REQUEST);
    }
    Ok(())
}

/// Handles a `GET_VERSION` request and produces the matching `VERSION` response.
///
/// The responder accepts `GET_VERSION` in **any** phase; the
/// dispatcher resets the connection (via
/// [`ConnectionState::reset_negotiation`](crate::stack::ConnectionState::reset_negotiation))
/// before calling this function.
///
/// # Parameters
///
/// * `state` — Mutable connection state. On success this is advanced
///   to [`Phase::AfterVersion`].
/// * `pal` — Borrowed PAL used to allocate the response buffer and
///   query the transport header size.
/// * `io` — The I/O handle for the current request. Provides access
///   to the raw request bytes.
///
/// # Returns
///
/// * `Ok(PalBytes)` — The fully-encoded `VERSION` response (transport
///   header + SPDM common header + body). Always carries
///   [`SpdmVersion::V10`] per DSP0274 §10.2.
///
/// # Errors
///
/// * Allocator / codec errors from [`build_response`] propagate via
///   `?` and end up as [`SPDM_BUSY`](crate::error::SPDM_BUSY) /
///   [`SPDM_INVALID_REQUEST`] respectively.
pub(crate) async fn handle_get_version<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &'a Pal,
    io: &Pal::Io<'_>,
) -> SpdmResult<PalBytes<'a, Pal>> {
    let body = VersionRsp {
        versions: SUPPORTED_VERSIONS,
    };
    let spdm_len = body.encoded_size();
    let resp = build_response(pal, io, SpdmVersion::V10, &body)?;

    // DSP0274 §10.4.1: GET_VERSION + VERSION contribute to VCA.
    // Use spdm_len to exclude any transport-layer padding (e.g. DOE DWORD alignment).
    let head = pal.header_size();
    // Trim transport padding (e.g. PCIe-VDM DWORD alignment): only the exact
    // 4-byte GET_VERSION message (header + Param1 + Param2) contributes to VCA,
    // matching what the requester hashes.
    let req_msg = io
        .request()
        .get(..SpdmMsgHdrPdu::SIZE + 2)
        .ok_or(SPDM_INVALID_REQUEST)?;
    state.transcript.append_vca(pal, io, req_msg).await?;
    state
        .transcript
        .append_vca(pal, io, &resp[head..head + spdm_len])
        .await?;

    state.phase = Phase::AfterVersion;
    Ok(resp)
}
