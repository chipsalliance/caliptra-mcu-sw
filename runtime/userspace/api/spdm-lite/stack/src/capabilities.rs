// Licensed under the Apache-2.0 license

//! `GET_CAPABILITIES` → `CAPABILITIES` handler (DSP0274 §10.3).
//!
//! On a successful exchange this handler:
//!
//! 1. Verifies the connection is in [`Phase::AfterVersion`].
//! 2. Negotiates the SPDM version using the requester's
//!    common-header `version` byte (must be one of
//!    [`SUPPORTED_VERSIONS`](crate::version::SUPPORTED_VERSIONS)).
//! 3. Validates the V1.2+ `CapabilitiesBody` fields per §10.3 Table 11.
//! 4. Stashes the peer's advertised `DataTransferSize`,
//!    `MaxSPDMmsgSize`, and capability flags into [`ConnectionState`].
//! 5. Builds the `CAPABILITIES` response from the responder's fixed
//!    local policy, then transitions to [`Phase::AfterCapabilities`].

use mcu_spdm_lite_codec::{
    CapFlags, CapabilitiesBody, CapabilitiesRsp, ResponseBody, SpdmMsgHdrPdu, SpdmVersion,
};
use mcu_spdm_lite_traits::{PalBytes, SpdmPal, SpdmPalIo, SpdmPalIoTransport};
use zerocopy::FromBytes;

use crate::build::build_response;
use crate::error::{
    SpdmResult, SPDM_INVALID_REQUEST, SPDM_UNEXPECTED_REQUEST, SPDM_VERSION_MISMATCH,
};
use crate::stack::{ConnectionState, Phase};
use crate::version::SUPPORTED_VERSIONS;

/// Handles a `GET_CAPABILITIES` request.
///
/// # Parameters
///
/// * `state` — Mutable connection state. On success, peer capability
///   fields are populated and `phase` advances to
///   [`Phase::AfterCapabilities`].
/// * `pal` — Borrowed PAL used to allocate the response and query
///   `mtu()` for the responder's `DataTransferSize` /
///   `MaxSPDMmsgSize` fields.
/// * `io` — The I/O handle for the current request.
///
/// # Returns
///
/// * `Ok(PalBytes)` — Fully-encoded `CAPABILITIES` response, ready to
///   send.
///
/// # Errors
///
/// * [`SPDM_UNEXPECTED_REQUEST`] — connection is not in
///   [`Phase::AfterVersion`].
/// * [`SPDM_INVALID_REQUEST`] — header undecodable, body too short,
///   any reserved field non-zero, `ct_exponent` out of range, or
///   `DataTransferSize` / `MaxSPDMmsgSize` violate §10.3 Table 11.
/// * [`SPDM_VERSION_MISMATCH`] — requested version is not in
///   [`SUPPORTED_VERSIONS`].
pub(crate) async fn handle_get_capabilities<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
) -> SpdmResult<PalBytes<'a, Pal>> {
    if state.phase != Phase::AfterVersion {
        return Err(SPDM_UNEXPECTED_REQUEST);
    }

    let req = io.request();
    let (hdr, rest) = SpdmMsgHdrPdu::ref_from_prefix(req).map_err(|_| SPDM_INVALID_REQUEST)?;
    let version = select_version(state, hdr.version)?;

    let body = CapabilitiesBody::ref_from_bytes(
        rest.get(..CapabilitiesBody::SIZE)
            .ok_or(SPDM_INVALID_REQUEST)?,
    )
    .map_err(|_| SPDM_INVALID_REQUEST)?;

    let (peer_dts, peer_max) = validate_capabilities_body(body)?;
    state.peer_data_transfer_size = peer_dts;
    state.peer_max_spdm_msg_size = peer_max;
    state.peer_cap_flags = body.flags;

    let mtu = pal.mtu() as u32;
    let max_spdm_msg_size = (pal.large_message_capacity().max(pal.mtu())) as u32;
    let body = CapabilitiesRsp {
        ct_exponent: state.ct_exponent,
        flags: state.cap_flags,
        data_transfer_size: mtu,
        max_spdm_msg_size,
    };
    let spdm_len = body.encoded_size();
    let resp = build_response(pal, io, version, &body)?;

    // DSP0274 §10.4.1: GET_CAPABILITIES + CAPABILITIES contribute to VCA.
    let head = pal.header_size();
    state.transcript.append_vca(pal, io, io.request()).await?;
    state
        .transcript
        .append_vca(pal, io, &resp[head..head + spdm_len])
        .await?;

    state.phase = Phase::AfterCapabilities;
    Ok(resp)
}

/// Validates a `CapabilitiesBody` against DSP0274 §10.3 Table 11.
///
/// # Parameters
///
/// * `body` — Decoded V1.2+ request body.
///
/// # Returns
///
/// `(peer_data_transfer_size, peer_max_spdm_msg_size)` extracted from
/// `body` after all reserved-field / range / CHUNK consistency checks
/// pass.
///
/// # Errors
///
/// * [`SPDM_INVALID_REQUEST`] — any reserved field is non-zero,
///   `ct_exponent` exceeds the spec maximum, `DataTransferSize` is
///   below the spec minimum or above `MaxSPDMmsgSize`, or the
///   requester clears `CHUNK` but advertises
///   `DataTransferSize != MaxSPDMmsgSize`.
fn validate_capabilities_body(body: &CapabilitiesBody) -> SpdmResult<(u32, u32)> {
    // Param1/Param2 are reserved in V1.2; Param1 bit 0 = "Supported
    // Algorithms request" in V1.3, which we don't implement, so both
    // versions require these bytes to be zero.
    if body.param1 != 0 || body.param2 != 0 || body.reserved != 0 || body.reserved2 != [0; 2] {
        return Err(SPDM_INVALID_REQUEST);
    }
    if body.ct_exponent > CapabilitiesBody::MAX_CT_EXPONENT {
        return Err(SPDM_INVALID_REQUEST);
    }

    let peer_dts = body.data_transfer_size.get();
    let peer_max = body.max_spdm_msg_size.get();
    if peer_dts < CapabilitiesBody::MIN_DATA_TRANSFER_SIZE || peer_dts > peer_max {
        return Err(SPDM_INVALID_REQUEST);
    }
    // A requester without CHUNK can't reassemble large messages, so
    // it must advertise a single size.
    if !body.flags.contains(CapFlags::CHUNK) && peer_dts != peer_max {
        return Err(SPDM_INVALID_REQUEST);
    }
    Ok((peer_dts, peer_max))
}

/// Picks the negotiated SPDM version and records it on `state`.
///
/// # Parameters
///
/// * `state` — Connection state; `state.version` is updated on success.
/// * `requested` — Raw `version` byte from the request's common header.
///
/// # Returns
///
/// * `Ok(SpdmVersion)` — Decoded, supported version.
///
/// # Errors
///
/// * [`SPDM_VERSION_MISMATCH`] — byte is not a recognised version or
///   not in [`SUPPORTED_VERSIONS`].
fn select_version<S: Clone>(
    state: &mut ConnectionState<S>,
    requested: u8,
) -> SpdmResult<SpdmVersion> {
    let v = SpdmVersion::from_u8(requested).ok_or(SPDM_VERSION_MISMATCH)?;
    if !SUPPORTED_VERSIONS.contains(&v) {
        return Err(SPDM_VERSION_MISMATCH);
    }
    state.version = v;
    Ok(v)
}
