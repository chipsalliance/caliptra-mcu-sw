// Licensed under the Apache-2.0 license

//! `GET_CAPABILITIES` → `CAPABILITIES` handler.
//!
//! On a successful exchange this handler:
//!
//! 1. Verifies the connection is in [`Phase::AfterVersion`].
//! 2. Negotiates the SPDM version using the requester's
//!    common-header `version` byte (must be one of
//!    [`SUPPORTED_VERSIONS`](crate::version::SUPPORTED_VERSIONS)).
//! 3. Validates the V1.2+ `CapabilitiesBody` fields per the corresponding table.
//! 4. Stashes the peer's advertised `DataTransferSize`,
//!    `MaxSPDMmsgSize`, and capability flags into [`ConnectionState`].
//! 5. Builds the `CAPABILITIES` response from the responder's fixed
//!    local policy, then transitions to [`Phase::AfterCapabilities`].
//! 6. Replays an identical fixed-format retry from bounded connection state
//!    without changing phase or appending to VCA again.

use caliptra_mcu_spdm_codec::{
    CapFlags, CapabilitiesBody, CapabilitiesRsp, SpdmMsgHdrPdu, SpdmVersion,
};
use caliptra_mcu_spdm_traits::{PalBytes, SpdmPal, SpdmPalAlloc, SpdmPalIo, SpdmPalIoTransport};
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
/// * [`SPDM_UNEXPECTED_REQUEST`] — connection is not in an allowed phase,
///   or any post-success request is not byte-equivalent to the original.
/// * [`SPDM_INVALID_REQUEST`] — an initial request length is not exactly the
///   fixed wire length, any reserved field is non-zero, `ct_exponent` is out
///   of range, or `DataTransferSize` / `MaxSPDMmsgSize` violate the
///   corresponding table.
/// * [`SPDM_VERSION_MISMATCH`] — requested version is not in
///   [`SUPPORTED_VERSIONS`].
pub(crate) async fn handle_get_capabilities<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
) -> SpdmResult<PalBytes<'a, Pal>> {
    let is_retry = match state.phase {
        Phase::AfterVersion => false,
        Phase::AfterCapabilities => true,
        _ => return Err(SPDM_UNEXPECTED_REQUEST),
    };

    let req = io.request();
    let expected_len = SpdmMsgHdrPdu::SIZE + CapabilitiesBody::SIZE;

    if is_retry {
        // Retry identity must be checked before normal request validation.
        // Any differing bytes constitute a non-identical repeat and receive
        // UnexpectedRequest, including malformed lengths, reserved fields,
        // and mismatched versions.
        let identical = req.len() == expected_len
            && SpdmMsgHdrPdu::ref_from_prefix(req)
                .ok()
                .and_then(|(hdr, rest)| {
                    CapabilitiesBody::ref_from_bytes(rest)
                        .ok()
                        .map(|body| (hdr, body))
                })
                .is_some_and(|(hdr, body)| {
                    hdr.version == state.version.to_u8()
                        && body.param1 == 0
                        && body.param2 == 0
                        && body.reserved == 0
                        && body.reserved2 == [0; 2]
                        && body.ct_exponent == state.peer_ct_exponent
                        && body.flags == state.peer_cap_flags
                        && body.data_transfer_size.get() == state.peer_data_transfer_size
                        && body.max_spdm_msg_size.get() == state.peer_max_spdm_msg_size
                });
        if !identical {
            return Err(SPDM_UNEXPECTED_REQUEST);
        }

        // The original response is reproducible from fixed local policy and
        // the stored negotiated response flags. Do not append VCA again or
        // change phase on a retry.
        return build_capabilities_response(
            state,
            pal,
            io,
            state.version,
            state.advertised_cap_flags,
        );
    }

    let (hdr, rest) = SpdmMsgHdrPdu::ref_from_prefix(req).map_err(|_| SPDM_INVALID_REQUEST)?;
    let version = select_version(hdr.version)?;
    if req.len() != expected_len {
        return Err(SPDM_INVALID_REQUEST);
    }
    let body = CapabilitiesBody::ref_from_bytes(rest).map_err(|_| SPDM_INVALID_REQUEST)?;
    let (peer_dts, peer_max) = validate_capabilities_body(body)?;

    let mut flags = state.cap_flags;
    if version < SpdmVersion::V13 {
        let cleared = flags.into_bits() & !(0b11 << 26);
        flags = CapFlags::from_bits(cleared);
    }
    if !pal.secure_message_supported() {
        let secure_session_caps = CapFlags::KEY_EX | CapFlags::ENCRYPT | CapFlags::MAC;
        flags = CapFlags::from_bits(flags.into_bits() & !secure_session_caps.into_bits());
    }
    let resp = build_capabilities_response(state, pal, io, version, flags)?;
    let spdm_len = SpdmMsgHdrPdu::SIZE + CapabilitiesBody::SIZE;

    // SPDM: GET_CAPABILITIES + CAPABILITIES contribute to VCA. Commit the
    // request identity only after the whole first exchange succeeds; retries
    // therefore cannot appear to have completed a failed exchange.
    let head = pal.header_size();
    state.transcript.append_vca(pal, io, req).await?;
    state
        .transcript
        .append_vca(pal, io, &resp[head..head + spdm_len])
        .await?;

    state.version = version;
    state.peer_data_transfer_size = peer_dts;
    state.peer_max_spdm_msg_size = peer_max;
    state.peer_cap_flags = body.flags;
    state.peer_ct_exponent = body.ct_exponent;
    state.advertised_cap_flags = flags;
    state.phase = Phase::AfterCapabilities;
    Ok(resp)
}

/// Rebuilds the fixed-size CAPABILITIES response from connection-local state.
///
/// This is intentionally command-specific rather than a response cache: the
/// original response contains only fixed local policy and transport limits.
fn build_capabilities_response<'a, Pal: SpdmPal>(
    state: &ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    version: SpdmVersion,
    flags: CapFlags,
) -> SpdmResult<PalBytes<'a, Pal>> {
    let mtu = pal.mtu();
    let max_spdm_msg_size = if flags.contains(CapFlags::CHUNK) {
        pal.large_capacity().max(mtu)
    } else {
        mtu
    } as u32;
    let body = CapabilitiesRsp {
        ct_exponent: state.ct_exponent,
        flags,
        data_transfer_size: mtu as u32,
        max_spdm_msg_size,
    };
    build_response(pal, io, version, &body)
}

/// Validates a `CapabilitiesBody` against SPDM the corresponding table.
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
///   `ct_exponent` exceeds the protocol maximum, `DataTransferSize` is
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

/// Picks the negotiated SPDM version without changing connection state.
///
/// Keeping version selection pure is important for retry handling: a
/// non-identical repeat must not partially mutate the negotiated connection.
///
/// # Parameters
///
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
fn select_version(requested: u8) -> SpdmResult<SpdmVersion> {
    let v = SpdmVersion::from_u8(requested).ok_or(SPDM_VERSION_MISMATCH)?;
    if !SUPPORTED_VERSIONS.contains(&v) {
        return Err(SPDM_VERSION_MISMATCH);
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::measurements::support;
    use futures::executor::block_on;
    use std::vec::Vec;
    use zerocopy::{little_endian::U32, IntoBytes};

    const REQUEST_CT_EXPONENT: u8 = 10;
    const REQUEST_FLAGS: CapFlags = CapFlags::from_bits((1 << 17) | (1 << 1));
    const REQUEST_DATA_TRANSFER_SIZE: u32 = 512;
    const REQUEST_MAX_SPDM_MSG_SIZE: u32 = 1024;

    fn capabilities_request(
        version: SpdmVersion,
        ct_exponent: u8,
        flags: CapFlags,
        data_transfer_size: u32,
        max_spdm_msg_size: u32,
    ) -> Vec<u8> {
        let hdr = SpdmMsgHdrPdu::new(
            version,
            caliptra_mcu_spdm_codec::ReqRespCode::GET_CAPABILITIES,
        );
        let body = CapabilitiesBody {
            param1: 0,
            param2: 0,
            reserved: 0,
            ct_exponent,
            reserved2: [0; 2],
            flags,
            data_transfer_size: U32::new(data_transfer_size),
            max_spdm_msg_size: U32::new(max_spdm_msg_size),
        };
        let mut request = Vec::with_capacity(SpdmMsgHdrPdu::SIZE + CapabilitiesBody::SIZE);
        request.extend_from_slice(hdr.as_bytes());
        request.extend_from_slice(body.as_bytes());
        request
    }

    fn default_request(version: SpdmVersion) -> Vec<u8> {
        capabilities_request(
            version,
            REQUEST_CT_EXPONENT,
            REQUEST_FLAGS,
            REQUEST_DATA_TRANSFER_SIZE,
            REQUEST_MAX_SPDM_MSG_SIZE,
        )
    }

    fn first_exchange(
        state: &mut ConnectionState<support::TestHashState, Vec<u8>>,
        pal: &support::TestPal,
        request: Vec<u8>,
    ) -> Vec<u8> {
        state.phase = Phase::AfterVersion;
        let io = support::TestIo::message(request);
        block_on(handle_get_capabilities(state, pal, &io)).unwrap()
    }

    #[test]
    fn identical_retry_replays_response_without_phase_or_transcript_change() {
        for version in [SpdmVersion::V12, SpdmVersion::V13] {
            let pal = support::TestPal::default();
            let mut state = ConnectionState::caliptra();
            let request = default_request(version);
            let first = first_exchange(&mut state, &pal, request.clone());
            let phase = state.phase;
            let vca_updates = state.transcript.vca.as_ref().unwrap().updates;

            let retry_io = support::TestIo::message(request);
            let retry = block_on(handle_get_capabilities(&mut state, &pal, &retry_io)).unwrap();

            assert_eq!(retry, first);
            assert_eq!(state.phase, phase);
            assert_eq!(state.phase, Phase::AfterCapabilities);
            assert_eq!(state.transcript.vca.as_ref().unwrap().updates, vca_updates);
        }
    }

    #[test]
    fn non_identical_valid_retries_are_rejected() {
        let cases = [
            (
                SpdmVersion::V12,
                REQUEST_CT_EXPONENT + 1,
                REQUEST_FLAGS,
                REQUEST_DATA_TRANSFER_SIZE,
                REQUEST_MAX_SPDM_MSG_SIZE,
            ),
            (
                SpdmVersion::V12,
                REQUEST_CT_EXPONENT,
                CapFlags::from_bits((1 << 17) | (1 << 2)),
                REQUEST_DATA_TRANSFER_SIZE,
                REQUEST_MAX_SPDM_MSG_SIZE,
            ),
            (
                SpdmVersion::V12,
                REQUEST_CT_EXPONENT,
                REQUEST_FLAGS,
                REQUEST_DATA_TRANSFER_SIZE + 1,
                REQUEST_MAX_SPDM_MSG_SIZE,
            ),
            (
                SpdmVersion::V12,
                REQUEST_CT_EXPONENT,
                REQUEST_FLAGS,
                REQUEST_DATA_TRANSFER_SIZE,
                REQUEST_MAX_SPDM_MSG_SIZE + 1,
            ),
            (
                SpdmVersion::V13,
                REQUEST_CT_EXPONENT,
                REQUEST_FLAGS,
                REQUEST_DATA_TRANSFER_SIZE,
                REQUEST_MAX_SPDM_MSG_SIZE,
            ),
        ];

        for (version, ct_exponent, flags, data_transfer_size, max_spdm_msg_size) in cases {
            let pal = support::TestPal::default();
            let mut state = ConnectionState::caliptra();
            let original = default_request(SpdmVersion::V12);
            first_exchange(&mut state, &pal, original);
            let vca_updates = state.transcript.vca.as_ref().unwrap().updates;

            let changed = capabilities_request(
                version,
                ct_exponent,
                flags,
                data_transfer_size,
                max_spdm_msg_size,
            );
            let io = support::TestIo::message(changed);
            assert_eq!(
                block_on(handle_get_capabilities(&mut state, &pal, &io)),
                Err(SPDM_UNEXPECTED_REQUEST)
            );
            assert_eq!(state.phase, Phase::AfterCapabilities);
            assert_eq!(state.transcript.vca.as_ref().unwrap().updates, vca_updates);
        }
    }

    #[test]
    fn unsupported_version_is_reported_before_initial_body_length_validation() {
        let pal = support::TestPal::default();
        let mut state = ConnectionState::caliptra();
        state.phase = Phase::AfterVersion;
        let mut request = SpdmMsgHdrPdu::new(
            SpdmVersion::V11,
            caliptra_mcu_spdm_codec::ReqRespCode::GET_CAPABILITIES,
        )
        .as_bytes()
        .to_vec();
        request.extend_from_slice(&[0; 3]);
        let io = support::TestIo::message(request);

        assert_eq!(
            block_on(handle_get_capabilities(&mut state, &pal, &io)),
            Err(SPDM_VERSION_MISMATCH)
        );
    }

    #[test]
    fn requests_in_other_phases_are_unexpected_before_body_validation() {
        let pal = support::TestPal::default();
        let mut state = ConnectionState::caliptra();
        let io = support::TestIo::message(Vec::new());

        assert_eq!(
            block_on(handle_get_capabilities(&mut state, &pal, &io)),
            Err(SPDM_UNEXPECTED_REQUEST)
        );
    }

    #[test]
    fn malformed_and_trailing_retries_are_unexpected_non_identical_requests() {
        let pal = support::TestPal::default();
        let mut state = ConnectionState::caliptra();
        let request = default_request(SpdmVersion::V12);
        first_exchange(&mut state, &pal, request.clone());
        let vca_updates = state.transcript.vca.as_ref().unwrap().updates;

        let mut retries = Vec::new();

        let mut trailing = request.clone();
        trailing.push(0);
        retries.push(trailing);

        let mut short = request.clone();
        short.pop();
        retries.push(short);

        let mut reserved_param = request;
        reserved_param[SpdmMsgHdrPdu::SIZE + 1] = 1;
        retries.push(reserved_param);

        for retry in retries {
            let io = support::TestIo::message(retry);
            assert_eq!(
                block_on(handle_get_capabilities(&mut state, &pal, &io)),
                Err(SPDM_UNEXPECTED_REQUEST)
            );
        }
        assert_eq!(state.phase, Phase::AfterCapabilities);
        assert_eq!(state.transcript.vca.as_ref().unwrap().updates, vca_updates);
    }

    #[test]
    fn reset_clears_get_capabilities_retry_identity() {
        let pal = support::TestPal::default();
        let mut state = ConnectionState::caliptra();
        let request = default_request(SpdmVersion::V12);
        first_exchange(&mut state, &pal, request.clone());

        state.reset_negotiation();
        assert_eq!(state.phase, Phase::Start);
        assert_eq!(state.peer_data_transfer_size, 0);
        assert_eq!(state.peer_max_spdm_msg_size, 0);
        assert_eq!(
            state.peer_cap_flags.into_bits(),
            CapFlags::EMPTY.into_bits()
        );
        assert_eq!(state.peer_ct_exponent, 0);
        assert!(state.transcript.vca.is_none());

        let retry_io = support::TestIo::message(request);
        assert_eq!(
            block_on(handle_get_capabilities(&mut state, &pal, &retry_io)),
            Err(SPDM_UNEXPECTED_REQUEST)
        );
    }
}
