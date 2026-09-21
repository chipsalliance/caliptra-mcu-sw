// Licensed under the Apache-2.0 license

//! `GET_CAPABILITIES` → `CAPABILITIES` handler.
//!
//! On a successful exchange this handler:
//!
//! 1. Verifies the connection is in [`Phase::AfterVersion`].
//! 2. Negotiates the SPDM version using the requester's
//!    common-header `version` byte (must be one of
//!    [`SUPPORTED_VERSIONS`](crate::version::SUPPORTED_VERSIONS)).
//! 3. Validates the V1.2+ `CapabilitiesBody` fields used by the responder.
//! 4. Stashes the peer's advertised `DataTransferSize`,
//!    `MaxSPDMmsgSize`, and capability flags into [`ConnectionState`].
//! 5. Builds the `CAPABILITIES` response from the responder's fixed
//!    local policy, then transitions to [`Phase::AfterCapabilities`].

use caliptra_mcu_spdm_codec::{
    CapFlags, CapabilitiesBody, CapabilitiesBodyV11, CapabilitiesRsp, ExtCapFlags, ResponseBody,
    SpdmMsgHdrPdu,
    SpdmVersion,
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
/// * `pal` — Borrowed PAL providing the single-frame and logical-request
///   receive limits.
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
///   `ct_exponent` out of range, or `DataTransferSize` /
///   `MaxSPDMmsgSize` violate the corresponding table.
/// * [`SPDM_VERSION_MISMATCH`] — requested version is not in
///   [`SUPPORTED_VERSIONS`].
pub(crate) async fn handle_get_capabilities<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
) -> SpdmResult<PalBytes<'a, Pal>> {
    if state.phase != Phase::AfterVersion {
        return Err(SPDM_UNEXPECTED_REQUEST);
    }

    let req = io.request();
    let (hdr, rest) = SpdmMsgHdrPdu::ref_from_prefix(req).map_err(|_| SPDM_INVALID_REQUEST)?;
    let version = select_version(hdr.version)?;

    // parse the version-specific GET_CAPABILITIES request body. V1.0/1.1
    // (DSP0274 1.1.1 §10.3) uses a 10-byte body that ends at Flags — it has no
    // DataTransferSize/MaxSPDMmsgSize. V1.2+ adds those two u32 fields (18-byte
    // body). A V1.1 peer cannot chunk or reassemble, so its effective transfer
    // size is the responder MTU in both directions.
    let (peer_flags, peer_dts, peer_max) = if version < SpdmVersion::V12 {
        let body = CapabilitiesBodyV11::ref_from_bytes(
            rest.get(..CapabilitiesBodyV11::SIZE)
                .ok_or(SPDM_INVALID_REQUEST)?,
        )
        .map_err(|_| SPDM_INVALID_REQUEST)?;
        validate_capabilities_body_v11(body)?;
        let mtu = pal.mtu() as u32;
        (body.flags, mtu, mtu)
    } else {
        let body = CapabilitiesBody::ref_from_bytes(
            rest.get(..CapabilitiesBody::SIZE)
                .ok_or(SPDM_INVALID_REQUEST)?,
        )
        .map_err(|_| SPDM_INVALID_REQUEST)?;
        let (dts, max) = validate_capabilities_body(body)?;
        (body.flags, dts, max)
    };
    state.version = version;
    state.peer_data_transfer_size = peer_dts;
    state.peer_max_spdm_msg_size = peer_max;
    state.peer_cap_flags = peer_flags;

    let mtu = pal.mtu();
    // Version-gate the responder cap flags (V1.3/V1.4-only bits are masked off
    // for a pre-1.3 peer by `responder_cap_mask`).
    let mut flags = CapFlags::from_bits(state.cap_flags.into_bits() & responder_cap_mask(version));
    // Gate off caps a V1.1 peer must not see. CHUNK, SET_CERT and ALIAS_CERT
    // are V1.2-introduced and did not exist in the V1.1 flag set. ENCAP *is* a
    // valid V1.1 capability (DSP0274 1.1.1 Table 16), but we clear it
    // intentionally: our encapsulated-request handling depends on V1.2+ framing
    // (V1.1 ENCAP support is tracked separately).
    if version < SpdmVersion::V12 {
        let v12plus_caps =
            CapFlags::CHUNK | CapFlags::ENCAP | CapFlags::SET_CERT | CapFlags::ALIAS_CERT;
        flags = CapFlags::from_bits(flags.into_bits() & !v12plus_caps.into_bits());
    }
    if !pal.secure_message_supported() {
        let secure_session_caps = CapFlags::KEY_EX | CapFlags::ENCRYPT | CapFlags::MAC;
        flags = CapFlags::from_bits(flags.into_bits() & !secure_session_caps.into_bits());
    }
    state.advertised_cap_flags = flags;
    // MaxSPDMmsgSize covers all buffered and streamed inbound request paths.
    let max_spdm_msg_size = if flags.contains(CapFlags::CHUNK) {
        pal.max_inbound_spdm_request_size()
    } else {
        mtu
    } as u32;
    let body = CapabilitiesRsp {
        version,
        ct_exponent: state.ct_exponent,
        // SLOT_MANAGEMENT is not implemented by this responder.
        ext_flags: ExtCapFlags::EMPTY,
        flags,
        data_transfer_size: mtu as u32,
        max_spdm_msg_size,
    };
    let spdm_len = body.encoded_size();
    let resp = build_response(pal, io, version, &body)?;

    // SPDM: GET_CAPABILITIES + CAPABILITIES contribute to VCA.
    let head = pal.header_size();
    state.transcript.append_vca(pal, io, io.request()).await?;
    state
        .transcript
        .append_vca(pal, io, &resp[head..head + spdm_len])
        .await?;

    state.phase = Phase::AfterCapabilities;
    Ok(resp)
}

/// Validates the `CapabilitiesBody` fields used by the responder.
///
/// # Parameters
///
/// * `body` — Decoded V1.2+ request body.
///
/// # Returns
///
/// `(peer_data_transfer_size, peer_max_spdm_msg_size)` extracted from
/// `body` after all range / CHUNK consistency checks pass.
///
/// # Errors
///
/// * [`SPDM_INVALID_REQUEST`] — `ct_exponent` exceeds the protocol maximum,
///   transfer sizes are invalid, or the Supported Algorithms request is made
///   without requester CHUNK support.
fn validate_capabilities_body(body: &CapabilitiesBody) -> SpdmResult<(u32, u32)> {
    if body.ct_exponent > CapabilitiesBody::MAX_CT_EXPONENT {
        return Err(SPDM_INVALID_REQUEST);
    }

    let flags = body.flags;
    // A requester can only request the Supported Algorithms block when it
    // supports chunking. This responder does not currently include the
    // optional block, so Param1 remains zero in the response even when this
    // valid request bit is set.
    if body.param1 & 0x01 != 0 && !flags.contains(CapFlags::CHUNK) {
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

const RESPONDER_CAP_FLAGS_V12_MASK: u32 = (1 << 22) - 1;
const RESPONDER_CAP_FLAGS_V13_MASK: u32 = (1 << 30) - 1;
const RESPONDER_CAP_FLAGS_V14_MASK: u32 = u32::MAX;

fn responder_cap_mask(version: SpdmVersion) -> u32 {
    match version {
        SpdmVersion::V10 | SpdmVersion::V11 | SpdmVersion::V12 => RESPONDER_CAP_FLAGS_V12_MASK,
        SpdmVersion::V13 => RESPONDER_CAP_FLAGS_V13_MASK,
        SpdmVersion::V14 => RESPONDER_CAP_FLAGS_V14_MASK,
    }
}

/// Validates a V1.0/1.1 `CapabilitiesBodyV11` (DSP0274 1.1.1 §10.3).
///
/// The V1.1 body has no `DataTransferSize`/`MaxSPDMmsgSize`, so only the
/// reserved fields and `CTExponent` are range-checked. `Param1`/`Param2` are
/// Reserved in V1.1 (the V1.3 "Supported Algorithms request" bit does not
/// exist here), so they must be zero.
fn validate_capabilities_body_v11(body: &CapabilitiesBodyV11) -> SpdmResult<()> {
    if body.param1 != 0 || body.param2 != 0 || body.reserved != 0 || body.reserved2 != [0; 2] {
        return Err(SPDM_INVALID_REQUEST);
    }
    if body.ct_exponent > CapabilitiesBody::MAX_CT_EXPONENT {
        return Err(SPDM_INVALID_REQUEST);
    }
    Ok(())
}

/// Picks the requested SPDM version without mutating connection state.
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
