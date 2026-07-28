// Licensed under the Apache-2.0 license

//! `GET_CAPABILITIES` → `CAPABILITIES` handler.
//!
//! On a successful exchange this handler:
//!
//! 1. Verifies the connection is in [`Phase::AfterVersion`].
//! 2. Negotiates the SPDM version using the requester's
//!    common-header `version` byte (must be one of
//!    [`SUPPORTED_VERSIONS`](crate::version::SUPPORTED_VERSIONS)).
//! 3. Validates the V1.2+ `CapabilitiesBody`, version-specific capability
//!    masks, extended flags, and capability dependencies.
//! 4. Stashes the peer's advertised `DataTransferSize`,
//!    `MaxSPDMmsgSize`, and capability flags into [`ConnectionState`].
//! 5. Builds the `CAPABILITIES` response from the responder's fixed
//!    local policy, then transitions to [`Phase::AfterCapabilities`].

use caliptra_mcu_spdm_codec::{
    CapFlags, CapabilitiesBody, CapabilitiesRsp, ExtCapFlags, ResponseBody, SpdmMsgHdrPdu,
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
///   `DataTransferSize` / `MaxSPDMmsgSize` violate the corresponding table.
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

    let body = CapabilitiesBody::ref_from_bytes(
        rest.get(..CapabilitiesBody::SIZE)
            .ok_or(SPDM_INVALID_REQUEST)?,
    )
    .map_err(|_| SPDM_INVALID_REQUEST)?;

    let (peer_dts, peer_max) = validate_capabilities_body(version, state.cap_flags, body)?;
    state.version = version;
    state.peer_data_transfer_size = peer_dts;
    state.peer_max_spdm_msg_size = peer_max;
    state.peer_cap_flags = body.flags;

    let mtu = pal.mtu();
    let mut flags = CapFlags::from_bits(state.cap_flags.into_bits() & responder_cap_mask(version));
    if !pal.secure_message_supported() {
        let secure_session_caps = CapFlags::KEY_EX | CapFlags::ENCRYPT | CapFlags::MAC;
        flags = CapFlags::from_bits(flags.into_bits() & !secure_session_caps.into_bits());
    }
    state.advertised_cap_flags = flags;
    let max_spdm_msg_size = if flags.contains(CapFlags::CHUNK) {
        pal.large_capacity().max(mtu)
    } else {
        mtu
    } as u32;
    let body = CapabilitiesRsp {
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

/// Validates a `CapabilitiesBody` against the negotiated SPDM version.
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
/// * [`SPDM_INVALID_REQUEST`] — a reserved/version-inapplicable field or flag
///   is non-zero, capability dependencies are invalid, `ct_exponent` exceeds
///   the protocol maximum, transfer sizes are invalid, or the Supported
///   Algorithms request is made without CHUNK support at both endpoints.
fn validate_capabilities_body(
    version: SpdmVersion,
    local_flags: CapFlags,
    body: &CapabilitiesBody,
) -> SpdmResult<(u32, u32)> {
    let param1_mask = if version >= SpdmVersion::V13 { 0x01 } else { 0 };
    if body.param1 & !param1_mask != 0 || body.param2 != 0 || body.reserved != 0 {
        return Err(SPDM_INVALID_REQUEST);
    }
    // Requester ExtFlags are reserved in SPDM V1.4 and the same bytes
    // are reserved in all earlier versions.
    if !body.ext_flags.is_empty() {
        return Err(SPDM_INVALID_REQUEST);
    }
    if body.ct_exponent > CapabilitiesBody::MAX_CT_EXPONENT {
        return Err(SPDM_INVALID_REQUEST);
    }

    let flags = body.flags;
    if flags.into_bits() & !requester_cap_mask(version) != 0 {
        return Err(SPDM_INVALID_REQUEST);
    }
    validate_request_flag_compatibility(version, flags)?;

    // Supported Algorithms can only be requested when both endpoints
    // support the large-message transfer mechanism. This responder does
    // not currently include the optional block, so Param1 remains zero in
    // the response even when this valid request bit is set.
    if body.param1 & 0x01 != 0
        && (!flags.contains(CapFlags::CHUNK) || !local_flags.contains(CapFlags::CHUNK))
    {
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

fn validate_request_flag_compatibility(version: SpdmVersion, flags: CapFlags) -> SpdmResult<()> {
    let cert = flags.contains(CapFlags::CERT);
    let chal = flags.contains(CapFlags::CHAL);
    let encrypt = flags.contains(CapFlags::ENCRYPT);
    let mac = flags.contains(CapFlags::MAC);
    let mut_auth = flags.contains(CapFlags::MUT_AUTH);
    let key_ex = flags.contains(CapFlags::KEY_EX);
    let psk = flags.psk_field();
    let pub_key_id = flags.contains(CapFlags::PUB_KEY_ID);
    let ep_info = flags.ep_info_field();
    let multi_key = flags.multi_key_field();

    // Requesters may advertise PSK_CAP=00b or 01b. The 10b value is
    // responder-only and 11b is reserved.
    if psk > 1 || ep_info == 3 || multi_key == 3 {
        return Err(SPDM_INVALID_REQUEST);
    }

    let has_session_exchange = key_ex || psk != 0;
    if has_session_exchange {
        if !encrypt && !mac {
            return Err(SPDM_INVALID_REQUEST);
        }
    } else if encrypt
        || mac
        || flags.contains(CapFlags::HANDSHAKE_IN_THE_CLEAR)
        || flags.contains(CapFlags::HBEAT)
        || flags.contains(CapFlags::KEY_UPD)
        || (version >= SpdmVersion::V13 && flags.contains(CapFlags::EVENT))
    {
        return Err(SPDM_INVALID_REQUEST);
    }
    if !key_ex && psk == 1 && flags.contains(CapFlags::HANDSHAKE_IN_THE_CLEAR) {
        return Err(SPDM_INVALID_REQUEST);
    }

    if cert || pub_key_id {
        if cert && pub_key_id {
            return Err(SPDM_INVALID_REQUEST);
        }
        if !(chal || key_ex || (version >= SpdmVersion::V13 && ep_info == 2)) {
            return Err(SPDM_INVALID_REQUEST);
        }
    } else if chal || mut_auth || (version >= SpdmVersion::V13 && ep_info == 2) {
        return Err(SPDM_INVALID_REQUEST);
    }

    if mut_auth && !key_ex && !chal {
        return Err(SPDM_INVALID_REQUEST);
    }
    if version >= SpdmVersion::V13 && multi_key != 0 && (!cert || pub_key_id) {
        return Err(SPDM_INVALID_REQUEST);
    }
    Ok(())
}

const REQUESTER_CAP_FLAGS_V12_MASK: u32 = (1 << 1)
    | (1 << 2)
    | (1 << 6)
    | (1 << 7)
    | (1 << 8)
    | (1 << 9)
    | (0b11 << 10)
    | (1 << 12)
    | (1 << 13)
    | (1 << 14)
    | (1 << 15)
    | (1 << 16)
    | (1 << 17);
const REQUESTER_CAP_FLAGS_V13_MASK: u32 =
    REQUESTER_CAP_FLAGS_V12_MASK | (0b11 << 22) | (1 << 25) | (0b11 << 26);
const REQUESTER_CAP_FLAGS_V14_MASK: u32 = REQUESTER_CAP_FLAGS_V13_MASK | (1 << 31);

const RESPONDER_CAP_FLAGS_V12_MASK: u32 = (1 << 22) - 1;
const RESPONDER_CAP_FLAGS_V13_MASK: u32 = (1 << 30) - 1;
const RESPONDER_CAP_FLAGS_V14_MASK: u32 = u32::MAX;

fn requester_cap_mask(version: SpdmVersion) -> u32 {
    match version {
        SpdmVersion::V10 | SpdmVersion::V11 | SpdmVersion::V12 => REQUESTER_CAP_FLAGS_V12_MASK,
        SpdmVersion::V13 => REQUESTER_CAP_FLAGS_V13_MASK,
        SpdmVersion::V14 => REQUESTER_CAP_FLAGS_V14_MASK,
    }
}

fn responder_cap_mask(version: SpdmVersion) -> u32 {
    match version {
        SpdmVersion::V10 | SpdmVersion::V11 | SpdmVersion::V12 => RESPONDER_CAP_FLAGS_V12_MASK,
        SpdmVersion::V13 => RESPONDER_CAP_FLAGS_V13_MASK,
        SpdmVersion::V14 => RESPONDER_CAP_FLAGS_V14_MASK,
    }
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
