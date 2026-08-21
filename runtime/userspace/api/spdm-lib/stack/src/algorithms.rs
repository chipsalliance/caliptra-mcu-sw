// Licensed under the Apache-2.0 license

//! `NEGOTIATE_ALGORITHMS` → `ALGORITHMS` handler.
//!
//! The responder picks **at most one** algorithm per family. The
//! selection rule is "intersect local-supported with peer-offered";
//! since our local profile only sets one bit per family, the
//! intersection is either that bit or `EMPTY` (= unsupported).
//!
//! The wire body decomposes into:
//!
//! ```text
//!   [ fixed prefix | ext-asym entries | ext-hash entries | AlgStruct[] ]
//!   SIZE bytes   ext_asym_count*4  ext_hash_count*4  num_alg_struct * SIZE
//! ```
//!
//! Extended (vendor-defined) asym/hash entries are present in the
//! wire format but unused by this responder; we validate their
//! length contribution and skip them. The `AlgStruct` array is
//! walked once, with monotonically-increasing `alg_type` and the
//! per-family bitmaps captured into `peer_dhe` / `peer_aead` /
//! `peer_key_schedule`. Anything else (e.g. `ReqBaseAsymAlg`) is
//! accepted but ignored.

use caliptra_mcu_spdm_codec::{
    alg_type, AeadAlgos, AlgStructEntry, AlgorithmsRsp, CapFlags, DheAlgos, KeyScheduleAlgos,
    NegotiateAlgorithmsReqBodyFixed, OtherParamSupport, ResponseBody, SpdmMsgHdrPdu, SpdmVersion,
};
use caliptra_mcu_spdm_traits::{PalBytes, SpdmPal, SpdmPalAlloc, SpdmPalIo, SpdmPalIoTransport};
use zerocopy::FromBytes;

use crate::build::build_response;
use crate::error::{SpdmResult, SPDM_INVALID_REQUEST, SPDM_UNEXPECTED_REQUEST};
use crate::stack::{ConnectionState, Phase};

/// Peer-advertised algorithm bitmaps, one per family the responder
/// actually consumes.
struct PeerAlgs {
    dhe: DheAlgos,
    aead: AeadAlgos,
    key_schedule: KeyScheduleAlgos,
}

/// Handles a `NEGOTIATE_ALGORITHMS` request.
///
/// # Parameters
///
/// * `state` — Mutable connection state. Read for local-policy bits
///   and current negotiated version; on success, `phase` advances to
///   [`Phase::AfterAlgorithms`].
/// * `pal` — Borrowed PAL used to allocate the response buffer.
/// * `io` — The I/O handle for the current request.
///
/// # Returns
///
/// * `Ok(PalBytes)` — Fully-encoded `ALGORITHMS` response containing
///   the responder's selections (single-bit per family or `EMPTY` if
///   no overlap with the peer).
///
/// # Errors
///
/// * [`SPDM_UNEXPECTED_REQUEST`] — connection is not in
///   [`Phase::AfterCapabilities`].
/// * [`SPDM_INVALID_REQUEST`] — header undecodable or body violates
///   the corresponding table (see [`locate_alg_structs`] / [`parse_peer_algs`]
///   for the exact rules).
pub(crate) async fn handle_negotiate_algorithms<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
) -> SpdmResult<PalBytes<'a, Pal>> {
    if state.phase != Phase::AfterCapabilities {
        return Err(SPDM_UNEXPECTED_REQUEST);
    }

    let req = io.request();
    let (hdr, body) = SpdmMsgHdrPdu::ref_from_prefix(req).map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != state.version.to_u8() {
        return Err(crate::error::SPDM_VERSION_MISMATCH);
    }
    let fixed = NegotiateAlgorithmsReqBodyFixed::ref_from_bytes(
        body.get(..NegotiateAlgorithmsReqBodyFixed::SIZE)
            .ok_or(SPDM_INVALID_REQUEST)?,
    )
    .map_err(|_| SPDM_INVALID_REQUEST)?;

    let alg_structs = locate_alg_structs(fixed, body)?;
    let peer = parse_peer_algs(alg_structs)?;
    let rsp_body = build_response_body(state, fixed, &peer, pal.secure_message_supported());
    let spdm_len = rsp_body.encoded_size();
    state.other_param_sel = rsp_body.other_param_support;
    state.negotiated_base_asym_sel = rsp_body.base_asym_sel;
    state.negotiated_base_hash_sel = rsp_body.base_hash_sel;
    state.negotiated_pqc_asym_sel = rsp_body.pqc_asym_sel;

    let resp = build_response(pal, io, state.version, &rsp_body)?;

    // SPDM: NEGOTIATE_ALGORITHMS + ALGORITHMS contribute to VCA.
    let head = pal.header_size();
    state.transcript.append_vca(pal, io, io.request()).await?;
    state
        .transcript
        .append_vca(pal, io, &resp[head..head + spdm_len])
        .await?;

    state.phase = Phase::AfterAlgorithms;
    Ok(resp)
}

/// Validates the fixed-prefix length fields and returns the
/// `AlgStruct[]` slice within `body`.
///
/// # Parameters
///
/// * `fixed` — Already-decoded fixed prefix; reserved fields and
///   `length` are validated here.
/// * `body` — The full request body (everything after the SPDM
///   common header).
///
/// # Returns
///
/// A slice covering exactly `num_alg_struct * AlgStructEntry::SIZE`
/// bytes inside `body`.
///
/// # Errors
///
/// * [`SPDM_INVALID_REQUEST`] — any reserved field is non-zero,
///   `length` exceeds the V1.3 maximum, the extended-asym /
///   extended-hash entries overflow the body, or the trailing
///   `AlgStruct[]` does not consume the remaining bytes exactly.
fn locate_alg_structs<'a>(
    fixed: &NegotiateAlgorithmsReqBodyFixed,
    body: &'a [u8],
) -> SpdmResult<&'a [u8]> {
    if fixed.param2 != 0 || fixed.reserved1 != [0; 8] || fixed.reserved2 != 0 {
        return Err(SPDM_INVALID_REQUEST);
    }

    // `length` is the full request size including the 2-byte SPDM
    // common header — `body` starts after it.
    let total = fixed.length.get();
    if total > NegotiateAlgorithmsReqBodyFixed::MAX_REQUEST_LENGTH {
        return Err(SPDM_INVALID_REQUEST);
    }
    let body_len = total
        .checked_sub(SpdmMsgHdrPdu::SIZE as u16)
        .ok_or(SPDM_INVALID_REQUEST)? as usize;
    if body_len < NegotiateAlgorithmsReqBodyFixed::SIZE || body_len > body.len() {
        return Err(SPDM_INVALID_REQUEST);
    }

    // We don't support extended (vendor) algorithms but must skip
    // over any the requester sent.
    let ext_bytes = (fixed.ext_asym_count as usize + fixed.ext_hash_count as usize) * 4;
    let after_ext = NegotiateAlgorithmsReqBodyFixed::SIZE
        .checked_add(ext_bytes)
        .ok_or(SPDM_INVALID_REQUEST)?;

    let alg_bytes = fixed.num_alg_struct as usize * AlgStructEntry::SIZE;
    if after_ext.checked_add(alg_bytes) != Some(body_len) {
        return Err(SPDM_INVALID_REQUEST);
    }
    Ok(&body[after_ext..after_ext + alg_bytes])
}

/// Walks a validated `AlgStruct[]` slice and returns the peer's
/// per-family bitmaps.
///
/// # Parameters
///
/// * `slice` — Byte slice whose length is an exact multiple of
///   [`AlgStructEntry::SIZE`] (typically produced by
///   [`locate_alg_structs`]).
///
/// # Returns
///
/// A [`PeerAlgs`] with `dhe` / `aead` / `key_schedule` populated for
/// every family the peer advertised. Families the responder doesn't
/// consume (e.g. `ReqBaseAsymAlg`) are accepted but discarded.
///
/// # Errors
///
/// * [`SPDM_INVALID_REQUEST`] — any entry fails the per-entry
///   rules: `alg_type` must monotonically increase across the array,
///   `FixedAlgCount` must equal 2, `ExtAlgCount` must be 0, and
///   `AlgSupported` must be non-zero.
fn parse_peer_algs(slice: &[u8]) -> SpdmResult<PeerAlgs> {
    let mut peer = PeerAlgs {
        dhe: DheAlgos::EMPTY,
        aead: AeadAlgos::EMPTY,
        key_schedule: KeyScheduleAlgos::EMPTY,
    };
    let mut prev_alg_type: u8 = 0;

    for (i, chunk) in slice.chunks_exact(AlgStructEntry::SIZE).enumerate() {
        let entry = AlgStructEntry::ref_from_bytes(chunk).map_err(|_| SPDM_INVALID_REQUEST)?;

        if i > 0 && entry.alg_type <= prev_alg_type {
            return Err(SPDM_INVALID_REQUEST);
        }
        prev_alg_type = entry.alg_type;

        let fixed_count = entry.alg_count_etc >> 4;
        let ext_count = entry.alg_count_etc & 0x0F;
        let bits = entry.alg_supported.get();
        if fixed_count != 2 || ext_count != 0 || bits == 0 {
            return Err(SPDM_INVALID_REQUEST);
        }

        match entry.alg_type {
            alg_type::DHE => peer.dhe = DheAlgos::from_bits(bits),
            alg_type::AEAD => peer.aead = AeadAlgos::from_bits(bits),
            alg_type::KEY_SCHEDULE => peer.key_schedule = KeyScheduleAlgos::from_bits(bits),
            // Other types (e.g. ReqBaseAsymAlg = 0x04) are accepted
            // but unused by this responder.
            _ => {}
        }
    }
    Ok(peer)
}

/// Builds the `ALGORITHMS` response body by intersecting the
/// responder's local policy with the peer-offered bitmaps.
///
/// Because local profiles set at most one bit per family, every
/// `state.X & peer.X` is either the responder's single bit or
/// `EMPTY` (= no agreement).
///
/// # Parameters
///
/// * `state` — Connection state holding the responder's fixed policy.
/// * `fixed` — Decoded fixed prefix of the request (provides
///   per-family bitmaps for `MeasurementSpec`, `OtherParamSupport`,
///   `BaseAsymAlgo`, `BaseHashAlgo`).
/// * `peer` — Peer-offered DHE / AEAD / KeySchedule bitmaps from the
///   `AlgStruct[]` tail.
///
/// # Returns
///
/// An [`AlgorithmsRsp`] ready to hand to [`build_response`]. Families
/// with no overlap are omitted from `alg_structs` (encoded as `None`).
fn build_response_body<S, L>(
    state: &ConnectionState<S, L>,
    fixed: &NegotiateAlgorithmsReqBodyFixed,
    peer: &PeerAlgs,
    secure_message_supported: bool,
) -> AlgorithmsRsp {
    let mut other_param_support = state.other_param_support & fixed.other_param_support;
    let (dhe, aead, key_schedule) = if secure_message_supported {
        (
            state.dhe & peer.dhe,
            state.aead & peer.aead,
            state.key_schedule & peer.key_schedule,
        )
    } else {
        (DheAlgos::EMPTY, AeadAlgos::EMPTY, KeyScheduleAlgos::EMPTY)
    };
    if state.version < SpdmVersion::V13
        || !multi_key_cap_allows_connection(state.advertised_cap_flags, state.peer_cap_flags)
    {
        other_param_support = OtherParamSupport::from_bits(
            other_param_support.into_bits() & !OtherParamSupport::MULTI_KEY_CONN.into_bits(),
        );
    }

    AlgorithmsRsp {
        measurement_spec_sel: state.measurement_spec & fixed.measurement_spec,
        other_param_support,
        // MeasurementHashAlgo has no peer bitmap to intersect — the
        // requester relies on the responder's choice.
        meas_hash_algo: state.meas_hash_algo,
        base_asym_sel: state.base_asym_sel & fixed.base_asym_algo,
        base_hash_sel: state.base_hash_sel & fixed.base_hash_algo,
        pqc_asym_sel: state.pqc_asym_sel & fixed.pqc_asym_algo,
        alg_structs: [
            (!dhe.is_empty()).then(|| AlgStructEntry::dhe(dhe)),
            (!aead.is_empty()).then(|| AlgStructEntry::aead(aead)),
            (!key_schedule.is_empty()).then(|| AlgStructEntry::key_schedule(key_schedule)),
            None,
        ],
    }
}

fn multi_key_cap_allows_connection(local: CapFlags, peer: CapFlags) -> bool {
    matches!(local.multi_key_field(), 0b01 | 0b10) && matches!(peer.multi_key_field(), 0b01 | 0b10)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::stack::ConnectionState;
    use caliptra_mcu_spdm_codec::{
        alg_type, AlgorithmsRspBodyFixed, AsymAlgos, HashAlgos, MeasHashAlgos, MeasSpec,
        PqcAsymAlgos, ReqRespCode,
    };
    use caliptra_mcu_spdm_traits::SpdmPalHash;
    use futures::executor::block_on;
    use std::vec;
    use std::vec::Vec;
    use zerocopy::{little_endian::U16, FromBytes, IntoBytes};

    use crate::measurements::support;
    use support::{test_digest, TestHashState, TestIo, TestPal};

    fn negotiate_request(base_asym_algo: AsymAlgos, include_req_base_asym: bool) -> Vec<u8> {
        let mut alg_structs = vec![
            AlgStructEntry::dhe(DheAlgos::SECP_384_R1),
            AlgStructEntry::aead(AeadAlgos::AES_256_GCM),
        ];
        if include_req_base_asym {
            alg_structs.push(AlgStructEntry {
                alg_type: alg_type::REQ_BASE_ASYM,
                alg_count_etc: AlgStructEntry::FIXED_ALG_COUNT_ETC,
                alg_supported: U16::new(AsymAlgos::ECDSA_ECC_NIST_P384.into_bits() as u16),
            });
        }
        alg_structs.push(AlgStructEntry::key_schedule(KeyScheduleAlgos::SPDM));

        let total_len = SpdmMsgHdrPdu::SIZE
            + NegotiateAlgorithmsReqBodyFixed::SIZE
            + alg_structs.len() * AlgStructEntry::SIZE;
        let fixed = NegotiateAlgorithmsReqBodyFixed {
            num_alg_struct: alg_structs.len() as u8,
            param2: 0,
            length: U16::new(total_len as u16),
            measurement_spec: MeasSpec::DMTF,
            other_param_support: OtherParamSupport::OPAQUE_DATA_FMT1,
            base_asym_algo,
            base_hash_algo: HashAlgos::SHA_384,
            pqc_asym_algo: PqcAsymAlgos::MLDSA_87,
            reserved1: [0; 8],
            ext_asym_count: 0,
            ext_hash_count: 0,
            reserved2: 0,
            mel_spec_or_reserved: 0,
        };

        let mut request = Vec::with_capacity(total_len);
        request.extend_from_slice(
            SpdmMsgHdrPdu::new(SpdmVersion::V12, ReqRespCode::NEGOTIATE_ALGORITHMS).as_bytes(),
        );
        request.extend_from_slice(fixed.as_bytes());
        for entry in &alg_structs {
            request.extend_from_slice(entry.as_bytes());
        }
        assert_eq!(request.len(), total_len);
        request
    }

    fn run_negotiate(request: Vec<u8>) -> (ConnectionState<TestHashState, Vec<u8>>, Vec<u8>) {
        let pal = TestPal::default();
        let mut state = ConnectionState {
            phase: Phase::AfterCapabilities,
            ..ConnectionState::default()
        };
        let io = TestIo::message(request);
        let response = block_on(handle_negotiate_algorithms(&mut state, &pal, &io)).unwrap();
        (state, response[..].to_vec())
    }

    fn assert_algorithms_response(
        response: &[u8],
        expected_base_asym: AsymAlgos,
        expected_entries: &[AlgStructEntry],
    ) {
        let expected_len = SpdmMsgHdrPdu::SIZE
            + AlgorithmsRspBodyFixed::SIZE
            + expected_entries.len() * AlgStructEntry::SIZE;
        assert_eq!(response.len(), expected_len);

        let (header, body) = SpdmMsgHdrPdu::ref_from_prefix(response).unwrap();
        assert_eq!(header.version, SpdmVersion::V12.to_u8());
        assert_eq!(header.code, ReqRespCode::ALGORITHMS);
        let fixed = AlgorithmsRspBodyFixed::ref_from_bytes(
            body.get(..AlgorithmsRspBodyFixed::SIZE).unwrap(),
        )
        .unwrap();
        assert_eq!(fixed.num_alg_struct as usize, expected_entries.len());
        assert_eq!(fixed.length.get() as usize, response.len());
        assert_eq!(
            fixed.measurement_spec_sel.into_bits(),
            MeasSpec::DMTF.into_bits()
        );
        assert_eq!(
            fixed.other_param_support.into_bits(),
            OtherParamSupport::OPAQUE_DATA_FMT1.into_bits()
        );
        assert_eq!(
            fixed.meas_hash_algo.into_bits(),
            MeasHashAlgos::SHA_384.into_bits()
        );
        assert_eq!(
            fixed.base_asym_sel.into_bits(),
            expected_base_asym.into_bits()
        );
        assert_eq!(
            fixed.base_hash_sel.into_bits(),
            HashAlgos::SHA_384.into_bits()
        );
        assert_eq!(fixed.reserved3, [0; 8]);
        assert_eq!(fixed.ext_asym_sel_count, 0);
        assert_eq!(fixed.ext_hash_sel_count, 0);
        assert_eq!(fixed.reserved4, [0; 2]);

        let mut expected_struct_bytes = Vec::new();
        for entry in expected_entries {
            expected_struct_bytes.extend_from_slice(entry.as_bytes());
        }
        assert_eq!(
            body.get(AlgorithmsRspBodyFixed::SIZE..).unwrap(),
            expected_struct_bytes.as_slice()
        );
    }

    fn assert_response_was_appended_to_vca(
        state: &mut ConnectionState<TestHashState, Vec<u8>>,
        response: &[u8],
    ) {
        let pal = TestPal::default();
        let io = TestIo::message(Vec::new());
        let mut digest = [0; support::SHA384_DIGEST_SIZE];
        block_on(pal.hash_finish(&io, state.transcript.vca.as_mut().unwrap(), &mut digest))
            .unwrap();
        assert_eq!(digest, test_digest(response));
    }

    #[test]
    fn algorithms_omits_peer_only_req_base_asym_structure_from_response_and_vca() {
        let request = negotiate_request(AsymAlgos::ECDSA_ECC_NIST_P384, true);
        let (mut state, response) = run_negotiate(request);
        let expected_entries = [
            AlgStructEntry::dhe(DheAlgos::SECP_384_R1),
            AlgStructEntry::aead(AeadAlgos::AES_256_GCM),
            AlgStructEntry::key_schedule(KeyScheduleAlgos::SPDM),
        ];

        assert_algorithms_response(&response, AsymAlgos::ECDSA_ECC_NIST_P384, &expected_entries);
        assert_eq!(
            state.negotiated_base_asym_sel.into_bits(),
            AsymAlgos::ECDSA_ECC_NIST_P384.into_bits()
        );
        assert_eq!(state.phase, Phase::AfterAlgorithms);
        assert_response_was_appended_to_vca(&mut state, &response);
    }

    #[test]
    fn algorithms_keeps_zero_base_asym_selection_and_advances_state_without_common_algorithm() {
        let request = negotiate_request(AsymAlgos::EMPTY, false);
        let (mut state, response) = run_negotiate(request);
        let expected_entries = [
            AlgStructEntry::dhe(DheAlgos::SECP_384_R1),
            AlgStructEntry::aead(AeadAlgos::AES_256_GCM),
            AlgStructEntry::key_schedule(KeyScheduleAlgos::SPDM),
        ];

        assert_algorithms_response(&response, AsymAlgos::EMPTY, &expected_entries);
        assert_eq!(
            state.negotiated_base_asym_sel.into_bits(),
            AsymAlgos::EMPTY.into_bits()
        );
        assert_eq!(state.phase, Phase::AfterAlgorithms);
        assert_response_was_appended_to_vca(&mut state, &response);
    }
}
