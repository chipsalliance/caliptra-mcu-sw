// Licensed under the Apache-2.0 license

extern crate std;

use super::*;
use caliptra_mcu_spdm_codec::{AsymAlgos, HashAlgos, MeasSpec, ReqRespCode};
use futures::executor::block_on;
use std::vec::Vec;
use zerocopy::IntoBytes;

#[path = "support.rs"]
mod support;
use support::*;

/// `MULTI_KEY_CAP` field lives in CAPABILITIES flags bits 27:26, so a
/// field value of `01b` is `1 << 26`. `10b` already has a named
/// constant (`CapFlags::MULTI_KEY_CONN_RSP`); `01b` and the reserved
/// `11b` do not.
const MULTI_KEY_CAP_ONLY: u32 = 1 << 26;
const MULTI_KEY_CAP_RESERVED: u32 = 3 << 26;

/// `OtherParamSupport::MULTI_KEY_CONN` as a raw bit, for the
/// `from_bits` round-trips below.
const MULTI_KEY_CONN_BIT: u8 = 1 << 4;

fn state_at_capabilities(version: SpdmVersion) -> ConnectionState<TestHashState, Vec<u8>> {
    let mut state = negotiated_state(version);
    state.phase = Phase::AfterCapabilities;
    // `MULTI_KEY_CONN` is only in the responder's local OtherParamSupport
    // policy when the `set-certificate` feature is on, and the response
    // bit is the intersection of local policy with the request. Offer it
    // unconditionally here so these tests exercise the Table 32 rules
    // rather than the feature gate.
    state.other_param_support =
        OtherParamSupport::from_bits(state.other_param_support.into_bits() | MULTI_KEY_CONN_BIT);
    state
}

/// Overrides the responder's advertised `MULTI_KEY_CAP` field, leaving
/// every other capability bit as the Caliptra profile set it.
fn with_multi_key_cap(
    mut state: ConnectionState<TestHashState, Vec<u8>>,
    field: u32,
) -> ConnectionState<TestHashState, Vec<u8>> {
    let cleared = state.advertised_cap_flags.into_bits() & !MULTI_KEY_CAP_RESERVED;
    state.advertised_cap_flags = CapFlags::from_bits(cleared | field);
    state
}

/// Builds a minimal NEGOTIATE_ALGORITHMS request: 2-byte SPDM header
/// plus the 30-byte fixed body, no extended entries and no AlgStructs.
fn negotiate_algorithms_io(version: SpdmVersion, other_params: OtherParamSupport) -> TestIo {
    let total = (SpdmMsgHdrPdu::SIZE + NegotiateAlgorithmsReqBodyFixed::SIZE) as u16;
    let mut req = Vec::new();
    req.push(version.to_u8());
    req.push(ReqRespCode::NEGOTIATE_ALGORITHMS.0);

    let body = NegotiateAlgorithmsReqBodyFixed {
        num_alg_struct: 0,
        param2: 0,
        length: total.into(),
        measurement_spec: MeasSpec::DMTF,
        other_param_support: other_params,
        base_asym_algo: AsymAlgos::ECDSA_ECC_NIST_P384,
        base_hash_algo: HashAlgos::SHA_384,
        pqc_asym_algo: PqcAsymAlgos::EMPTY,
        reserved1: [0; 8],
        ext_asym_count: 0,
        ext_hash_count: 0,
        reserved2: 0,
        mel_spec_or_reserved: 0,
    };
    req.extend_from_slice(body.as_bytes());
    assert_eq!(req.len(), total as usize);

    TestIo::message(req)
}

/// Extracts the ALGORITHMS response's OtherParamSupport byte. Response
/// layout: transport header, then SPDM header (2) + Param1/Param2 (2) +
/// Length (2) + MeasurementSpecificationSel (1) + OtherParamsSupport.
fn response_other_params(pal: &TestPal, rsp: &[u8]) -> u8 {
    let body = &rsp[pal.header_size()..];
    assert_eq!(body[1], ReqRespCode::ALGORITHMS.0);
    body[7]
}

/// MULTI_KEY_CAP = 00b and the Requester sets ResponderMultiKeyConn.
/// DSP0274 1.3.0 Table 32 marks this invalid, so it must not be answered with a
/// successful ALGORITHMS.
#[test]
fn test_negotiate_algorithms_v13_rejects_multi_key_conn_when_cap_not_supported() {
    let pal = TestPal::default();
    let mut state = with_multi_key_cap(state_at_capabilities(SpdmVersion::V13), 0);
    let io = negotiate_algorithms_io(SpdmVersion::V13, OtherParamSupport::MULTI_KEY_CONN);

    let err = block_on(handle_negotiate_algorithms(&mut state, &pal, &io)).unwrap_err();

    assert_eq!(err, SPDM_INVALID_REQUEST);
    // The request was refused, so the connection must not advance.
    assert_eq!(state.phase, Phase::AfterCapabilities);
}

/// The mirror-image invalid row: MULTI_KEY_CAP = 01b means multi-key
/// only, so a cleared ResponderMultiKeyConn contradicts it.
#[test]
fn test_negotiate_algorithms_v13_rejects_cleared_multi_key_conn_when_cap_only() {
    let pal = TestPal::default();
    let mut state = with_multi_key_cap(state_at_capabilities(SpdmVersion::V13), MULTI_KEY_CAP_ONLY);
    let io = negotiate_algorithms_io(SpdmVersion::V13, OtherParamSupport::EMPTY);

    let err = block_on(handle_negotiate_algorithms(&mut state, &pal, &io)).unwrap_err();

    assert_eq!(err, SPDM_INVALID_REQUEST);
    assert_eq!(state.phase, Phase::AfterCapabilities);
}

/// MULTI_KEY_CAP = 01b with the bit set is the valid half of that row.
#[test]
fn test_negotiate_algorithms_v13_accepts_multi_key_conn_when_cap_only() {
    let pal = TestPal::default();
    let mut state = with_multi_key_cap(state_at_capabilities(SpdmVersion::V13), MULTI_KEY_CAP_ONLY);
    state.peer_cap_flags = CapFlags::MULTI_KEY_CONN_RSP;
    let io = negotiate_algorithms_io(SpdmVersion::V13, OtherParamSupport::MULTI_KEY_CONN);

    let rsp = block_on(handle_negotiate_algorithms(&mut state, &pal, &io)).unwrap();

    assert_eq!(state.phase, Phase::AfterAlgorithms);
    assert_ne!(
        response_other_params(&pal, &rsp) & OtherParamSupport::MULTI_KEY_CONN.into_bits(),
        0
    );
}

/// MULTI_KEY_CAP = 00b with the bit clear is legal and negotiates the
/// connection as single-key.
#[test]
fn test_negotiate_algorithms_v13_accepts_cleared_multi_key_conn_when_cap_not_supported() {
    let pal = TestPal::default();
    let mut state = with_multi_key_cap(state_at_capabilities(SpdmVersion::V13), 0);
    let io = negotiate_algorithms_io(SpdmVersion::V13, OtherParamSupport::EMPTY);

    let rsp = block_on(handle_negotiate_algorithms(&mut state, &pal, &io)).unwrap();

    assert_eq!(state.phase, Phase::AfterAlgorithms);
    assert_eq!(
        response_other_params(&pal, &rsp) & OtherParamSupport::MULTI_KEY_CONN.into_bits(),
        0
    );
}

/// MULTI_KEY_CAP = 10b leaves the choice to the Requester, so both
/// values of the bit are accepted.
#[test]
fn test_negotiate_algorithms_v13_multi_key_cap_negotiable_accepts_either_value() {
    for requested in [OtherParamSupport::EMPTY, OtherParamSupport::MULTI_KEY_CONN] {
        let pal = TestPal::default();
        let mut state = with_multi_key_cap(
            state_at_capabilities(SpdmVersion::V13),
            CapFlags::MULTI_KEY_CONN_RSP.into_bits(),
        );
        state.peer_cap_flags = CapFlags::MULTI_KEY_CONN_RSP;
        let io = negotiate_algorithms_io(SpdmVersion::V13, requested);

        let rsp = block_on(handle_negotiate_algorithms(&mut state, &pal, &io)).unwrap();

        assert_eq!(state.phase, Phase::AfterAlgorithms);
        assert_eq!(
            response_other_params(&pal, &rsp) & OtherParamSupport::MULTI_KEY_CONN.into_bits(),
            requested.into_bits(),
        );
    }
}

/// Pre-V1.3 the bit is reserved, not illegal: the responder keeps
/// masking it out of the response instead of failing the request.
#[test]
fn test_negotiate_algorithms_v12_masks_multi_key_conn_without_error() {
    let pal = TestPal::default();
    let mut state = state_at_capabilities(SpdmVersion::V12);
    let io = negotiate_algorithms_io(SpdmVersion::V12, OtherParamSupport::MULTI_KEY_CONN);

    let rsp = block_on(handle_negotiate_algorithms(&mut state, &pal, &io)).unwrap();

    assert_eq!(state.phase, Phase::AfterAlgorithms);
    assert_eq!(
        response_other_params(&pal, &rsp) & OtherParamSupport::MULTI_KEY_CONN.into_bits(),
        0
    );
}

/// The reserved `11b` MULTI_KEY_CAP encoding is refused outright.
#[test]
fn test_negotiate_algorithms_v13_rejects_reserved_multi_key_cap() {
    let pal = TestPal::default();
    let mut state = with_multi_key_cap(
        state_at_capabilities(SpdmVersion::V13),
        MULTI_KEY_CAP_RESERVED,
    );
    let io = negotiate_algorithms_io(SpdmVersion::V13, OtherParamSupport::MULTI_KEY_CONN);

    let err = block_on(handle_negotiate_algorithms(&mut state, &pal, &io)).unwrap_err();

    assert_eq!(err, SPDM_INVALID_REQUEST);
}
