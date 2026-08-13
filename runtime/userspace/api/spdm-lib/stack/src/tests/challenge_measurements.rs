// Licensed under the Apache-2.0 license

//! SPDM 1.4 CHALLENGE / GET_MEASUREMENTS dispatch tests.
//!
//! SPDM 1.4 keeps the 1.3 wire format for both commands, so these tests pin
//! the negotiated-1.4 behavior: the 8-byte requester context must be present
//! in requests and echoed in responses, and responses carry the negotiated
//! version byte.

#![allow(clippy::field_reassign_with_default)]

extern crate std;

use super::*;
use caliptra_mcu_spdm_codec::{
    ReqRespCode, SpdmVersion, ECC_P384_SIGNATURE_SIZE, REQUESTER_CONTEXT_LEN, SHA384_HASH_SIZE,
    SPDM_PREFIX_LEN, SPDM_SIGNING_CONTEXT_LEN,
};
use caliptra_mcu_spdm_traits::{MeasurementInfo, NoVdmBackend, SPDM_NONCE_LEN};
use futures::executor::block_on;
use std::vec;
use std::vec::Vec;

#[path = "support.rs"]
mod support;
use support::{test_digest, TestHashState, TestIo, TestPal};

const CONTEXT: [u8; REQUESTER_CONTEXT_LEN] = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];

fn v14_signing_context(operation: &[u8]) -> [u8; SPDM_SIGNING_CONTEXT_LEN] {
    let mut context = [0u8; SPDM_SIGNING_CONTEXT_LEN];
    let prefix = b"dmtf-spdm-v1.4.*";
    for chunk in context[..SPDM_PREFIX_LEN].chunks_exact_mut(prefix.len()) {
        chunk.copy_from_slice(prefix);
    }
    let operation_start = SPDM_SIGNING_CONTEXT_LEN - operation.len();
    context[operation_start..].copy_from_slice(operation);
    context
}

fn assert_v14_signature_inputs(
    pal: &TestPal,
    response: &[u8],
    signature_offset: usize,
    operation: &[u8],
) {
    let signed_hashes = pal.signed_hashes.borrow();
    assert_eq!(signed_hashes.len(), 1);
    let transcript_hash = test_digest(&response[..signature_offset]);
    assert_eq!(signed_hashes[0], test_digest(&transcript_hash));

    let expected_context = v14_signing_context(operation);
    assert!(pal
        .hash_seeds
        .borrow()
        .iter()
        .any(|seed| seed.as_slice() == expected_context));
}

static MEASUREMENT_INFO: [MeasurementInfo; 1] = [MeasurementInfo {
    index: 0x01,
    value_size: 4,
    value_type: 0,
    is_raw: false,
    is_tcb: true,
}];
static MEASUREMENT_VALUE: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

fn v14_pal() -> TestPal {
    TestPal {
        provisioned_slots: 0x01,
        measurement_info: &MEASUREMENT_INFO,
        measurement_value: &MEASUREMENT_VALUE,
        ..Default::default()
    }
}

fn v14_state() -> ConnectionState<TestHashState, Vec<u8>> {
    let mut state = ConnectionState::default();
    state.phase = Phase::AfterAlgorithms;
    state.version = SpdmVersion::V14;
    state
}

fn challenge_request(version: SpdmVersion, slot_id: u8, meas_hash_type: u8) -> Vec<u8> {
    let mut req = vec![
        version.to_u8(),
        ReqRespCode::CHALLENGE.0,
        slot_id,
        meas_hash_type,
    ];
    req.extend_from_slice(&[0x5A; SPDM_NONCE_LEN]);
    req.extend_from_slice(&CONTEXT);
    req
}

fn get_measurements_request(version: SpdmVersion, attributes: u8, meas_op: u8) -> Vec<u8> {
    let mut req = vec![
        version.to_u8(),
        ReqRespCode::GET_MEASUREMENTS.0,
        attributes,
        meas_op,
    ];
    if attributes & 0x01 != 0 {
        req.extend_from_slice(&[0x5A; SPDM_NONCE_LEN]);
        req.push(0); // SlotIDParam
    }
    req.extend_from_slice(&CONTEXT);
    req
}

fn dispatch_request(
    state: &mut ConnectionState<TestHashState, Vec<u8>>,
    pal: &TestPal,
    request: Vec<u8>,
    code: ReqRespCode,
) -> SpdmResult<Vec<u8>> {
    let mut sessions: Sessions<TestPal, 1> = SessionManager::new();
    let io = TestIo::message(request);
    // Seed the VCA transcript that a real GET_VERSION..NEGOTIATE_ALGORITHMS
    // exchange would have produced; M1/L1 fork from it.
    if state.transcript.vca.is_none() {
        block_on(state.transcript.append_vca(pal, &io, b"vca")).unwrap();
    }
    block_on(dispatch(
        state,
        &mut sessions,
        pal,
        &io,
        code,
        &NoVdmBackend,
    ))
}

#[test]
fn v14_challenge_returns_challenge_auth_with_echoed_context() {
    let pal = v14_pal();
    let mut state = v14_state();

    let rsp = dispatch_request(
        &mut state,
        &pal,
        challenge_request(SpdmVersion::V14, 0, 0),
        ReqRespCode::CHALLENGE,
    )
    .unwrap();

    // hdr(2) + slot(1) + mask(1) + chain hash + nonce + opaque_len(2) + ctx + sig
    let ctx_offset = 2 + 2 + SHA384_HASH_SIZE + SPDM_NONCE_LEN + 2;
    assert_eq!(
        rsp.len(),
        ctx_offset + REQUESTER_CONTEXT_LEN + ECC_P384_SIGNATURE_SIZE
    );
    assert_eq!(rsp[0], SpdmVersion::V14.to_u8());
    assert_eq!(rsp[1], ReqRespCode::CHALLENGE_AUTH.0);
    assert_eq!(rsp[2], 0); // slot 0
    assert_eq!(rsp[3], 0x01); // slot mask
    assert_eq!(
        &rsp[ctx_offset..ctx_offset + REQUESTER_CONTEXT_LEN],
        &CONTEXT
    );
    // Signature slot is filled by the TestPal signer.
    let signature_offset = ctx_offset + REQUESTER_CONTEXT_LEN;
    assert!(rsp[signature_offset..].iter().all(|b| *b == 0x77));
    assert_v14_signature_inputs(
        &pal,
        &rsp,
        signature_offset,
        b"responder-challenge_auth signing",
    );
}

#[test]
fn v14_challenge_with_measurement_summary_hash() {
    let pal = v14_pal();
    let mut state = v14_state();

    let rsp = dispatch_request(
        &mut state,
        &pal,
        challenge_request(SpdmVersion::V14, 0, 0xFF),
        ReqRespCode::CHALLENGE,
    )
    .unwrap();

    // Same layout plus the 48-byte measurement summary hash before OpaqueDataLength.
    let ctx_offset = 2 + 2 + SHA384_HASH_SIZE + SPDM_NONCE_LEN + SHA384_HASH_SIZE + 2;
    assert_eq!(
        rsp.len(),
        ctx_offset + REQUESTER_CONTEXT_LEN + ECC_P384_SIGNATURE_SIZE
    );
    assert_eq!(rsp[0], SpdmVersion::V14.to_u8());
    assert_eq!(rsp[1], ReqRespCode::CHALLENGE_AUTH.0);
    assert_eq!(
        &rsp[ctx_offset..ctx_offset + REQUESTER_CONTEXT_LEN],
        &CONTEXT
    );
}

#[test]
fn v14_challenge_without_requester_context_is_rejected() {
    let pal = v14_pal();
    let mut state = v14_state();

    let mut req = challenge_request(SpdmVersion::V14, 0, 0);
    req.truncate(req.len() - REQUESTER_CONTEXT_LEN);

    let err = dispatch_request(&mut state, &pal, req, ReqRespCode::CHALLENGE).unwrap_err();

    assert_eq!(err.spec_byte(), SPDM_INVALID_REQUEST.spec_byte());
    assert_eq!(state.phase, Phase::AfterAlgorithms);
}

#[test]
fn v14_challenge_version_mismatch_is_rejected() {
    let pal = v14_pal();
    let mut state = v14_state();

    let err = dispatch_request(
        &mut state,
        &pal,
        challenge_request(SpdmVersion::V13, 0, 0),
        ReqRespCode::CHALLENGE,
    )
    .unwrap_err();

    assert_eq!(
        err.spec_byte(),
        crate::error::SPDM_VERSION_MISMATCH.spec_byte()
    );
}

#[test]
fn v14_signed_measurements_echoes_context_and_signs() {
    let pal = v14_pal();
    let mut state = v14_state();

    let rsp = dispatch_request(
        &mut state,
        &pal,
        get_measurements_request(SpdmVersion::V14, 0x01, 0x01),
        ReqRespCode::GET_MEASUREMENTS,
    )
    .unwrap();

    assert_eq!(rsp[0], SpdmVersion::V14.to_u8());
    assert_eq!(rsp[1], ReqRespCode::MEASUREMENTS.0);
    // Param2: slot 0 | ContentChanged=no-change-detected (2) << 4.
    assert_eq!(rsp[3], 0x20);
    assert_eq!(rsp[4], 1); // NumberOfBlocks
    let record_len = u32::from_le_bytes([rsp[5], rsp[6], rsp[7], 0]) as usize;
    let ctx_offset = 2 + 6 + record_len + SPDM_NONCE_LEN + 2;
    assert_eq!(
        rsp.len(),
        ctx_offset + REQUESTER_CONTEXT_LEN + ECC_P384_SIGNATURE_SIZE
    );
    assert_eq!(
        &rsp[ctx_offset..ctx_offset + REQUESTER_CONTEXT_LEN],
        &CONTEXT
    );
    let signature_offset = ctx_offset + REQUESTER_CONTEXT_LEN;
    assert!(rsp[signature_offset..].iter().all(|b| *b == 0x77));
    assert_v14_signature_inputs(
        &pal,
        &rsp,
        signature_offset,
        b"responder-measurements signing",
    );
}

#[test]
fn v14_unsigned_measurements_echoes_context_without_signature() {
    let pal = v14_pal();
    let mut state = v14_state();

    let rsp = dispatch_request(
        &mut state,
        &pal,
        get_measurements_request(SpdmVersion::V14, 0x00, 0x01),
        ReqRespCode::GET_MEASUREMENTS,
    )
    .unwrap();

    assert_eq!(rsp[0], SpdmVersion::V14.to_u8());
    assert_eq!(rsp[1], ReqRespCode::MEASUREMENTS.0);
    let record_len = u32::from_le_bytes([rsp[5], rsp[6], rsp[7], 0]) as usize;
    let ctx_offset = 2 + 6 + record_len + SPDM_NONCE_LEN + 2;
    assert_eq!(rsp.len(), ctx_offset + REQUESTER_CONTEXT_LEN);
    assert_eq!(
        &rsp[ctx_offset..ctx_offset + REQUESTER_CONTEXT_LEN],
        &CONTEXT
    );
}

#[test]
fn v14_measurements_without_requester_context_is_rejected() {
    let pal = v14_pal();
    let mut state = v14_state();

    let mut req = get_measurements_request(SpdmVersion::V14, 0x01, 0x01);
    req.truncate(req.len() - REQUESTER_CONTEXT_LEN);

    let err = dispatch_request(&mut state, &pal, req, ReqRespCode::GET_MEASUREMENTS).unwrap_err();

    assert_eq!(err.spec_byte(), SPDM_INVALID_REQUEST.spec_byte());
}

#[test]
fn v14_measurements_version_mismatch_is_rejected() {
    let pal = v14_pal();
    let mut state = v14_state();

    let err = dispatch_request(
        &mut state,
        &pal,
        get_measurements_request(SpdmVersion::V13, 0x01, 0x01),
        ReqRespCode::GET_MEASUREMENTS,
    )
    .unwrap_err();

    assert_eq!(
        err.spec_byte(),
        crate::error::SPDM_VERSION_MISMATCH.spec_byte()
    );
}
