// Licensed under the Apache-2.0 license

//! SPDM 1.4 GET_MEASUREMENTS / MEASUREMENTS dispatch tests.
//!
//! SPDM 1.4 keeps the 1.3 wire format, so these tests pin the
//! negotiated-1.4 behavior for requester context, response version, and
//! signed and unsigned responses.

#![allow(clippy::field_reassign_with_default)]

extern crate std;

use super::*;
use caliptra_mcu_spdm_codec::{
    ReqRespCode, SpdmVersion, ECC_P384_SIGNATURE_SIZE, REQUESTER_CONTEXT_LEN, SPDM_PREFIX_LEN,
    SPDM_SIGNING_CONTEXT_LEN,
};
use caliptra_mcu_spdm_traits::{MeasurementInfo, NoVdmBackend, SPDM_NONCE_LEN};
use futures::executor::block_on;
use std::vec;
use std::vec::Vec;

#[path = "support.rs"]
mod support;
use support::{test_digest, TestHashState, TestIo, TestPal};

const CONTEXT: [u8; REQUESTER_CONTEXT_LEN] = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];

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
    ConnectionState {
        phase: Phase::AfterAlgorithms,
        version: SpdmVersion::V14,
        ..ConnectionState::default()
    }
}

fn get_measurements_request(version: SpdmVersion, attributes: u8, operation: u8) -> Vec<u8> {
    let mut req = vec![
        version.to_u8(),
        ReqRespCode::GET_MEASUREMENTS.0,
        attributes,
        operation,
    ];
    if attributes & 0x01 != 0 {
        req.extend_from_slice(&[0x5A; SPDM_NONCE_LEN]);
        req.push(0);
    }
    req.extend_from_slice(&CONTEXT);
    req
}

fn dispatch_measurements(
    state: &mut ConnectionState<TestHashState, Vec<u8>>,
    pal: &TestPal,
    request: Vec<u8>,
) -> SpdmResult<Vec<u8>> {
    let mut sessions: Sessions<TestPal, 1> = SessionManager::new();
    let io = TestIo::message(request);
    block_on(state.transcript.append_vca(pal, &io, b"vca")).unwrap();
    block_on(dispatch(
        state,
        &mut sessions,
        pal,
        &io,
        ReqRespCode::GET_MEASUREMENTS,
        &NoVdmBackend,
    ))
}

fn v14_signing_context() -> [u8; SPDM_SIGNING_CONTEXT_LEN] {
    let mut context = [0u8; SPDM_SIGNING_CONTEXT_LEN];
    let prefix = b"dmtf-spdm-v1.4.*";
    for chunk in context[..SPDM_PREFIX_LEN].chunks_exact_mut(prefix.len()) {
        chunk.copy_from_slice(prefix);
    }
    let operation = b"responder-measurements signing";
    let operation_start = SPDM_SIGNING_CONTEXT_LEN - operation.len();
    context[operation_start..].copy_from_slice(operation);
    context
}

fn assert_v14_signature_inputs(pal: &TestPal, response: &[u8], signature_offset: usize) {
    let signed_hashes = pal.signed_hashes.borrow();
    assert_eq!(signed_hashes.len(), 1);
    let transcript_hash = test_digest(&response[..signature_offset]);
    assert_eq!(signed_hashes[0], test_digest(&transcript_hash));
    assert!(pal
        .hash_seeds
        .borrow()
        .iter()
        .any(|seed| seed.as_slice() == v14_signing_context()));
}

#[test]
fn signed_measurements_echo_v14_context_and_sign() {
    let pal = v14_pal();
    let mut state = v14_state();

    let rsp = dispatch_measurements(
        &mut state,
        &pal,
        get_measurements_request(SpdmVersion::V14, 0x01, 0x01),
    )
    .unwrap();

    assert_eq!(rsp[0], SpdmVersion::V14.to_u8());
    assert_eq!(rsp[1], ReqRespCode::MEASUREMENTS.0);
    assert_eq!(rsp[3], 0x20);
    assert_eq!(rsp[4], 1);
    let record_len = u32::from_le_bytes([rsp[5], rsp[6], rsp[7], 0]) as usize;
    let context_offset = 2 + 6 + record_len + SPDM_NONCE_LEN + 2;
    assert_eq!(
        rsp.len(),
        context_offset + REQUESTER_CONTEXT_LEN + ECC_P384_SIGNATURE_SIZE
    );
    assert_eq!(
        &rsp[context_offset..context_offset + REQUESTER_CONTEXT_LEN],
        &CONTEXT
    );

    let signature_offset = context_offset + REQUESTER_CONTEXT_LEN;
    assert!(rsp[signature_offset..].iter().all(|byte| *byte == 0x77));
    assert_v14_signature_inputs(&pal, &rsp, signature_offset);
}

#[test]
fn unsigned_measurements_echo_v14_context_without_signature() {
    let pal = v14_pal();
    let mut state = v14_state();

    let rsp = dispatch_measurements(
        &mut state,
        &pal,
        get_measurements_request(SpdmVersion::V14, 0x00, 0x01),
    )
    .unwrap();

    assert_eq!(rsp[0], SpdmVersion::V14.to_u8());
    assert_eq!(rsp[1], ReqRespCode::MEASUREMENTS.0);
    let record_len = u32::from_le_bytes([rsp[5], rsp[6], rsp[7], 0]) as usize;
    let context_offset = 2 + 6 + record_len + SPDM_NONCE_LEN + 2;
    assert_eq!(rsp.len(), context_offset + REQUESTER_CONTEXT_LEN);
    assert_eq!(
        &rsp[context_offset..context_offset + REQUESTER_CONTEXT_LEN],
        &CONTEXT
    );
}

#[test]
fn measurements_reject_missing_v14_requester_context() {
    let pal = v14_pal();
    let mut state = v14_state();
    let mut req = get_measurements_request(SpdmVersion::V14, 0x01, 0x01);
    req.truncate(req.len() - REQUESTER_CONTEXT_LEN);

    let err = dispatch_measurements(&mut state, &pal, req).unwrap_err();

    assert_eq!(err.spec_byte(), SPDM_INVALID_REQUEST.spec_byte());
}

#[test]
fn measurements_reject_version_mismatch_after_v14_negotiation() {
    let pal = v14_pal();
    let mut state = v14_state();

    let err = dispatch_measurements(
        &mut state,
        &pal,
        get_measurements_request(SpdmVersion::V13, 0x01, 0x01),
    )
    .unwrap_err();

    assert_eq!(
        err.spec_byte(),
        crate::error::SPDM_VERSION_MISMATCH.spec_byte()
    );
}
