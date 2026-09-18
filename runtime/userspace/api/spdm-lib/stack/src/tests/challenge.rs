// Licensed under the Apache-2.0 license

//! CHALLENGE / CHALLENGE_AUTH tests.
//!
//! SPDM 1.4 leaves the CHALLENGE_AUTH wire format unchanged, but adds PQC
//! signing algorithms. When ML-DSA-87 is negotiated the signature grows from
//! 96 to 4627 bytes and is produced with pure `ML-DSA.Sign` rather than a
//! pre-hashed ECDSA digest.

#![allow(clippy::field_reassign_with_default)]

extern crate std;

use super::*;
use crate::build::SPDM_SIGNING_CONTEXT_LEN;
use caliptra_mcu_spdm_codec::{
    AsymAlgos, CapFlags, PqcAsymAlgos, ReqRespCode, ECC_P384_SIGNATURE_SIZE, MLDSA87_SIGNATURE_SIZE,
};
use futures::executor::block_on;
use std::vec::Vec;

use crate::error::SPDM_VERSION_MISMATCH;

#[path = "support.rs"]
mod support;
use support::{
    drain_chunked_response, negotiated_state, RecordedSigningInput, TestHashState, TestIo, TestPal,
};

const REQ_CTX: [u8; REQUESTER_CONTEXT_LEN] = [0x11; REQUESTER_CONTEXT_LEN];

/// Build a CHALLENGE request. V1.3+ appends the 8-byte RequesterContext.
fn challenge_request(version: SpdmVersion, slot_id: u8, meas_hash_type: u8) -> Vec<u8> {
    let mut req = std::vec![
        version.to_u8(),
        ReqRespCode::CHALLENGE.0,
        slot_id,
        meas_hash_type
    ];
    req.extend_from_slice(&[0xAB; SPDM_NONCE_LEN]);
    if version >= SpdmVersion::V13 {
        req.extend_from_slice(&REQ_CTX);
    }
    req
}

fn ecdsa_state(version: SpdmVersion) -> ConnectionState<TestHashState, Vec<u8>> {
    negotiated_state(version)
}

/// SPDM 1.4 PQC negotiation: `BaseAsymSel` is zeroed and `PqcAsymSel` carries
/// ML-DSA-87, mirroring what `algorithms.rs` selects against a PQC requester.
fn mldsa_state(version: SpdmVersion) -> ConnectionState<TestHashState, Vec<u8>> {
    let mut state = negotiated_state(version);
    state.negotiated_base_asym_sel = AsymAlgos::EMPTY;
    state.negotiated_pqc_asym_sel = PqcAsymAlgos::ML_DSA_87;
    state
}

/// Run a CHALLENGE and return the SPDM message bytes of the response.
fn run_challenge(
    state: &mut ConnectionState<TestHashState, Vec<u8>>,
    pal: &TestPal,
    version: SpdmVersion,
) -> Vec<u8> {
    let io = TestIo::message(challenge_request(version, 0, 0));
    block_on(state.transcript.append_vca(pal, &io, &[0xAA, 0xBB])).unwrap();
    let rsp = block_on(handle_challenge(state, pal, &io)).unwrap();
    rsp[pal.header_size()..].to_vec()
}

/// Split a CHALLENGE_AUTH message into its pre-signature prefix and signature.
fn split_signature(msg: &[u8], has_req_ctx: bool, sig_len: usize) -> (&[u8], &[u8]) {
    let mut no_sig = SpdmMsgHdrPdu::SIZE + 1 + 1 + SHA384_HASH_SIZE + SPDM_NONCE_LEN + 2;
    if has_req_ctx {
        no_sig += REQUESTER_CONTEXT_LEN;
    }
    assert_eq!(msg.len(), no_sig + sig_len);
    (&msg[..no_sig], &msg[no_sig..])
}

#[test]
fn challenge_v14_ecdsa_emits_96_byte_signature() {
    let pal = TestPal::default();
    let mut state = ecdsa_state(SpdmVersion::V14);

    let msg = run_challenge(&mut state, &pal, SpdmVersion::V14);

    let (hdr, _) = SpdmMsgHdrPdu::ref_from_prefix(&msg).unwrap();
    assert_eq!(hdr.code, ReqRespCode::CHALLENGE_AUTH);
    assert_eq!(hdr.version, SpdmVersion::V14.to_u8());

    let (prefix, sig) = split_signature(&msg, true, ECC_P384_SIGNATURE_SIZE);
    assert_eq!(sig.len(), ECC_P384_SIGNATURE_SIZE);
    assert!(sig.iter().all(|&b| b == 0x77));

    // RequesterContext is echoed verbatim immediately before the signature.
    assert_eq!(&prefix[prefix.len() - REQUESTER_CONTEXT_LEN..], &REQ_CTX);

    let ops = pal.sign_ops.borrow();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].algo, SpdmPalAsymAlgo::EccP384);
    assert_eq!(ops[0].sig_len, ECC_P384_SIGNATURE_SIZE);
    assert!(matches!(
        ops[0].input,
        RecordedSigningInput::EccP384Digest(ref d) if d.len() == SHA384_HASH_SIZE
    ));
}

#[test]
fn challenge_v14_mldsa87_emits_4627_byte_signature() {
    let pal = TestPal {
        mtu: 8192,
        large_buffered_msg_capacity: 8192,
        ..Default::default()
    };
    let mut state = mldsa_state(SpdmVersion::V14);

    let msg = run_challenge(&mut state, &pal, SpdmVersion::V14);

    let (hdr, _) = SpdmMsgHdrPdu::ref_from_prefix(&msg).unwrap();
    assert_eq!(hdr.code, ReqRespCode::CHALLENGE_AUTH);

    let (_, sig) = split_signature(&msg, true, MLDSA87_SIGNATURE_SIZE);
    assert_eq!(sig.len(), MLDSA87_SIGNATURE_SIZE);
    assert!(sig.iter().all(|&b| b == 0x77));

    let ops = pal.sign_ops.borrow();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].algo, SpdmPalAsymAlgo::MlDsa87);
    assert_eq!(ops[0].sig_len, MLDSA87_SIGNATURE_SIZE);
}

/// In SPDM 1.4: `M = combined_spdm_prefix || message_hash` and the
/// FIPS 204 `ctx` is the unpadded `spdm_context` string.
#[test]
fn challenge_v14_mldsa87_signs_prefix_and_m1_hash_with_spdm_context() {
    let pal = TestPal {
        mtu: 8192,
        large_buffered_msg_capacity: 8192,
        ..Default::default()
    };
    let mut state = mldsa_state(SpdmVersion::V14);

    run_challenge(&mut state, &pal, SpdmVersion::V14);

    let ops = pal.sign_ops.borrow();
    let RecordedSigningInput::Mldsa87Message { context, message } = &ops[0].input else {
        panic!("expected ML-DSA message signing input");
    };

    assert_eq!(context.as_slice(), b"responder-challenge_auth signing");
    assert_eq!(message.len(), SPDM_SIGNING_CONTEXT_LEN + SHA384_HASH_SIZE);
    assert_eq!(
        &message[..SPDM_SIGNING_CONTEXT_LEN],
        signing_context(SpdmVersion::V14).as_slice()
    );
    // The 1.4 prefix must be version-specific, not inherited from 1.3.
    assert!(message.starts_with(b"dmtf-spdm-v1.4.*"));
}

#[test]
fn challenge_v14_mldsa87_response_is_chunked_when_over_data_transfer_size() {
    let pal = TestPal {
        mtu: 1024,
        large_buffered_msg_capacity: 8192,
        ..Default::default()
    };
    let mut state = mldsa_state(SpdmVersion::V14);
    state.peer_cap_flags = CapFlags::CHUNK;
    state.peer_data_transfer_size = 1024;
    state.peer_max_spdm_msg_size = 8192;

    let io = TestIo::message(challenge_request(SpdmVersion::V14, 0, 0));
    block_on(state.transcript.append_vca(&pal, &io, &[0xAA, 0xBB])).unwrap();
    let err_rsp = block_on(handle_challenge(&mut state, &pal, &io)).unwrap();

    // Oversized responses are announced via ERROR/LargeResponse carrying a handle.
    let spdm_msg = &err_rsp[pal.header_size()..];
    let (err_hdr, err_body) = SpdmMsgHdrPdu::ref_from_prefix(spdm_msg).unwrap();
    assert_eq!(err_hdr.code, ReqRespCode::ERROR);
    let handle = err_body[2];

    let drain_io = TestIo::message(Vec::new());
    let msg = block_on(drain_chunked_response(&mut state, &pal, &drain_io, handle)).unwrap();

    let (hdr, _) = SpdmMsgHdrPdu::ref_from_prefix(&msg).unwrap();
    assert_eq!(hdr.code, ReqRespCode::CHALLENGE_AUTH);
    let (_, sig) = split_signature(&msg, true, MLDSA87_SIGNATURE_SIZE);
    assert_eq!(sig.len(), MLDSA87_SIGNATURE_SIZE);
    assert!(sig.iter().all(|&b| b == 0x77));
}

#[test]
fn challenge_v13_still_uses_ecdsa_sizing() {
    let pal = TestPal::default();
    let mut state = ecdsa_state(SpdmVersion::V13);

    let msg = run_challenge(&mut state, &pal, SpdmVersion::V13);

    let (_, sig) = split_signature(&msg, true, ECC_P384_SIGNATURE_SIZE);
    assert_eq!(sig.len(), ECC_P384_SIGNATURE_SIZE);
    assert!(signing_context(SpdmVersion::V13).starts_with(b"dmtf-spdm-v1.3.*"));
}

#[test]
fn challenge_v12_omits_requester_context() {
    let pal = TestPal::default();
    let mut state = ecdsa_state(SpdmVersion::V12);

    let msg = run_challenge(&mut state, &pal, SpdmVersion::V12);

    let (_, sig) = split_signature(&msg, false, ECC_P384_SIGNATURE_SIZE);
    assert_eq!(sig.len(), ECC_P384_SIGNATURE_SIZE);
}

#[test]
fn challenge_rejects_version_mismatch() {
    let pal = TestPal::default();
    let mut state = ecdsa_state(SpdmVersion::V14);

    let io = TestIo::message(challenge_request(SpdmVersion::V13, 0, 0));
    let err = block_on(handle_challenge(&mut state, &pal, &io)).unwrap_err();
    assert_eq!(err, SPDM_VERSION_MISMATCH);
}

#[test]
fn challenge_v14_rejects_truncated_requester_context() {
    let pal = TestPal::default();
    let mut state = ecdsa_state(SpdmVersion::V14);

    let mut req = challenge_request(SpdmVersion::V14, 0, 0);
    req.truncate(req.len() - 1);
    let io = TestIo::message(req);
    assert!(block_on(handle_challenge(&mut state, &pal, &io)).is_err());
}
