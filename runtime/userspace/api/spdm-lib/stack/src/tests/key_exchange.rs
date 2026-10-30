// Licensed under the Apache-2.0 license

extern crate std;

use super::*;
use caliptra_mcu_spdm_codec::{
    CapFlags, KeyExchangeReqBodyFixed, PqcAsymAlgos, ReqRespCode, SpdmVersion,
    ECC_P384_SIGNATURE_SIZE, ECDH_P384_EXCHANGE_DATA_SIZE, KEY_EXCHANGE_RSP_FIXED_BODY_SIZE,
};
use caliptra_mcu_spdm_traits::SpdmPalHash;
use futures::executor::block_on;
use std::vec::Vec;
use zerocopy::IntoBytes;

#[path = "support.rs"]
mod support;
use support::{drain_chunked_response, negotiated_state, TestIo, TestPal};

fn key_exchange_request(opaque_data: &[u8]) -> Vec<u8> {
    let fixed = KeyExchangeReqBodyFixed {
        meas_summary_hash_type: 0,
        slot_id: 0,
        req_session_id: 0x1234u16.to_le_bytes(),
        session_policy: 0,
        _reserved: 0,
        random_data: [0x5a; KEY_EXCHANGE_RANDOM_DATA_LEN],
    };
    let mut request = std::vec![SpdmVersion::V13.to_u8(), ReqRespCode::KEY_EXCHANGE.0];
    request.extend_from_slice(fixed.as_bytes());
    request.extend_from_slice(&[0x3c; ECDH_P384_EXCHANGE_DATA_SIZE]);
    request.extend_from_slice(&(opaque_data.len() as u16).to_le_bytes());
    request.extend_from_slice(opaque_data);
    request
}

fn run_key_exchange(opaque_data: &[u8]) -> Vec<u8> {
    let pal = TestPal::default();
    let io = TestIo::message(key_exchange_request(opaque_data));
    let mut state = negotiated_state(SpdmVersion::V13);
    block_on(state.transcript.append_vca(&pal, &io, &[0xaa])).unwrap();
    let mut sessions: Sessions<TestPal, 1> = crate::session::SessionManager::new();

    block_on(handle_key_exchange(&mut state, &mut sessions, &pal, &io)).unwrap()
}

fn response_opaque_data(response: &[u8]) -> &[u8] {
    let opaque_len_offset =
        SpdmMsgHdrPdu::SIZE + KEY_EXCHANGE_RSP_FIXED_BODY_SIZE + ECDH_P384_EXCHANGE_DATA_SIZE;
    let opaque_len =
        u16::from_le_bytes([response[opaque_len_offset], response[opaque_len_offset + 1]]) as usize;
    &response[opaque_len_offset + 2..opaque_len_offset + 2 + opaque_len]
}

#[test]
fn empty_request_opaque_data_produces_empty_response_opaque_data() {
    let response = run_key_exchange(&[]);

    assert_eq!(response[1], ReqRespCode::KEY_EXCHANGE_RSP.0);
    let exchange_data_start = SpdmMsgHdrPdu::SIZE + KEY_EXCHANGE_RSP_FIXED_BODY_SIZE;
    assert!(
        response[exchange_data_start..exchange_data_start + ECDH_P384_EXCHANGE_DATA_SIZE]
            .iter()
            .all(|&byte| byte == 0x4d)
    );
    assert!(response_opaque_data(&response).is_empty());
}

#[test]
fn supported_version_list_produces_version_selection() {
    let opaque_data = [
        1, 0, 0, 0, // General header.
        0, 0, 5, 0, // DMTF element, five data bytes.
        1, 1, 1, // Supported-version-list header, one version.
        0, 0x11, // Secured-message version 1.1.
        0, 0, 0, // Alignment padding.
    ];

    let response = run_key_exchange(&opaque_data);

    assert_eq!(
        response_opaque_data(&response),
        &[1, 0, 0, 0, 0, 0, 4, 0, 1, 0, 0, 0x11]
    );
}

#[test]
fn ecdsa_response_can_be_chunked() {
    let pal = TestPal {
        mtu: 128,
        large_buffered_msg_capacity: 1024,
        ..Default::default()
    };
    let request = key_exchange_request(&[]);
    let io = TestIo::message(request);
    let mut state = negotiated_state(SpdmVersion::V13);
    state.peer_cap_flags = CapFlags::CHUNK;
    state.peer_data_transfer_size = 128;
    state.peer_max_spdm_msg_size = 1024;
    block_on(state.transcript.append_vca(&pal, &io, &[0xaa])).unwrap();
    let mut sessions: Sessions<TestPal, 1> = crate::session::SessionManager::new();

    let err_rsp = block_on(handle_key_exchange(&mut state, &mut sessions, &pal, &io)).unwrap();
    let (err_hdr, err_body) = SpdmMsgHdrPdu::ref_from_prefix(&err_rsp).unwrap();
    assert_eq!(err_hdr.code, ReqRespCode::ERROR);
    let handle = err_body[2];

    let drain_io = TestIo::message(Vec::new());
    let response = block_on(drain_chunked_response(&mut state, &pal, &drain_io, handle)).unwrap();
    let (rsp_hdr, _) = SpdmMsgHdrPdu::ref_from_prefix(&response).unwrap();
    assert_eq!(rsp_hdr.code, ReqRespCode::KEY_EXCHANGE_RSP);

    let signature_start =
        SpdmMsgHdrPdu::SIZE + KEY_EXCHANGE_RSP_FIXED_BODY_SIZE + ECDH_P384_EXCHANGE_DATA_SIZE + 2;
    let signature = &response[signature_start..signature_start + ECC_P384_SIGNATURE_SIZE];
    assert!(signature.iter().all(|&byte| byte == 0x77));
}

#[test]
fn v14_key_exchange_is_unsupported_for_ecc_and_mldsa() {
    for pqc_algo in [PqcAsymAlgos::EMPTY, PqcAsymAlgos::ML_DSA_87] {
        let pal = TestPal::default();
        let mut request = key_exchange_request(&[]);
        request[0] = SpdmVersion::V14.to_u8();
        let io = TestIo::message(request);
        let mut state = negotiated_state(SpdmVersion::V14);
        state.negotiated_pqc_asym_sel = pqc_algo;
        let mut sessions: Sessions<TestPal, 1> = crate::session::SessionManager::new();

        let err = block_on(handle_key_exchange(&mut state, &mut sessions, &pal, &io)).unwrap_err();

        assert_eq!(err.spec_byte(), SPDM_UNSUPPORTED_REQUEST.spec_byte());
        assert_eq!(err.error_data(), ReqRespCode::KEY_EXCHANGE.0);
        assert!(!sessions.has_handshake_in_progress());
        assert!(pal.sign_ops.borrow().is_empty());
    }
}

#[test]
fn v14_buffered_key_exchange_is_unsupported() {
    let pal = TestPal::default();
    let mut request = key_exchange_request(&[]);
    request[0] = SpdmVersion::V14.to_u8();
    let request_len = request.len();
    let guard = WipeOnDrop { buf: Some(request) };
    let io = TestIo::message(Vec::new());
    let mut state = negotiated_state(SpdmVersion::V14);
    let mut sessions: Sessions<TestPal, 1> = crate::session::SessionManager::new();

    let err = block_on(handle_buffered_key_exchange_req(
        &mut state,
        &mut sessions,
        &pal,
        &io,
        guard,
        request_len,
        128,
    ))
    .unwrap_err();

    assert_eq!(err.spec_byte(), SPDM_UNSUPPORTED_REQUEST.spec_byte());
    assert!(!sessions.has_handshake_in_progress());
    assert!(pal.sign_ops.borrow().is_empty());
}

#[test]
fn doe_and_mctp_supported_key_exchange_has_identical_payloads_and_signing_inputs() {
    for version in [SpdmVersion::V12, SpdmVersion::V13] {
        let mut baseline = None;
        for (header_size, send_len_alignment) in [(1, 1), (8, 4)] {
            let pal = TestPal {
                header_size,
                send_len_alignment,
                mtu: 8192,
                ..TestPal::default()
            };
            let mut state = negotiated_state(version);
            let mut request = key_exchange_request(&[]);
            request[0] = version.to_u8();
            if send_len_alignment == 4 {
                request.resize(request.len().next_multiple_of(4), 0);
            }
            let io = TestIo::message(request);
            block_on(state.transcript.append_vca(&pal, &io, b"VCA")).unwrap();
            let mut sessions: Sessions<TestPal, 1> = crate::session::SessionManager::new();
            let response =
                block_on(handle_key_exchange(&mut state, &mut sessions, &pal, &io)).unwrap();
            let spdm_len = SpdmMsgHdrPdu::SIZE
                + KEY_EXCHANGE_RSP_FIXED_BODY_SIZE
                + ECDH_P384_EXCHANGE_DATA_SIZE
                + 2
                + ECC_P384_SIGNATURE_SIZE
                + support::SHA384_DIGEST_SIZE;
            assert_eq!(
                response.len(),
                (header_size + spdm_len).next_multiple_of(send_len_alignment)
            );
            assert!(response[header_size + spdm_len..]
                .iter()
                .all(|&byte| byte == 0));
            let payload = &response[header_size..header_size + spdm_len];
            assert_eq!(payload[1], ReqRespCode::KEY_EXCHANGE_RSP.0);
            assert!(sessions.has_handshake_in_progress());
            let result = (
                payload.to_vec(),
                pal.sign_ops.borrow().clone(),
                pal.hash_finishes.borrow().clone(),
            );
            if let Some(expected) = &baseline {
                assert_eq!(&result, expected);
            } else {
                baseline = Some(result);
            }
        }
    }
}

#[test]
fn invalid_key_exchange_preserves_capacity_and_transcript_for_valid_retry() {
    for (header_size, send_len_alignment) in [(1, 1), (8, 4)] {
        let pal = TestPal {
            header_size,
            send_len_alignment,
            ..TestPal::default()
        };
        let mut state = negotiated_state(SpdmVersion::V13);
        let valid = key_exchange_request(&[]);
        let mut sessions: Sessions<TestPal, 1> = crate::session::SessionManager::new();
        let seed = TestIo::message(Vec::new());
        block_on(state.transcript.append_vca(&pal, &seed, b"VCA")).unwrap();
        for request in [
            valid[..valid.len() - 1].to_vec(),
            key_exchange_request(&[0xff]),
        ] {
            let io = TestIo::message(request);
            assert!(block_on(handle_key_exchange(&mut state, &mut sessions, &pal, &io)).is_err());
            assert!(!sessions.has_handshake_in_progress());
            assert!(pal.sign_ops.borrow().is_empty());
            let mut digest = [0; support::SHA384_DIGEST_SIZE];
            block_on(pal.hash_finish(&io, state.transcript.vca.as_mut().unwrap(), &mut digest))
                .unwrap();
            assert_eq!(digest, support::test_digest(b"VCA"));
        }

        let io = TestIo::message(valid);
        let response = block_on(handle_key_exchange(&mut state, &mut sessions, &pal, &io)).unwrap();
        assert_eq!(response[header_size + 1], ReqRespCode::KEY_EXCHANGE_RSP.0);
        assert!(sessions.has_handshake_in_progress());
    }
}
