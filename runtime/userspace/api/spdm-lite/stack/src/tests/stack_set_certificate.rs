// Licensed under the Apache-2.0 license

extern crate std;

use super::*;
use futures::executor::block_on;
use mcu_spdm_lite_traits::NoVdmBackend;
use std::vec::Vec;

#[path = "support.rs"]
mod support;
use support::*;

fn send_secured_chunk(
    state: &mut ConnectionState<TestHashState, Vec<u8>>,
    sessions: &mut Sessions<TestPal, 1>,
    pal: &TestPal,
    session_id: u32,
    chunk_send: &[u8],
) -> Vec<u8> {
    let io = secured_io(session_id, chunk_send);
    block_on(handle_secured_request(
        state,
        sessions,
        pal,
        &io,
        &NoVdmBackend,
    ))
    .unwrap()
    .unwrap()
}

fn send_plaintext_chunk(
    state: &mut ConnectionState<TestHashState, Vec<u8>>,
    sessions: &mut Sessions<TestPal, 1>,
    pal: &TestPal,
    chunk_send: &[u8],
) -> Vec<u8> {
    let io = TestIo::message(chunk_send.to_vec());
    block_on(dispatch(
        state,
        sessions,
        pal,
        &io,
        ReqRespCode::CHUNK_SEND,
        &NoVdmBackend,
    ))
    .unwrap()
}

#[test]
fn plaintext_chunked_set_certificate_succeeds() {
    let pal = TestPal::default();
    let mut state = chunking_state();
    let mut sessions = crate::session::SessionManager::new();
    let large_req = set_certificate_request(&pal);
    let (first, second) = split_large_request(&large_req);
    let first_chunk = chunk_send_request(7, 0, false, Some(large_req.len()), first);
    let second_chunk = chunk_send_request(7, 1, true, None, second);

    let rsp = send_plaintext_chunk(&mut state, &mut sessions, &pal, &first_chunk);
    assert_eq!(
        &rsp[..],
        &[
            SpdmVersion::V12.to_u8(),
            ReqRespCode::CHUNK_SEND_ACK.0,
            0,
            7,
            0,
            0
        ]
    );
    assert!(state.large_msg_ctx.request_in_progress());

    let rsp = send_plaintext_chunk(&mut state, &mut sessions, &pal, &second_chunk);
    assert_eq!(
        &rsp[..],
        &[
            SpdmVersion::V12.to_u8(),
            ReqRespCode::CHUNK_SEND_ACK.0,
            0,
            7,
            1,
            0,
            SpdmVersion::V12.to_u8(),
            ReqRespCode::SET_CERTIFICATE_RSP.0,
            1,
            0,
        ]
    );
    assert!(!state.large_msg_ctx.request_in_progress());
    assert_eq!(
        pal.op.take(),
        Some(StoreOp::Write {
            slot: 1,
            key_pair_id: 0,
            cert_model: 2,
            root_hash: test_digest(&pal.cert_chain[..5]),
            cert_chain: pal.cert_chain.to_vec(),
        })
    );
}

#[test]
fn secured_chunked_set_certificate_is_unsupported() {
    let pal = TestPal::default();
    let (mut state, mut sessions, session_id) = established_session(&pal);
    let large_req = set_certificate_request(&pal);
    let (first, second) = split_large_request(&large_req);
    let first_chunk = chunk_send_request(7, 0, false, Some(large_req.len()), first);
    let second_chunk = chunk_send_request(7, 1, true, None, second);

    let rsp = send_secured_chunk(&mut state, &mut sessions, &pal, session_id, &first_chunk);
    assert_eq!(
        secured_spdm_response(&rsp),
        &[
            SpdmVersion::V12.to_u8(),
            ReqRespCode::CHUNK_SEND_ACK.0,
            0,
            7,
            0,
            0
        ]
    );
    assert!(state.large_msg_ctx.request_in_progress());

    let rsp = send_secured_chunk(&mut state, &mut sessions, &pal, session_id, &second_chunk);
    assert_eq!(
        secured_spdm_response(&rsp),
        &[
            SpdmVersion::V12.to_u8(),
            ReqRespCode::CHUNK_SEND_ACK.0,
            0,
            7,
            1,
            0,
            SpdmVersion::V12.to_u8(),
            ReqRespCode::ERROR.0,
            SPDM_UNSUPPORTED_REQUEST.spec_byte(),
            0,
        ]
    );
    assert!(!state.large_msg_ctx.request_in_progress());
    assert_eq!(pal.op.take(), None);
}
