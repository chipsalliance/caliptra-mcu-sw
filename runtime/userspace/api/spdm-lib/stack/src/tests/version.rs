// Licensed under the Apache-2.0 license

extern crate std;

use super::*;
use caliptra_mcu_spdm_codec::{CapFlags, ReqRespCode, SpdmVersion};
use caliptra_mcu_spdm_traits::{NoVdmBackend, SpdmPalAlloc, SpdmPalHash};
use futures::executor::block_on;
use std::vec;
use std::vec::Vec;

#[path = "support.rs"]
mod support;
use support::{test_digest, TestHashState, TestIo, TestPal};

fn get_version_request(version: u8, param1: u8, param2: u8) -> Vec<u8> {
    vec![version, ReqRespCode::GET_VERSION.0, param1, param2]
}

fn dispatch_request(
    state: &mut ConnectionState<TestHashState, Vec<u8>>,
    sessions: &mut Sessions<TestPal, 1>,
    pal: &TestPal,
    request: Vec<u8>,
) -> SpdmResult<Vec<u8>> {
    let io = TestIo::message(request);
    block_on(dispatch(
        state,
        sessions,
        pal,
        &io,
        ReqRespCode::GET_VERSION,
        &NoVdmBackend,
    ))
}

#[test]
fn get_version_advertises_v14_and_resets_valid_connection() {
    let pal = TestPal::default();
    let mut state = ConnectionState {
        phase: Phase::AfterAlgorithms,
        version: SpdmVersion::V13,
        peer_cap_flags: CapFlags::CHUNK,
        ..ConnectionState::default()
    };
    let mut sessions = SessionManager::new();
    let session_id = sessions
        .create_session(0x1234, SpdmVersion::V13, |info| pal.alloc_persistent(info))
        .unwrap();

    let rsp = dispatch_request(
        &mut state,
        &mut sessions,
        &pal,
        get_version_request(SpdmVersion::V10.to_u8(), 0, 0),
    )
    .unwrap();

    assert_eq!(
        rsp,
        [
            SpdmVersion::V10.to_u8(),
            ReqRespCode::VERSION.0,
            0,
            0,
            0,
            3,
            0,
            SpdmVersion::V14.to_u8(),
            0,
            SpdmVersion::V13.to_u8(),
            0,
            SpdmVersion::V12.to_u8(),
        ]
    );
    assert_eq!(state.phase, Phase::AfterVersion);
    assert_eq!(
        state.peer_cap_flags.into_bits(),
        CapFlags::EMPTY.into_bits()
    );
    assert!(sessions.find(session_id).is_none());
}

#[test]
fn invalid_get_version_preserves_connection_and_sessions() {
    let pal = TestPal::default();
    let mut state = ConnectionState {
        phase: Phase::AfterAlgorithms,
        version: SpdmVersion::V13,
        peer_cap_flags: CapFlags::CHUNK,
        ..ConnectionState::default()
    };
    let mut sessions = SessionManager::new();
    let session_id = sessions
        .create_session(0x1234, SpdmVersion::V13, |info| pal.alloc_persistent(info))
        .unwrap();

    let err = dispatch_request(
        &mut state,
        &mut sessions,
        &pal,
        get_version_request(SpdmVersion::V11.to_u8(), 0, 0),
    )
    .unwrap_err();

    assert_eq!(err.spec_byte(), SPDM_VERSION_MISMATCH.spec_byte());
    assert_eq!(state.phase, Phase::AfterAlgorithms);
    assert_eq!(state.version, SpdmVersion::V13);
    assert_eq!(
        state.peer_cap_flags.into_bits(),
        CapFlags::CHUNK.into_bits()
    );
    assert!(sessions.find(session_id).is_some());
}

#[test]
fn get_version_clears_transcript_and_chunk_state() {
    let mut baseline = None;
    for (header_size, send_len_alignment) in [(0, 1), (1, 1), (8, 4)] {
        let pal = TestPal {
            header_size,
            send_len_alignment,
            ..TestPal::default()
        };
        let io = TestIo::message(Vec::new());
        let mut state = ConnectionState {
            phase: Phase::AfterAlgorithms,
            version: SpdmVersion::V14,
            ..ConnectionState::default()
        };
        block_on(state.transcript.append_vca(&pal, &io, b"VCA")).unwrap();
        block_on(state.transcript.append_m1(&pal, &io, b"M1")).unwrap();
        block_on(state.transcript.append_l1(&pal, &io, b"L1")).unwrap();
        state
            .large_msg_ctx
            .start_response(
                crate::chunk::LargeResponse::Buffered,
                3,
                Some(vec![1, 2, 3]),
            )
            .unwrap();
        let mut sessions = SessionManager::new();
        let request = get_version_request(SpdmVersion::V10.to_u8(), 0, 0);
        let response = dispatch_request(&mut state, &mut sessions, &pal, request.clone()).unwrap();
        let payload = &response[header_size..header_size + 12];
        assert_eq!(response.len() % send_len_alignment, 0);
        assert!(response[..header_size].iter().all(|&byte| byte == 0));
        assert!(response[header_size + 12..].iter().all(|&byte| byte == 0));
        assert_eq!(state.phase, Phase::AfterVersion);
        assert_eq!(
            state.transcript.vca.as_ref().unwrap().bytes,
            [request.as_slice(), payload].concat()
        );
        let mut vca_digest = [0u8; support::SHA384_DIGEST_SIZE];
        block_on(pal.hash_finish(&io, state.transcript.vca.as_mut().unwrap(), &mut vca_digest))
            .unwrap();
        assert_eq!(vca_digest, test_digest(payload));
        assert!(state.transcript.m1.is_none());
        assert!(state.transcript.l1.is_none());
        assert!(state.large_msg_ctx.is_idle());
        assert!(state.large_msg_ctx.get_buffer().is_none());
        let result = (payload.to_vec(), pal.hash_finishes.borrow().clone());
        if let Some(expected) = &baseline {
            assert_eq!(&result, expected);
        } else {
            baseline = Some(result);
        }
    }
}

#[test]
fn get_version_ignores_reserved_parameters() {
    let pal = TestPal::default();
    let mut state = ConnectionState::default();
    let mut sessions = SessionManager::new();

    dispatch_request(
        &mut state,
        &mut sessions,
        &pal,
        get_version_request(SpdmVersion::V10.to_u8(), 0xa5, 0x5a),
    )
    .unwrap();

    assert_eq!(state.phase, Phase::AfterVersion);
}
