// Licensed under the Apache-2.0 license

extern crate std;

use super::*;
use caliptra_mcu_spdm_codec::{ReqRespCode, SpdmVersion};
use caliptra_mcu_spdm_traits::{NoVdmBackend, SpdmPalAlloc};
use futures::executor::block_on;

#[path = "support.rs"]
mod support;
use support::{established_session, secured_io, secured_spdm_response, TestIo, TestPal};

#[test]
fn replay_authentication_failure_destroys_session_and_rejects_stale_record() {
    for (header_size, send_len_alignment) in [(0, 1), (1, 1), (8, 4)] {
        replay_authentication_failure(header_size, send_len_alignment);
    }
}

fn replay_authentication_failure(header_size: usize, send_len_alignment: usize) {
    let pal = TestPal {
        header_size,
        send_len_alignment,
        ..TestPal::default()
    };
    let (mut state, mut sessions, session_id) = established_session(&pal);
    let seed_io = TestIo::message(std::vec::Vec::new());
    block_on(state.transcript.append_vca(&pal, &seed_io, b"VCA")).unwrap();
    let request = [SpdmVersion::V12.to_u8(), ReqRespCode::GET_DIGESTS.0, 0, 0];
    let io = secured_io(session_id, &request);

    let response = block_on(handle_secured_request(
        &mut state,
        &mut sessions,
        &pal,
        &io,
        &NoVdmBackend,
    ))
    .unwrap()
    .unwrap();
    assert_eq!(
        secured_spdm_response(&response[header_size..])[1],
        ReqRespCode::DIGESTS.0
    );
    assert!(sessions.find(session_id).is_some());

    pal.aead_decrypt_error
        .set(Some(mcu_error::codes::INVARIANT));
    let replay_response = block_on(handle_secured_request(
        &mut state,
        &mut sessions,
        &pal,
        &io,
        &NoVdmBackend,
    ))
    .unwrap()
    .unwrap();
    assert_eq!(
        secured_spdm_response(&replay_response[header_size..])[1],
        ReqRespCode::ERROR.0
    );
    assert!(sessions.find(session_id).is_none());

    assert!(block_on(handle_secured_request(
        &mut state,
        &mut sessions,
        &pal,
        &io,
        &NoVdmBackend,
    ))
    .unwrap()
    .is_none());
}

#[test]
fn invalid_end_session_preserves_session_for_valid_teardown_and_reuse() {
    for (header_size, send_len_alignment) in [(0, 1), (1, 1), (8, 4)] {
        invalid_end_session_and_reuse(header_size, send_len_alignment);
    }
}

fn invalid_end_session_and_reuse(header_size: usize, send_len_alignment: usize) {
    let pal = TestPal {
        header_size,
        send_len_alignment,
        ..TestPal::default()
    };
    let (mut state, mut sessions, session_id) = established_session(&pal);
    let invalid_io = secured_io(
        session_id,
        &[SpdmVersion::V12.to_u8(), ReqRespCode::END_SESSION.0, 2, 0],
    );

    let error_response = block_on(handle_secured_request(
        &mut state,
        &mut sessions,
        &pal,
        &invalid_io,
        &NoVdmBackend,
    ))
    .unwrap()
    .unwrap();
    assert_eq!(
        secured_spdm_response(&error_response[header_size..])[1],
        ReqRespCode::ERROR.0
    );
    assert!(sessions.find(session_id).is_some());

    let valid_io = secured_io(
        session_id,
        &[SpdmVersion::V12.to_u8(), ReqRespCode::END_SESSION.0, 0, 0],
    );
    let response = block_on(handle_secured_request(
        &mut state,
        &mut sessions,
        &pal,
        &valid_io,
        &NoVdmBackend,
    ))
    .unwrap()
    .unwrap();
    assert_eq!(
        secured_spdm_response(&response[header_size..]),
        [
            SpdmVersion::V12.to_u8(),
            ReqRespCode::END_SESSION_ACK.0,
            0,
            0,
        ]
    );
    assert!(sessions.find(session_id).is_none());
    assert!(block_on(handle_secured_request(
        &mut state,
        &mut sessions,
        &pal,
        &valid_io,
        &NoVdmBackend,
    ))
    .unwrap()
    .is_none());

    let replacement = sessions
        .create_session(0x4321, SpdmVersion::V12, |info| pal.alloc_persistent(info))
        .unwrap();
    assert_ne!(replacement, session_id);
    assert!(sessions.find(replacement).is_some());
}

#[test]
fn invalid_finish_releases_session_for_fresh_finish_and_teardown_on_both_layouts() {
    let mut baseline = None;
    for (header_size, send_len_alignment) in [(1, 1), (8, 4)] {
        let pal = TestPal {
            header_size,
            send_len_alignment,
            ..TestPal::default()
        };
        let (mut state, mut sessions, session_id) = support::handshake_session(&pal);
        let seed = TestIo::message(std::vec::Vec::new());
        block_on(state.transcript.append_vca(&pal, &seed, b"VCA")).unwrap();
        sessions
            .find_mut(session_id)
            .unwrap()
            .transcript
            .init_from_running(&pal, &seed, state.transcript.vca.as_ref().unwrap())
            .unwrap();
        let prefix = [SpdmVersion::V12.to_u8(), ReqRespCode::FINISH.0, 0, 0];
        let mut request = prefix.to_vec();
        request.extend_from_slice(&[0xff; support::SHA384_DIGEST_SIZE]);
        let invalid = secured_io(session_id, &request);
        let response = block_on(handle_secured_request(
            &mut state,
            &mut sessions,
            &pal,
            &invalid,
            &NoVdmBackend,
        ))
        .unwrap()
        .unwrap();
        assert_eq!(
            secured_spdm_response(&response[header_size..])[1],
            ReqRespCode::ERROR.0
        );
        assert_eq!(
            secured_spdm_response(&response[header_size..])[2],
            crate::error::SPDM_DECRYPT_ERROR.spec_byte()
        );
        assert!(sessions.find(session_id).is_none());
        assert!(block_on(handle_secured_request(
            &mut state,
            &mut sessions,
            &pal,
            &invalid,
            &NoVdmBackend,
        ))
        .unwrap()
        .is_none());

        let fresh_id = sessions
            .create_session(0x1234, SpdmVersion::V12, |info| pal.alloc_persistent(info))
            .unwrap();
        assert_ne!(fresh_id, session_id);
        let session = sessions.find_mut(fresh_id).unwrap();
        session
            .transcript
            .init_from_running(&pal, &seed, state.transcript.vca.as_ref().unwrap())
            .unwrap();
        session.key_schedule.set_shared_secret(1);
        block_on(session.key_schedule.generate_handshake_keys(
            &pal,
            &invalid,
            &[0; support::SHA384_DIGEST_SIZE],
        ))
        .unwrap();
        let mut request = prefix.to_vec();
        request.extend_from_slice(&support::test_digest(&prefix));
        let valid = secured_io(fresh_id, &request);
        let response = block_on(handle_secured_request(
            &mut state,
            &mut sessions,
            &pal,
            &valid,
            &NoVdmBackend,
        ))
        .unwrap()
        .unwrap();
        assert_eq!(
            secured_spdm_response(&response[header_size..]),
            [SpdmVersion::V12.to_u8(), ReqRespCode::FINISH_RSP.0, 0, 0]
        );
        assert!(
            sessions.find(fresh_id).unwrap().state == crate::session::SessionState::Established
        );

        let end = secured_io(
            fresh_id,
            &[SpdmVersion::V12.to_u8(), ReqRespCode::END_SESSION.0, 0, 0],
        );
        let response = block_on(handle_secured_request(
            &mut state,
            &mut sessions,
            &pal,
            &end,
            &NoVdmBackend,
        ))
        .unwrap()
        .unwrap();
        assert_eq!(
            secured_spdm_response(&response[header_size..]),
            [
                SpdmVersion::V12.to_u8(),
                ReqRespCode::END_SESSION_ACK.0,
                0,
                0
            ]
        );
        assert!(sessions.find(fresh_id).is_none());
        let transcript_inputs = pal.hash_finishes.borrow().clone();
        assert!(transcript_inputs
            .iter()
            .any(|bytes| bytes.starts_with(b"VCA") && bytes.ends_with(&prefix)));
        if let Some(expected) = &baseline {
            assert_eq!(&transcript_inputs, expected);
        } else {
            baseline = Some(transcript_inputs);
        }
    }
}
