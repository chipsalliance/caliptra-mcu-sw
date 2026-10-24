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
    let pal = TestPal::default();
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
    assert_eq!(secured_spdm_response(&response)[1], ReqRespCode::DIGESTS.0);
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
        secured_spdm_response(&replay_response)[1],
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
    let pal = TestPal::default();
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
        secured_spdm_response(&error_response)[1],
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
        secured_spdm_response(&response),
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
