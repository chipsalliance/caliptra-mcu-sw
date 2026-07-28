// Licensed under the Apache-2.0 license

extern crate std;

use super::*;
use caliptra_mcu_spdm_codec::{CapFlags, ReqRespCode, SpdmVersion};
use caliptra_mcu_spdm_traits::{NoVdmBackend, SpdmPalAlloc};
use futures::executor::block_on;
use std::vec;
use std::vec::Vec;

#[path = "support.rs"]
mod support;
use support::{TestHashState, TestIo, TestPal};

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
