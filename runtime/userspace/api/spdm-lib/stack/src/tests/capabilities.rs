// Licensed under the Apache-2.0 license

#![allow(clippy::field_reassign_with_default)]

extern crate std;

use super::*;
use caliptra_mcu_spdm_codec::{CapFlags, ReqRespCode, SpdmVersion};
use caliptra_mcu_spdm_traits::NoVdmBackend;
use futures::executor::block_on;
use std::vec;
use std::vec::Vec;

#[path = "support.rs"]
mod support;
use support::{TestHashState, TestIo, TestPal};

fn capabilities_request(
    version: SpdmVersion,
    param1: u8,
    ext_flags: u16,
    flags: CapFlags,
    data_transfer_size: u32,
    max_spdm_msg_size: u32,
) -> Vec<u8> {
    let mut req = vec![
        version.to_u8(),
        ReqRespCode::GET_CAPABILITIES.0,
        param1,
        0,
        0,
        0,
    ];
    req.extend_from_slice(&ext_flags.to_le_bytes());
    req.extend_from_slice(&flags.into_bits().to_le_bytes());
    req.extend_from_slice(&data_transfer_size.to_le_bytes());
    req.extend_from_slice(&max_spdm_msg_size.to_le_bytes());
    req
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
        ReqRespCode::GET_CAPABILITIES,
        &NoVdmBackend,
    ))
}

#[test]
fn get_capabilities_negotiates_v14_and_encodes_ext_flags() {
    let pal = TestPal::default();
    let mut state = ConnectionState::default();
    state.phase = Phase::AfterVersion;
    let mut sessions = SessionManager::new();
    let peer_flags = CapFlags::CERT
        | CapFlags::KEY_EX
        | CapFlags::ENCRYPT
        | CapFlags::MAC
        | CapFlags::CHUNK
        | CapFlags::LARGE_RESP;

    let rsp = dispatch_request(
        &mut state,
        &mut sessions,
        &pal,
        capabilities_request(SpdmVersion::V14, 0, 0, peer_flags, 1024, 4096),
    )
    .unwrap();

    assert_eq!(rsp.len(), 20);
    assert_eq!(rsp[0], SpdmVersion::V14.to_u8());
    assert_eq!(rsp[1], ReqRespCode::CAPABILITIES.0);
    assert_eq!(&rsp[6..8], &[0, 0]);
    assert_eq!(
        u32::from_le_bytes(rsp[8..12].try_into().unwrap()),
        state.advertised_cap_flags.into_bits()
    );
    assert_eq!(state.version, SpdmVersion::V14);
    assert_eq!(state.phase, Phase::AfterCapabilities);
    assert_eq!(state.peer_cap_flags.into_bits(), peer_flags.into_bits());
    assert_eq!(state.peer_data_transfer_size, 1024);
    assert_eq!(state.peer_max_spdm_msg_size, 4096);
}

#[test]
fn get_capabilities_masks_flags_added_after_v12() {
    let pal = TestPal::default();
    let mut state = ConnectionState::default();
    state.phase = Phase::AfterVersion;
    state.cap_flags |= CapFlags::GET_KEY_PAIR_INFO | CapFlags::LARGE_RESP;
    let mut sessions = SessionManager::new();
    let peer_flags =
        CapFlags::CERT | CapFlags::KEY_EX | CapFlags::ENCRYPT | CapFlags::MAC | CapFlags::CHUNK;

    let rsp = dispatch_request(
        &mut state,
        &mut sessions,
        &pal,
        capabilities_request(SpdmVersion::V12, 0, 0, peer_flags, 1024, 1024),
    )
    .unwrap();
    let advertised = CapFlags::from_bits(u32::from_le_bytes(rsp[8..12].try_into().unwrap()));

    assert!(!advertised.contains(CapFlags::GET_KEY_PAIR_INFO));
    assert!(!advertised.contains(CapFlags::LARGE_RESP));
}

#[test]
fn v14_capabilities_ignores_reserved_extended_flags() {
    let pal = TestPal::default();
    let mut state = ConnectionState::default();
    state.phase = Phase::AfterVersion;
    let mut sessions = SessionManager::new();
    let peer_flags = CapFlags::CERT | CapFlags::KEY_EX | CapFlags::CHUNK;

    dispatch_request(
        &mut state,
        &mut sessions,
        &pal,
        capabilities_request(SpdmVersion::V14, 0, u16::MAX, peer_flags, 1024, 1024),
    )
    .unwrap();

    assert_eq!(state.phase, Phase::AfterCapabilities);
    assert_eq!(state.version, SpdmVersion::V14);
}

#[test]
fn v14_capabilities_accepts_supported_algorithms_request_with_chunking() {
    let pal = TestPal::default();
    let mut state = ConnectionState::default();
    state.phase = Phase::AfterVersion;
    let mut sessions = SessionManager::new();
    let peer_flags =
        CapFlags::CERT | CapFlags::KEY_EX | CapFlags::ENCRYPT | CapFlags::MAC | CapFlags::CHUNK;

    let rsp = dispatch_request(
        &mut state,
        &mut sessions,
        &pal,
        capabilities_request(SpdmVersion::V14, 1, 0, peer_flags, 1024, 1024),
    )
    .unwrap();

    // The request is valid, but this responder does not implement the
    // optional Supported Algorithms block and therefore clears Param1.
    assert_eq!(rsp[2], 0);
    assert_eq!(state.phase, Phase::AfterCapabilities);
}

#[test]
fn v14_supported_algorithms_request_requires_requester_chunking() {
    let pal = TestPal::default();
    let mut state = ConnectionState::default();
    state.phase = Phase::AfterVersion;
    let mut sessions = SessionManager::new();
    let peer_flags = CapFlags::CERT | CapFlags::KEY_EX;

    let err = dispatch_request(
        &mut state,
        &mut sessions,
        &pal,
        capabilities_request(SpdmVersion::V14, 1, 0, peer_flags, 1024, 1024),
    )
    .unwrap_err();

    assert_eq!(err.spec_byte(), SPDM_INVALID_REQUEST.spec_byte());
    assert_eq!(state.phase, Phase::AfterVersion);
    assert_eq!(state.version, SpdmVersion::V12);
}

#[test]
fn v13_capabilities_masks_v14_responder_flags() {
    let pal = TestPal::default();
    let mut state = ConnectionState::default();
    state.phase = Phase::AfterVersion;
    state.cap_flags |= CapFlags::SET_KEY_PAIR_RESET | CapFlags::LARGE_RESP;
    let mut sessions = SessionManager::new();
    let peer_flags =
        CapFlags::CERT | CapFlags::KEY_EX | CapFlags::ENCRYPT | CapFlags::MAC | CapFlags::CHUNK;

    let rsp = dispatch_request(
        &mut state,
        &mut sessions,
        &pal,
        capabilities_request(SpdmVersion::V13, 0, 0, peer_flags, 1024, 1024),
    )
    .unwrap();
    let advertised = CapFlags::from_bits(u32::from_le_bytes(rsp[8..12].try_into().unwrap()));

    assert!(!advertised.contains(CapFlags::SET_KEY_PAIR_RESET));
    assert!(!advertised.contains(CapFlags::LARGE_RESP));
}
