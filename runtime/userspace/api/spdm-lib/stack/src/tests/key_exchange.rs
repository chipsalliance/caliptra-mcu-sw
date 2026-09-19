// Licensed under the Apache-2.0 license

extern crate std;

use super::*;
use crate::stack::ConnectionState;
use caliptra_mcu_spdm_codec::{
    ReqRespCode, SpdmVersion, ECDH_P384_EXCHANGE_DATA_SIZE, KEY_EXCHANGE_RANDOM_DATA_LEN,
    OPAQUE_VERSION_SELECTION_SIZE,
};
use futures::executor::block_on;
use std::vec::Vec;

#[path = "support.rs"]
mod support;
use support::*;

// Offset of OpaqueDataLength in KEY_EXCHANGE_RSP, for meas_summary_hash_type = 0
// and a transport header size of 0 (TestPal): header(2) + heartbeat(1)
// + reserved(1) + rsp_session_id(2) + mut_auth(1) + req_slot_id_param(1)
// + random(32) + exchange_data(96).
const RSP_OPAQUE_LEN_OFFSET: usize =
    2 + 1 + 1 + 2 + 1 + 1 + KEY_EXCHANGE_RANDOM_DATA_LEN + ECDH_P384_EXCHANGE_DATA_SIZE;

fn key_exchange_request(version: SpdmVersion, opaque: &[u8]) -> Vec<u8> {
    let mut req = std::vec![
        version.to_u8(),
        ReqRespCode::KEY_EXCHANGE.0,
        0, // meas_summary_hash_type = none
        0, // slot_id = 0
    ];
    req.extend_from_slice(&0x1234u16.to_le_bytes()); // req_session_id
    req.extend_from_slice(&[0, 0]); // session_policy, reserved
    req.extend_from_slice(&[0xAA; KEY_EXCHANGE_RANDOM_DATA_LEN]);
    req.extend_from_slice(&[0xBB; ECDH_P384_EXCHANGE_DATA_SIZE]);
    req.extend_from_slice(&(opaque.len() as u16).to_le_bytes());
    req.extend_from_slice(opaque);
    req
}

fn ready_state_and_sessions(
    version: SpdmVersion,
) -> (
    ConnectionState<TestHashState, Vec<u8>>,
    TestPal,
    Sessions<TestPal, 1>,
) {
    let pal = TestPal {
        provisioned_slots: 0x01,
        ..Default::default()
    };
    let mut state = negotiated_state(version);
    let empty_io = TestIo::message(Vec::new());
    // KEY_EXCHANGE forks the running VCA hash, so it must exist.
    block_on(state.transcript.append_vca(&pal, &empty_io, b"vca-seed")).unwrap();
    let sessions: Sessions<TestPal, 1> = crate::session::SessionManager::new();
    (state, pal, sessions)
}

#[test]
fn key_exchange_empty_opaque_is_accepted_and_response_has_no_opaque() {
    let (mut state, pal, mut sessions) = ready_state_and_sessions(SpdmVersion::V11);
    let io = TestIo::message(key_exchange_request(SpdmVersion::V11, &[]));

    let rsp = block_on(handle_key_exchange(&mut state, &mut sessions, &pal, &io)).unwrap();

    assert_eq!(rsp[0], SpdmVersion::V11.to_u8());
    assert_eq!(rsp[1], ReqRespCode::KEY_EXCHANGE_RSP.0);
    let opaque_len =
        u16::from_le_bytes([rsp[RSP_OPAQUE_LEN_OFFSET], rsp[RSP_OPAQUE_LEN_OFFSET + 1]]);
    assert_eq!(opaque_len, 0, "response must carry no OpaqueData");
}

#[test]
fn key_exchange_with_secured_version_list_still_selects_and_returns_opaque() {
    let opaque: [u8; 16] = [
        0x01, 0x00, 0x00, 0x00, // total_elements = 1, reserved
        0x00, 0x00, // DMTF standards body, vendor_id_len = 0
        0x05, 0x00, // element data_len = 5
        0x01, 0x01, // sm_data_version = 1, sm_data_id = supported version list
        0x01, // version_count = 1
        0x00, 0x11, // SM version 1.1
        0x00, 0x00, 0x00, // pad to a 4-byte boundary
    ];
    let (mut state, pal, mut sessions) = ready_state_and_sessions(SpdmVersion::V11);
    let io = TestIo::message(key_exchange_request(SpdmVersion::V11, &opaque));

    let rsp = block_on(handle_key_exchange(&mut state, &mut sessions, &pal, &io)).unwrap();

    let opaque_len =
        u16::from_le_bytes([rsp[RSP_OPAQUE_LEN_OFFSET], rsp[RSP_OPAQUE_LEN_OFFSET + 1]]);
    assert_eq!(
        opaque_len as usize, OPAQUE_VERSION_SELECTION_SIZE,
        "response must echo the selected secured-message version"
    );
}
