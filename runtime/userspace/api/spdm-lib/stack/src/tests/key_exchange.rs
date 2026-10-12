// Licensed under the Apache-2.0 license

extern crate std;

use super::*;
use caliptra_mcu_spdm_codec::{
    KeyExchangeReqBodyFixed, ReqRespCode, SpdmVersion, ECDH_P384_EXCHANGE_DATA_SIZE,
    KEY_EXCHANGE_RSP_FIXED_BODY_SIZE,
};
use futures::executor::block_on;
use std::vec::Vec;
use zerocopy::IntoBytes;

#[path = "support.rs"]
mod support;
use support::{negotiated_state, TestIo, TestPal};

fn key_exchange_request(opaque_data: &[u8]) -> Vec<u8> {
    let fixed = KeyExchangeReqBodyFixed {
        meas_summary_hash_type: 0,
        slot_id: 0,
        req_session_id: 0x1234u16.to_le_bytes(),
        session_policy: 0,
        _reserved: 0,
        random_data: [0x5a; KEY_EXCHANGE_RANDOM_DATA_LEN],
    };
    let mut request = std::vec![SpdmVersion::V14.to_u8(), ReqRespCode::KEY_EXCHANGE.0];
    request.extend_from_slice(fixed.as_bytes());
    request.extend_from_slice(&[0x3c; ECDH_P384_EXCHANGE_DATA_SIZE]);
    request.extend_from_slice(&(opaque_data.len() as u16).to_le_bytes());
    request.extend_from_slice(opaque_data);
    request
}

fn run_key_exchange(opaque_data: &[u8]) -> Vec<u8> {
    let pal = TestPal::default();
    let io = TestIo::message(key_exchange_request(opaque_data));
    let mut state = negotiated_state(SpdmVersion::V14);
    state.negotiated_key_ex_sel = KeyExSel::Dhe;
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
