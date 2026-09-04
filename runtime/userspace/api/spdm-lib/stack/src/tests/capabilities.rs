// Licensed under the Apache-2.0 license

//! Unit tests for the GET_CAPABILITIES handler's version-based capability
//! gating.

extern crate std;

use super::*;
use caliptra_mcu_spdm_codec::{CapFlags, ReqRespCode, SpdmMsgHdrPdu, SpdmVersion};
use futures::executor::block_on;
use std::vec;
use std::vec::Vec;

#[path = "support.rs"]
mod support;
use support::*;

/// A state ready to receive GET_CAPABILITIES (phase `AfterVersion`) whose
/// `cap_flags` advertise the full V1.2+/V1.3 capability set, including the
/// set-certificate group (SET_CERT/MULTI_KEY_CONN_RSP/GET_KEY_PAIR_INFO)
/// when that feature is built.
fn after_version_state(version: SpdmVersion) -> ConnectionState<TestHashState, Vec<u8>> {
    let mut state = negotiated_state(version);
    state.phase = Phase::AfterVersion;
    // Advertise everything the responder can; the handler must mask down per
    // negotiated version. Mirror the flags SpdmContext::caliptra() would build.
    state.cap_flags = CapFlags::CERT
        | CapFlags::CHAL
        | CapFlags::MEAS_SIG
        | CapFlags::ALIAS_CERT
        | CapFlags::KEY_EX
        | CapFlags::ENCRYPT
        | CapFlags::MAC
        | CapFlags::CHUNK
        | CapFlags::HBEAT
        | CapFlags::ENCAP
        | CapFlags::SET_CERT
        | CapFlags::MULTI_KEY_CONN_RSP
        | CapFlags::GET_KEY_PAIR_INFO;
    state
}

/// 10-byte V1.0/1.1 GET_CAPABILITIES request: header + the V1.1 body
/// (Param1|Param2|Reserved|CTExponent|Reserved2(2)|Flags(4)).
fn get_capabilities_io_v11(peer_flags: CapFlags) -> TestIo {
    let mut request = vec![
        SpdmVersion::V11.to_u8(),
        SpdmMsgHdrPdu::new(SpdmVersion::V11, ReqRespCode::GET_CAPABILITIES)
            .code
            .0,
    ];
    request.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // Param1/2, Reserved, CTExp, Reserved2
    request.extend_from_slice(&peer_flags.into_bits().to_le_bytes());
    TestIo::message(request)
}

// A V1.1 CAPABILITIES response must not advertise any V1.2+
// (CHUNK/ENCAP/SET_CERT/ALIAS_CERT) or V1.3 (MULTI_KEY_CONN_RSP,
// GET_KEY_PAIR_INFO) capability.
#[test]
fn v11_capabilities_masks_off_all_v12plus_and_v13_caps() {
    let pal = TestPal::default();
    let mut state = after_version_state(SpdmVersion::V11);
    let io = get_capabilities_io_v11(CapFlags::EMPTY);

    block_on(handle_get_capabilities(&mut state, &pal, &io)).unwrap();

    let v12plus = CapFlags::CHUNK | CapFlags::ENCAP | CapFlags::SET_CERT | CapFlags::ALIAS_CERT;
    let v13 = CapFlags::from_bits((0b11 << 26) | CapFlags::GET_KEY_PAIR_INFO.into_bits());
    let leaked = state.advertised_cap_flags.into_bits() & (v12plus.into_bits() | v13.into_bits());
    assert_eq!(
        leaked, 0,
        "V1.1 response leaked 1.2+/1.3 caps: {:#x}",
        leaked
    );

    // Base V1.1 caps still advertised.
    assert!(state.advertised_cap_flags.contains(CapFlags::CERT));
    assert!(state.advertised_cap_flags.contains(CapFlags::CHAL));
}

// A V1.2 peer must still be denied the V1.3-only capabilities
// (MULTI_KEY_CONN_RSP, GET_KEY_PAIR_INFO) but keep the V1.2 ones.
#[test]
fn v12_capabilities_masks_off_v13_caps_only() {
    let pal = TestPal::default();
    let mut state = after_version_state(SpdmVersion::V12);
    // 18-byte V1.2 request body: header + full CapabilitiesBody.
    let mut request = vec![SpdmVersion::V12.to_u8(), ReqRespCode::GET_CAPABILITIES.0];
    request.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // Param1/2, Reserved, CTExp, Reserved2
    request.extend_from_slice(&CapFlags::EMPTY.into_bits().to_le_bytes());
    request.extend_from_slice(&4096u32.to_le_bytes()); // DataTransferSize
    request.extend_from_slice(&4096u32.to_le_bytes()); // MaxSPDMmsgSize
    let io = TestIo::message(request);

    block_on(handle_get_capabilities(&mut state, &pal, &io)).unwrap();

    let v13 = CapFlags::from_bits((0b11 << 26) | CapFlags::GET_KEY_PAIR_INFO.into_bits());
    let leaked = state.advertised_cap_flags.into_bits() & v13.into_bits();
    assert_eq!(leaked, 0, "V1.2 response leaked V1.3 caps: {:#x}", leaked);
    // V1.2 caps are retained at V1.2.
    assert!(state.advertised_cap_flags.contains(CapFlags::SET_CERT));
    assert!(state.advertised_cap_flags.contains(CapFlags::CHUNK));
}
