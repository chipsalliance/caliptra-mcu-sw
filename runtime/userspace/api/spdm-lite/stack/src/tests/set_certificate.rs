// Licensed under the Apache-2.0 license

extern crate std;

use super::*;
use crate::error::{SPDM_BUSY, SPDM_OPERATION_FAILED, SPDM_RESET_REQUIRED, SPDM_UNSPECIFIED};
use futures::executor::block_on;
use mcu_spdm_lite_codec::{errors as wire_errors, OtherParamSupport};
use std::vec::Vec;

#[path = "support.rs"]
mod support;
use support::*;

fn state(version: SpdmVersion) -> ConnectionState<TestHashState, Vec<u8>> {
    negotiated_state(version)
}

fn state_v13_multi_key() -> ConnectionState<TestHashState, Vec<u8>> {
    let mut state = state(SpdmVersion::V13);
    state.other_param_sel = OtherParamSupport::MULTI_KEY_CONN;
    state.peer_cap_flags = CapFlags::MULTI_KEY_CONN_RSP;
    state
}

#[test]
fn test_handle_set_certificate_v12_writes_cert_chain() {
    let pal = TestPal::default();
    let mut state = state(SpdmVersion::V12);
    let der = der_chain();
    let root_hash = test_digest(&der[..5]);
    let payload = cert_payload(&der, root_hash);
    let io = set_certificate_io(SpdmVersion::V12, 1, 0, &payload);

    let rsp = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap();

    assert_eq!(
        &rsp[..],
        &[
            SpdmVersion::V12.to_u8(),
            ReqRespCode::SET_CERTIFICATE_RSP.0,
            1,
            0
        ]
    );
    assert_eq!(
        pal.op.take(),
        Some(StoreOp::Write {
            slot: 1,
            key_pair_id: 0,
            cert_model: CERT_MODEL_ALIAS_CERT,
            root_hash,
            cert_chain: der,
        })
    );
}

#[test]
fn test_handle_set_certificate_v12_uses_device_cert_without_alias_cap() {
    let pal = TestPal::default();
    let mut state = state(SpdmVersion::V12);
    state.advertised_cap_flags =
        CapFlags::CERT | CapFlags::CHAL | CapFlags::MEAS_SIG | CapFlags::SET_CERT;
    let der = der_chain();
    let root_hash = test_digest(&der[..5]);
    let payload = cert_payload(&der, root_hash);
    let io = set_certificate_io(SpdmVersion::V12, 1, 0, &payload);

    block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap();

    assert_eq!(
        pal.op.take(),
        Some(StoreOp::Write {
            slot: 1,
            key_pair_id: 0,
            cert_model: CERT_MODEL_DEVICE_CERT,
            root_hash,
            cert_chain: der,
        })
    );
}

#[test]
fn test_handle_set_certificate_v13_non_multi_key_uses_alias_cert() {
    let pal = TestPal::default();
    let mut state = state(SpdmVersion::V13);
    let der = der_chain();
    let root_hash = test_digest(&der[..5]);
    let payload = cert_payload(&der, root_hash);
    let io = set_certificate_io(SpdmVersion::V13, 2, 0, &payload);

    block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap();

    assert_eq!(
        pal.op.take(),
        Some(StoreOp::Write {
            slot: 2,
            key_pair_id: 0,
            cert_model: CERT_MODEL_ALIAS_CERT,
            root_hash,
            cert_chain: der,
        })
    );
}

#[test]
fn test_handle_set_certificate_v13_rejects_multikey_when_not_advertised() {
    let pal = TestPal::default();
    let mut state = state_v13_multi_key();
    state.advertised_cap_flags = CapFlags::CERT
        | CapFlags::CHAL
        | CapFlags::MEAS_SIG
        | CapFlags::ALIAS_CERT
        | CapFlags::SET_CERT;
    let der = der_chain();
    let root_hash = test_digest(&der[..5]);
    let payload = cert_payload(&der, root_hash);
    let attributes = 2 | (CERT_MODEL_GENERIC_CERT << 4);
    let io = set_certificate_io(SpdmVersion::V13, attributes, 7, &payload);

    let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

    assert_eq!(err, SPDM_INVALID_REQUEST);
    assert_eq!(pal.op.take(), None);
}

#[test]
fn test_handle_set_certificate_v13_multi_key_writes_cert_chain() {
    let pal = TestPal::default();
    let mut state = state_v13_multi_key();
    let der = der_chain();
    let root_hash = test_digest(&der[..5]);
    let payload = cert_payload(&der, root_hash);
    let attributes = 2 | (CERT_MODEL_GENERIC_CERT << 4);
    let io = set_certificate_io(SpdmVersion::V13, attributes, 7, &payload);

    let rsp = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap();

    assert_eq!(
        &rsp[..],
        &[
            SpdmVersion::V13.to_u8(),
            ReqRespCode::SET_CERTIFICATE_RSP.0,
            2,
            0,
        ]
    );
    assert_eq!(
        pal.op.take(),
        Some(StoreOp::Write {
            slot: 2,
            key_pair_id: 7,
            cert_model: CERT_MODEL_GENERIC_CERT,
            root_hash,
            cert_chain: der,
        })
    );
}

#[test]
fn test_handle_set_certificate_v13_multi_key_cap_one_writes_cert_chain() {
    let pal = TestPal::default();
    let mut state = state_v13_multi_key();
    state.advertised_cap_flags = CapFlags::from_bits(
        (state.advertised_cap_flags.into_bits() & !(0b11 << 26)) | (0b01 << 26),
    );
    let der = der_chain();
    let root_hash = test_digest(&der[..5]);
    let payload = cert_payload(&der, root_hash);
    let attributes = 2 | (CERT_MODEL_GENERIC_CERT << 4);
    let io = set_certificate_io(SpdmVersion::V13, attributes, 7, &payload);

    block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap();

    assert_eq!(
        pal.op.take(),
        Some(StoreOp::Write {
            slot: 2,
            key_pair_id: 7,
            cert_model: CERT_MODEL_GENERIC_CERT,
            root_hash,
            cert_chain: der,
        })
    );
}

#[test]
fn test_handle_set_certificate_v13_erase_succeeds() {
    let pal = TestPal::default();
    let mut state = state(SpdmVersion::V13);
    let io = set_certificate_io(SpdmVersion::V13, 3 | (1 << 7), 0, &[]);

    let rsp = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap();

    assert_eq!(
        &rsp[..],
        &[
            SpdmVersion::V13.to_u8(),
            ReqRespCode::SET_CERTIFICATE_RSP.0,
            3,
            0,
        ]
    );
    assert_eq!(pal.op.take(), Some(StoreOp::Erase { slot: 3 }));
}

#[test]
fn test_handle_set_certificate_rejects_unadvertised_capability() {
    let pal = TestPal::default();
    let mut state = state(SpdmVersion::V12);
    state.advertised_cap_flags = CapFlags::from_bits(
        state.advertised_cap_flags.into_bits() & !CapFlags::SET_CERT.into_bits(),
    );
    let der = der_chain();
    let payload = cert_payload(&der, test_digest(&der[..5]));
    let io = set_certificate_io(SpdmVersion::V12, 1, 0, &payload);

    let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

    assert_eq!(err, unsupported_set_certificate());
    assert_eq!(pal.op.take(), None);
}

#[test]
fn test_handle_set_certificate_rejects_request_larger_than_mtu() {
    let der = der_chain();
    let payload = cert_payload(&der, test_digest(&der[..5]));
    let io = set_certificate_io(SpdmVersion::V12, 1, 0, &payload);
    let pal = TestPal {
        mtu: io.request.len() - 1,
        ..TestPal::default()
    };
    let mut state = state(SpdmVersion::V12);

    let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

    assert_eq!(err, SPDM_INVALID_REQUEST);
    assert_eq!(pal.op.take(), None);
}

#[test]
fn test_handle_set_certificate_rejects_unsupported_slot() {
    let pal = TestPal {
        supported_slots: u8::MAX ^ (1u8 << 2),
        ..TestPal::default()
    };
    let mut state = state(SpdmVersion::V12);
    let der = der_chain();
    let payload = cert_payload(&der, test_digest(&der[..5]));
    let io = set_certificate_io(SpdmVersion::V12, 2, 0, &payload);

    let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

    assert_eq!(err, SPDM_INVALID_REQUEST);
    assert_eq!(pal.op.take(), None);
}

#[test]
fn test_handle_set_certificate_rejects_erase_for_unsupported_slot() {
    let pal = TestPal {
        supported_slots: u8::MAX ^ (1u8 << 3),
        ..TestPal::default()
    };
    let mut state = state(SpdmVersion::V13);
    let io = set_certificate_io(SpdmVersion::V13, 3 | (1 << 7), 0, &[]);

    let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

    assert_eq!(err, SPDM_INVALID_REQUEST);
    assert_eq!(pal.op.take(), None);
}

#[test]
fn test_handle_set_certificate_rejects_unnegotiated_hash_algo() {
    let pal = TestPal::default();
    let mut state = state(SpdmVersion::V12);
    state.negotiated_base_hash_sel = HashAlgos::EMPTY;
    let der = der_chain();
    let payload = cert_payload(&der, test_digest(&der[..5]));
    let io = set_certificate_io(SpdmVersion::V12, 1, 0, &payload);

    let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

    assert_eq!(err, SPDM_UNSPECIFIED);
    assert_eq!(pal.op.take(), None);
}

#[test]
fn test_handle_set_certificate_rejects_unnegotiated_base_asym_algo() {
    let pal = TestPal::default();
    let mut state = state(SpdmVersion::V12);
    state.negotiated_base_asym_sel = AsymAlgos::EMPTY;
    let der = der_chain();
    let payload = cert_payload(&der, test_digest(&der[..5]));
    let io = set_certificate_io(SpdmVersion::V12, 1, 0, &payload);

    let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

    assert_eq!(err, SPDM_INVALID_REQUEST);
    assert_eq!(pal.op.take(), None);
}

#[test]
fn test_handle_set_certificate_checks_authorization_before_algorithms() {
    let pal = TestPal {
        authorized: false,
        ..TestPal::default()
    };
    let mut state = state(SpdmVersion::V12);
    state.negotiated_base_hash_sel = HashAlgos::EMPTY;
    let der = der_chain();
    let payload = cert_payload(&der, test_digest(&der[..5]));
    let io = set_certificate_io(SpdmVersion::V12, 1, 0, &payload);

    let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

    assert_eq!(err, SPDM_SESSION_REQUIRED);
    assert_eq!(pal.op.take(), None);
}

#[test]
fn test_reset_negotiation_clears_selected_algorithms() {
    let mut state = state(SpdmVersion::V13);

    state.reset_negotiation();

    assert_eq!(
        state.negotiated_base_hash_sel.into_bits(),
        HashAlgos::EMPTY.into_bits()
    );
    assert_eq!(
        state.negotiated_base_asym_sel.into_bits(),
        AsymAlgos::EMPTY.into_bits()
    );
    assert_eq!(
        state.advertised_cap_flags.into_bits(),
        CapFlags::EMPTY.into_bits()
    );
}

#[test]
fn test_handle_set_certificate_rejects_unauthorized_request() {
    let pal = TestPal {
        authorized: false,
        ..TestPal::default()
    };
    let mut state = state(SpdmVersion::V12);
    let der = der_chain();
    let payload = cert_payload(&der, test_digest(&der[..5]));
    let io = set_certificate_io(SpdmVersion::V12, 1, 0, &payload);

    let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

    assert_eq!(err, SPDM_SESSION_REQUIRED);
    assert_eq!(pal.op.take(), None);
}

#[test]
fn test_handle_set_certificate_passes_root_hash_through_without_recomputing() {
    let pal = TestPal::default();
    let mut state = state(SpdmVersion::V12);
    let der = der_chain();
    let root_hash = [0xa5; support::SHA384_DIGEST_SIZE];
    let payload = cert_payload(&der, root_hash);
    let io = set_certificate_io(SpdmVersion::V12, 1, 0, &payload);

    block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap();

    assert_eq!(
        pal.op.take(),
        Some(StoreOp::Write {
            slot: 1,
            key_pair_id: 0,
            cert_model: CERT_MODEL_ALIAS_CERT,
            root_hash,
            cert_chain: der,
        })
    );
}

#[test]
fn test_validate_der_chain_rejects_trailing_garbage() {
    assert!(validate_der_chain(&[0x30, 0x01, 0x00, 0xff]).is_err());
}

#[test]
fn test_handle_set_certificate_calls_pal_validation_before_write() {
    let pal = TestPal {
        validate_error: Some(mcu_error::codes::INVARIANT),
        ..TestPal::default()
    };
    let mut state = state(SpdmVersion::V12);
    let der = der_chain();
    let payload = cert_payload(&der, test_digest(&der[..5]));
    let io = set_certificate_io(SpdmVersion::V12, 1, 0, &payload);

    let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

    assert_eq!(err, SPDM_INVALID_REQUEST);
    assert_eq!(pal.op.take(), None);
}

#[test]
fn test_handle_set_certificate_preserves_wire_validation_error() {
    let pal = TestPal {
        validate_error: Some(wire_errors::SPDM_OPERATION_FAILED),
        ..TestPal::default()
    };
    let mut state = state(SpdmVersion::V12);
    let der = der_chain();
    let payload = cert_payload(&der, test_digest(&der[..5]));
    let io = set_certificate_io(SpdmVersion::V12, 1, 0, &payload);

    let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

    assert_eq!(err, SPDM_OPERATION_FAILED);
    assert_eq!(pal.op.take(), None);
}

#[test]
fn test_handle_set_certificate_preserves_wire_write_error() {
    let pal = TestPal {
        write_error: Some(wire_errors::SPDM_BUSY),
        ..TestPal::default()
    };
    let mut state = state(SpdmVersion::V12);
    let der = der_chain();
    let payload = cert_payload(&der, test_digest(&der[..5]));
    let io = set_certificate_io(SpdmVersion::V12, 1, 0, &payload);

    let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

    assert_eq!(err, SPDM_BUSY);
    assert_eq!(pal.op.take(), None);
}

#[test]
fn test_handle_set_certificate_preserves_wire_erase_error() {
    let pal = TestPal {
        erase_error: Some(wire_errors::SPDM_RESET_REQUIRED),
        ..TestPal::default()
    };
    let mut state = state(SpdmVersion::V13);
    let io = set_certificate_io(SpdmVersion::V13, 3 | (1 << 7), 0, &[]);

    let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

    assert_eq!(err, SPDM_RESET_REQUIRED);
    assert_eq!(pal.op.take(), None);
}
