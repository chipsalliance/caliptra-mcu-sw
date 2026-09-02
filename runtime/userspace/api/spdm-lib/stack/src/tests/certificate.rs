// Licensed under the Apache-2.0 license

#![allow(clippy::field_reassign_with_default)]

extern crate std;

use super::*;
use caliptra_mcu_spdm_codec::{
    CapFlags, CertificateLargeRspBody, CertificateRspBody, GetCertificateLargeReqBody,
    GetCertificateParam1, GetCertificateReqBody, ReqRespCode, SpdmMsgHdrPdu, SpdmVersion,
    WireWriter, ATTR_SLOT_SIZE_REQUESTED,
};
use caliptra_mcu_spdm_traits::NoVdmBackend;
use futures::executor::block_on;
use std::vec;
use std::vec::Vec;
use zerocopy::{little_endian::U16, little_endian::U32, FromBytes};

use crate::error::SPDM_LARGE_RESPONSE;

#[path = "support.rs"]
mod support;
use support::{
    drain_chunked_response, negotiated_state, TestHashState, TestIo, TestPal,
    SPDM_CERT_CHAIN_HDR_LEN, TEST_CERT_CHAIN,
};

const STREAMED_CERT_CHAIN: &[u8] = &[0xA5; 2048];

fn init_cert_test_state(
    version: SpdmVersion,
    pal: &TestPal,
) -> ConnectionState<TestHashState, Vec<u8>> {
    let mut state = negotiated_state(version);
    let io = TestIo::message(Vec::new());
    block_on(state.transcript.append_vca(pal, &io, &[0xAA, 0xBB])).unwrap();
    state
}

fn standard_cert_request(
    version: SpdmVersion,
    slot_id: u8,
    attributes: u8,
    offset: u16,
    length: u16,
) -> Vec<u8> {
    let mut buf = vec![0u8; SpdmMsgHdrPdu::SIZE + GetCertificateReqBody::SIZE];
    let mut w = WireWriter::new(&mut buf);
    w.write(&SpdmMsgHdrPdu::new(version, ReqRespCode::GET_CERTIFICATE))
        .unwrap();
    w.write(&GetCertificateReqBody {
        slot_id,
        attributes,
        offset: U16::new(offset),
        length: U16::new(length),
    })
    .unwrap();
    buf
}

fn large_cert_request(
    version: SpdmVersion,
    slot_id: u8,
    attributes: u8,
    large_offset: u32,
    large_length: u32,
) -> Vec<u8> {
    let mut buf = vec![0u8; SpdmMsgHdrPdu::SIZE + GetCertificateLargeReqBody::SIZE];
    let mut w = WireWriter::new(&mut buf);
    w.write(&SpdmMsgHdrPdu::new(version, ReqRespCode::GET_CERTIFICATE))
        .unwrap();
    w.write(&GetCertificateLargeReqBody {
        param1: GetCertificateParam1::new()
            .with_slot_id(slot_id)
            .with_large_cert_chain(true),
        attributes,
        offset: U16::new(0),
        length: U16::new(0),
        large_offset: U32::new(large_offset),
        large_length: U32::new(large_length),
    })
    .unwrap();
    buf
}

fn dispatch_cert_request(
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
        ReqRespCode::GET_CERTIFICATE,
        &NoVdmBackend,
    ))
}

#[test]
fn test_get_certificate_v13_legacy_success() {
    let pal = TestPal::default();
    let mut state = init_cert_test_state(SpdmVersion::V13, &pal);
    let mut sessions = SessionManager::new();

    let total_len = SPDM_CERT_CHAIN_HDR_LEN + TEST_CERT_CHAIN.len();
    let req = standard_cert_request(SpdmVersion::V13, 0, 0, 0, 0xFFFF);
    let rsp = dispatch_cert_request(&mut state, &mut sessions, &pal, req).unwrap();

    let (hdr, rest) = SpdmMsgHdrPdu::ref_from_prefix(&rsp).unwrap();
    assert_eq!(hdr.version, SpdmVersion::V13.to_u8());
    assert_eq!(hdr.code, ReqRespCode::CERTIFICATE);

    let (body, payload) = CertificateRspBody::ref_from_prefix(rest).unwrap();
    let wanted_body = CertificateRspBody {
        slot_id: 0,
        param2: 0,
        portion_length: U16::new(total_len as u16),
        remainder_length: U16::new(0),
    };
    assert_eq!(body, &wanted_body);
    assert_eq!(&payload[SPDM_CERT_CHAIN_HDR_LEN..], TEST_CERT_CHAIN);
    assert_eq!(state.phase, Phase::AfterCertificate);
}

#[test]
fn test_get_certificate_v14_large_success_pagination() {
    let pal = TestPal::default();
    let mut state = init_cert_test_state(SpdmVersion::V14, &pal);
    state.advertised_cap_flags |= CapFlags::LARGE_RESP;
    let mut sessions = SessionManager::new();

    let total_len = SPDM_CERT_CHAIN_HDR_LEN + TEST_CERT_CHAIN.len(); // 52 + 8 = 60

    // Fetch chunk 1: 32 bytes
    let req1 = large_cert_request(SpdmVersion::V14, 0, 0, 0, 32);
    let rsp1 = dispatch_cert_request(&mut state, &mut sessions, &pal, req1).unwrap();

    let (hdr1, rest1) = SpdmMsgHdrPdu::ref_from_prefix(&rsp1).unwrap();
    assert_eq!(hdr1.version, SpdmVersion::V14.to_u8());
    assert_eq!(hdr1.code, ReqRespCode::CERTIFICATE);

    let (body1, payload1) = CertificateLargeRspBody::ref_from_prefix(rest1).unwrap();
    let wanted_body1 = CertificateLargeRspBody {
        param1: GetCertificateParam1::new().with_large_cert_chain(true),
        param2: 0,
        portion_length: U16::new(0),
        remainder_length: U16::new(0),
        large_portion_length: U32::new(32),
        large_remainder_length: U32::new((total_len - 32) as u32),
    };
    assert_eq!(body1, &wanted_body1);
    assert_eq!(payload1.len(), 32);

    // Fetch chunk 2: remainder
    let req2 = large_cert_request(SpdmVersion::V14, 0, 0, 32, 0xFFFFFFFF);
    let rsp2 = dispatch_cert_request(&mut state, &mut sessions, &pal, req2).unwrap();

    let (hdr2, rest2) = SpdmMsgHdrPdu::ref_from_prefix(&rsp2).unwrap();
    assert_eq!(hdr2.version, SpdmVersion::V14.to_u8());
    assert_eq!(hdr2.code, ReqRespCode::CERTIFICATE);

    let (body2, payload2) = CertificateLargeRspBody::ref_from_prefix(rest2).unwrap();
    let wanted_body2 = CertificateLargeRspBody {
        param1: GetCertificateParam1::new().with_large_cert_chain(true),
        param2: 0,
        portion_length: U16::new(0),
        remainder_length: U16::new(0),
        large_portion_length: U32::new((total_len - 32) as u32),
        large_remainder_length: U32::new(0),
    };
    assert_eq!(body2, &wanted_body2);

    // Verify concatenated data matches
    let mut full = Vec::new();
    full.extend_from_slice(payload1);
    full.extend_from_slice(payload2);
    assert_eq!(full.len(), total_len);
    assert_eq!(&full[SPDM_CERT_CHAIN_HDR_LEN..], TEST_CERT_CHAIN);
}

#[test]
fn test_get_certificate_v14_large_size_req() {
    let pal = TestPal::default();
    let mut state = init_cert_test_state(SpdmVersion::V14, &pal);
    state.advertised_cap_flags |= CapFlags::LARGE_RESP;
    let mut sessions = SessionManager::new();

    let total_len = SPDM_CERT_CHAIN_HDR_LEN + TEST_CERT_CHAIN.len();
    let req = large_cert_request(
        SpdmVersion::V14,
        0,
        ATTR_SLOT_SIZE_REQUESTED,
        0xFFFFFFFF,
        0xAA55AA55,
    );
    let rsp = dispatch_cert_request(&mut state, &mut sessions, &pal, req).unwrap();

    let (hdr, rest) = SpdmMsgHdrPdu::ref_from_prefix(&rsp).unwrap();
    assert_eq!(hdr.version, SpdmVersion::V14.to_u8());
    assert_eq!(hdr.code, ReqRespCode::CERTIFICATE);

    let (body, payload) = CertificateLargeRspBody::ref_from_prefix(rest).unwrap();
    let wanted_body = CertificateLargeRspBody {
        param1: GetCertificateParam1::new().with_large_cert_chain(true),
        param2: 0,
        portion_length: U16::new(0),
        remainder_length: U16::new(0),
        large_portion_length: U32::new(0),
        large_remainder_length: U32::new(total_len as u32),
    };
    assert_eq!(body, &wanted_body);
    assert!(payload.is_empty());
}

#[test]
fn test_get_certificate_large_on_v13_returns_invalid_request() {
    let pal = TestPal::default();
    let mut state = init_cert_test_state(SpdmVersion::V13, &pal);
    state.advertised_cap_flags |= CapFlags::LARGE_RESP;
    let mut sessions = SessionManager::new();

    let req = large_cert_request(SpdmVersion::V13, 0, 0, 0, 1024);
    let err = dispatch_cert_request(&mut state, &mut sessions, &pal, req).unwrap_err();
    assert_eq!(err.spec_byte(), SPDM_INVALID_REQUEST.spec_byte());
}

#[test]
fn test_get_certificate_v14_large_invalid_slot_or_offset() {
    let pal = TestPal::default();
    let mut state = init_cert_test_state(SpdmVersion::V14, &pal);
    state.advertised_cap_flags |= CapFlags::LARGE_RESP;
    let mut sessions = SessionManager::new();

    // Invalid slot: 15 (MAX_SLOTS is 8)
    let req_invalid_slot = large_cert_request(SpdmVersion::V14, 15, 0, 0, 1024);
    let err = dispatch_cert_request(&mut state, &mut sessions, &pal, req_invalid_slot).unwrap_err();
    assert_eq!(err.spec_byte(), SPDM_INVALID_REQUEST.spec_byte());

    // Invalid offset: 0xFFFFFFFF > total_len
    let req_invalid_offset = large_cert_request(SpdmVersion::V14, 0, 0, 0xFFFFFFFF, 1024);
    let err =
        dispatch_cert_request(&mut state, &mut sessions, &pal, req_invalid_offset).unwrap_err();
    assert_eq!(err.spec_byte(), SPDM_INVALID_REQUEST.spec_byte());
}

#[test]
fn test_get_certificate_chunked_full_fetch() {
    let pal = TestPal::default();

    let mut state = init_cert_test_state(SpdmVersion::V14, &pal);
    state.cap_flags |= CapFlags::CHUNK | CapFlags::LARGE_RESP;
    state.peer_cap_flags |= CapFlags::CHUNK;
    state.advertised_cap_flags |= CapFlags::CHUNK | CapFlags::LARGE_RESP;
    state.peer_data_transfer_size = 42; // Constrained DataTransferSize to force chunking
    state.peer_max_spdm_msg_size = 1024;
    let mut sessions = SessionManager::new();

    let total_len = SPDM_CERT_CHAIN_HDR_LEN + TEST_CERT_CHAIN.len(); // 60 bytes
    let total_spdm_msg_len = SpdmMsgHdrPdu::SIZE + CertificateLargeRspBody::SIZE + total_len; // 76 bytes

    // Request full large cert
    let req = large_cert_request(SpdmVersion::V14, 0, 0, 0, 0xFFFFFFFF);
    let err_rsp = dispatch_cert_request(&mut state, &mut sessions, &pal, req).unwrap();

    // Expect ERROR(LargeResponse)
    let (err_hdr, err_body) = SpdmMsgHdrPdu::ref_from_prefix(&err_rsp).unwrap();
    assert_eq!(err_hdr.version, SpdmVersion::V14.to_u8());
    assert_eq!(err_hdr.code, ReqRespCode::ERROR);
    assert_eq!(err_body[0], SPDM_LARGE_RESPONSE.spec_byte());
    let handle = err_body[2]; // ErrorData is at byte index 2 of error body (spdm_msg[4])

    // Drain entire chunked response using the helper in support.rs
    let io = TestIo::message(Vec::new());
    let reassembled_payload =
        block_on(drain_chunked_response(&mut state, &pal, &io, handle)).unwrap();

    assert_eq!(reassembled_payload.len(), total_spdm_msg_len);

    // Reassembled message begins with SpdmMsgHdrPdu (version 1.4, CERTIFICATE)
    let (rsp_hdr, rsp_rest) = SpdmMsgHdrPdu::ref_from_prefix(&reassembled_payload).unwrap();
    assert_eq!(rsp_hdr.version, SpdmVersion::V14.to_u8());
    assert_eq!(rsp_hdr.code, ReqRespCode::CERTIFICATE);

    // Large body header
    let (body, payload) = CertificateLargeRspBody::ref_from_prefix(rsp_rest).unwrap();
    let wanted_body = CertificateLargeRspBody {
        param1: GetCertificateParam1::new().with_large_cert_chain(true),
        param2: 0,
        portion_length: U16::new(0),
        remainder_length: U16::new(0),
        large_portion_length: U32::new(total_len as u32),
        large_remainder_length: U32::new(0),
    };
    assert_eq!(body, &wanted_body);

    // Followed by SPDM cert chain header + DER certs
    assert_eq!(&payload[SPDM_CERT_CHAIN_HDR_LEN..], TEST_CERT_CHAIN);
}

#[test]
fn test_get_certificate_chunked_full_fetch_exceeds_local_buffer() {
    let pal = TestPal {
        cert_chain: STREAMED_CERT_CHAIN,
        ..TestPal::default()
    };
    assert!(
        SPDM_CERT_CHAIN_HDR_LEN + STREAMED_CERT_CHAIN.len() > pal.large_buffered_msg_capacity()
    );

    let mut state = init_cert_test_state(SpdmVersion::V14, &pal);
    state.cap_flags |= CapFlags::CHUNK;
    state.peer_cap_flags |= CapFlags::CHUNK;
    state.advertised_cap_flags |= CapFlags::CHUNK;
    state.peer_data_transfer_size = 256;
    state.peer_max_spdm_msg_size = 4096;
    let mut sessions = SessionManager::new();

    let total_len = SPDM_CERT_CHAIN_HDR_LEN + STREAMED_CERT_CHAIN.len();
    let total_spdm_msg_len = SpdmMsgHdrPdu::SIZE + CertificateRspBody::SIZE + total_len;
    let req = standard_cert_request(SpdmVersion::V14, 0, 0, 0, u16::MAX);
    let err_rsp = dispatch_cert_request(&mut state, &mut sessions, &pal, req).unwrap();

    let (_err_hdr, err_body) = SpdmMsgHdrPdu::ref_from_prefix(&err_rsp).unwrap();
    assert_eq!(err_body[0], SPDM_LARGE_RESPONSE.spec_byte());
    let handle = err_body[2];

    let io = TestIo::message(Vec::new());
    let reassembled = block_on(drain_chunked_response(&mut state, &pal, &io, handle)).unwrap();
    assert_eq!(reassembled.len(), total_spdm_msg_len);

    let (rsp_hdr, rsp_rest) = SpdmMsgHdrPdu::ref_from_prefix(&reassembled).unwrap();
    assert_eq!(rsp_hdr.version, SpdmVersion::V14.to_u8());
    assert_eq!(rsp_hdr.code, ReqRespCode::CERTIFICATE);

    let (body, payload) = CertificateRspBody::ref_from_prefix(rsp_rest).unwrap();
    assert_eq!(body.portion_length.get() as usize, total_len);
    assert_eq!(body.remainder_length.get(), 0);
    assert_eq!(&payload[SPDM_CERT_CHAIN_HDR_LEN..], STREAMED_CERT_CHAIN);
}

#[test]
fn test_get_certificate_v14_with_mldsa87_negotiated() {
    let pal = TestPal::default();
    let mut state = init_cert_test_state(SpdmVersion::V14, &pal);
    state.advertised_cap_flags |= CapFlags::LARGE_RESP;
    state.negotiated_pqc_asym_sel = caliptra_mcu_spdm_codec::PqcAsymAlgos::ML_DSA_87;
    assert_eq!(
        state.asym_algo(),
        caliptra_mcu_spdm_traits::SpdmPalAsymAlgo::MlDsa87
    );

    let mut sessions = SessionManager::new();
    let total_len = (SPDM_CERT_CHAIN_HDR_LEN + TEST_CERT_CHAIN.len()) as u32;

    // Query size using large cert request
    let req = large_cert_request(SpdmVersion::V14, 0, ATTR_SLOT_SIZE_REQUESTED, 0, 0);
    let rsp = dispatch_cert_request(&mut state, &mut sessions, &pal, req).unwrap();

    let (_hdr, rest) = SpdmMsgHdrPdu::ref_from_prefix(&rsp).unwrap();
    let (body, payload) = CertificateLargeRspBody::ref_from_prefix(rest).unwrap();
    let wanted_body = CertificateLargeRspBody {
        param1: GetCertificateParam1::new().with_large_cert_chain(true),
        param2: 0,
        portion_length: U16::new(0),
        remainder_length: U16::new(0),
        large_portion_length: U32::new(0),
        large_remainder_length: U32::new(total_len),
    };
    assert_eq!(body, &wanted_body);
    assert!(payload.is_empty());
}
