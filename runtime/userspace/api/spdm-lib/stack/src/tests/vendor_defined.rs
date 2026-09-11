// Licensed under the Apache-2.0 license

#![allow(clippy::field_reassign_with_default)]

extern crate std;

use std::vec;
use std::vec::Vec;

use futures::executor::block_on;
use zerocopy::{little_endian::U16, little_endian::U32, FromBytes};

use super::*;
use caliptra_mcu_spdm_codec::{
    CapFlags, ReqRespCode, SpdmMsgHdrPdu, SpdmVersion, VendorDefinedParam1, VendorDefinedReqPdu,
    VendorDefinedRspPdu, WireWriter,
};
use caliptra_mcu_spdm_traits::{
    SpdmPalAlloc, SpdmPalIo, SpdmVdmBackend, VdmRegistry, VdmResponse, VdmResponseBuffer,
};
use mcu_error::McuResult;

use crate::error::{SPDM_DATA_TOO_LARGE, SPDM_INVALID_REQUEST, SPDM_LARGE_RESPONSE};

#[path = "support.rs"]
mod support;
use support::{drain_chunked_response, negotiated_state, TestHashState, TestIo, TestPal};

const TEST_STANDARD_ID: u16 = 0x0004; // IANA
const TEST_VENDOR_ID: [u8; 4] = [0x01, 0x02, 0x03, 0x04];

struct TestVdmBackend {
    payload: Vec<u8>,
    force_large: bool,
}

impl SpdmVdmBackend for TestVdmBackend {
    const USES_LARGE_RESPONSE: bool = true;

    fn match_id(&self, registry: &VdmRegistry<'_>) -> bool {
        registry.standard_id == TEST_STANDARD_ID && registry.vendor_id == TEST_VENDOR_ID
    }

    fn large_response_capacity(&self, _req: &[u8]) -> usize {
        self.payload.len()
    }

    async fn handle_request<Alloc, Io>(
        &self,
        _req: &[u8],
        rsp: VdmResponseBuffer<'_, Alloc, Io>,
    ) -> McuResult<VdmResponse>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo,
    {
        if self.force_large || self.payload.len() > rsp.inline.len() {
            rsp.large[..self.payload.len()].copy_from_slice(&self.payload);
            Ok(VdmResponse::Large(self.payload.len()))
        } else {
            rsp.inline[..self.payload.len()].copy_from_slice(&self.payload);
            Ok(VdmResponse::Inline(self.payload.len()))
        }
    }
}

fn init_vdm_test_state(
    version: SpdmVersion,
    pal: &TestPal,
) -> ConnectionState<TestHashState, Vec<u8>> {
    let mut state = negotiated_state(version);
    let io = TestIo::message(Vec::new());
    block_on(state.transcript.append_vca(pal, &io, &[0xAA, 0xBB])).unwrap();
    state
}

fn vdm_request(version: SpdmVersion, is_large: bool, payload: &[u8]) -> Vec<u8> {
    let extra_hdr = if is_large { 6 } else { 2 };
    let mut buf =
        vec![0u8; SpdmMsgHdrPdu::SIZE + 5 + TEST_VENDOR_ID.len() + extra_hdr + payload.len()];
    let mut w = WireWriter::new(&mut buf);
    w.write(&SpdmMsgHdrPdu::new(
        version,
        ReqRespCode::VENDOR_DEFINED_REQUEST,
    ))
    .unwrap();
    w.write(&VendorDefinedReqPdu {
        param1: VendorDefinedParam1::new().with_large(is_large),
        param2: 0,
        standard_id: U16::new(TEST_STANDARD_ID),
        vendor_id_len: TEST_VENDOR_ID.len() as u8,
    })
    .unwrap();
    w.write_bytes(&TEST_VENDOR_ID).unwrap();
    if is_large {
        w.write(&[0u8, 0u8]).unwrap();
        w.write(&U32::new(payload.len() as u32)).unwrap();
    } else {
        w.write(&U16::new(payload.len() as u16)).unwrap();
    }
    w.write_bytes(payload).unwrap();
    buf
}

fn dispatch_vdm_request<V: SpdmVdmBackend>(
    vdm: &V,
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
        ReqRespCode::VENDOR_DEFINED_REQUEST,
        vdm,
    ))
}

#[test]
fn test_vdm_v14_large_request_success() {
    let pal = TestPal::default();
    let mut state = init_vdm_test_state(SpdmVersion::V14, &pal);
    state.advertised_cap_flags |= CapFlags::LARGE_RESP;
    let mut sessions = SessionManager::new();

    let rsp_payload = vec![0x11, 0x22, 0x33, 0x44, 0x55];
    let vdm = TestVdmBackend {
        payload: rsp_payload.clone(),
        force_large: false,
    };

    let req = vdm_request(SpdmVersion::V14, true, &[0x01, 0x02, 0x03]);
    let rsp = dispatch_vdm_request(&vdm, &mut state, &mut sessions, &pal, req).unwrap();

    let (hdr, rest) = SpdmMsgHdrPdu::ref_from_prefix(&rsp).unwrap();
    assert_eq!(hdr.version, SpdmVersion::V14.to_u8());
    assert_eq!(hdr.code, ReqRespCode::VENDOR_DEFINED_RESPONSE);

    let (vdm_rsp_hdr, rest2) = VendorDefinedRspPdu::ref_from_prefix(rest).unwrap();
    assert_eq!(
        vdm_rsp_hdr.param1.into_bits(),
        VendorDefinedParam1::LARGE_RESP
    );
    assert_eq!(vdm_rsp_hdr.standard_id.get(), TEST_STANDARD_ID);
    assert_eq!(vdm_rsp_hdr.vendor_id_len, 4);
    assert_eq!(&rest2[..4], &TEST_VENDOR_ID);
    assert_eq!(&rest2[4..6], &[0, 0]); // reserved
    assert_eq!(&rest2[6..10], &(rsp_payload.len() as u32).to_le_bytes());
    assert_eq!(&rest2[10..], &rsp_payload[..]);
}

#[test]
fn test_vdm_large_negotiation_gates() {
    let pal = TestPal::default();
    let vdm = TestVdmBackend {
        payload: vec![0x00],
        force_large: false,
    };
    let req = vdm_request(SpdmVersion::V14, true, &[0xAA]);

    // 1. Version < 1.4 (V13) with LARGE_RESP advertised
    let mut state = init_vdm_test_state(SpdmVersion::V13, &pal);
    state.advertised_cap_flags |= CapFlags::LARGE_RESP;
    let mut sessions = SessionManager::new();
    let err = dispatch_vdm_request(
        &vdm,
        &mut state,
        &mut sessions,
        &pal,
        vdm_request(SpdmVersion::V13, true, &[0xAA]),
    )
    .unwrap_err();
    assert_eq!(err.spec_byte(), SPDM_INVALID_REQUEST.spec_byte());

    // 2. SPDM 1.4 but responder does NOT advertise LARGE_RESP
    let mut state = init_vdm_test_state(SpdmVersion::V14, &pal);
    state.advertised_cap_flags = CapFlags::from_bits(
        state.advertised_cap_flags.into_bits() & !CapFlags::LARGE_RESP.into_bits(),
    );
    let mut sessions = SessionManager::new();
    let err = dispatch_vdm_request(&vdm, &mut state, &mut sessions, &pal, req).unwrap_err();
    assert_eq!(err.spec_byte(), SPDM_INVALID_REQUEST.spec_byte());
}

#[test]
fn test_vdm_standard_overflow_returns_data_too_large() {
    let overflow_size = 65536 + 10;
    let pal = TestPal {
        large_buffered_msg_capacity: overflow_size + 1024,
        ..TestPal::default()
    };
    let mut state = init_vdm_test_state(SpdmVersion::V14, &pal);
    state.cap_flags |= CapFlags::CHUNK | CapFlags::LARGE_RESP;
    state.peer_cap_flags |= CapFlags::CHUNK | CapFlags::LARGE_RESP;
    state.advertised_cap_flags |= CapFlags::CHUNK | CapFlags::LARGE_RESP;
    state.peer_max_spdm_msg_size = (overflow_size + 1024) as u32;
    let mut sessions = SessionManager::new();

    let vdm = TestVdmBackend {
        payload: vec![0xA5; overflow_size],
        force_large: true,
    };

    // Standard request (LargeReq = false)
    let req = vdm_request(SpdmVersion::V14, false, &[0xAA]);
    let err = dispatch_vdm_request(&vdm, &mut state, &mut sessions, &pal, req).unwrap_err();
    assert_eq!(err.spec_byte(), SPDM_DATA_TOO_LARGE.spec_byte());
    assert_eq!(err.extended_data(), (overflow_size as u32).to_le_bytes());
}

#[test]
fn test_vdm_large_response_chunked_transfer() {
    let payload_len = 500;
    let pal = TestPal {
        large_buffered_msg_capacity: 4096,
        ..TestPal::default()
    };
    let mut state = init_vdm_test_state(SpdmVersion::V14, &pal);
    state.cap_flags |= CapFlags::CHUNK | CapFlags::LARGE_RESP;
    state.peer_cap_flags |= CapFlags::CHUNK;
    state.advertised_cap_flags |= CapFlags::CHUNK | CapFlags::LARGE_RESP;
    state.peer_data_transfer_size = 64; // Small DTS forces chunking
    state.peer_max_spdm_msg_size = 4096;
    let mut sessions = SessionManager::new();

    let rsp_payload = vec![0x42; payload_len];
    let vdm = TestVdmBackend {
        payload: rsp_payload.clone(),
        force_large: true,
    };

    let req = vdm_request(SpdmVersion::V14, true, &[0xAA]);
    let err_rsp = dispatch_vdm_request(&vdm, &mut state, &mut sessions, &pal, req).unwrap();

    let (err_hdr, err_body) = SpdmMsgHdrPdu::ref_from_prefix(&err_rsp).unwrap();
    assert_eq!(err_hdr.code, ReqRespCode::ERROR);
    assert_eq!(err_body[0], SPDM_LARGE_RESPONSE.spec_byte());
    let handle = err_body[2];

    let io = TestIo::message(Vec::new());
    let reassembled = block_on(drain_chunked_response(&mut state, &pal, &io, handle)).unwrap();

    // Large envelope = 2 (SPDM hdr) + 11 (VdmPdu + rsvd + u32 len) + 4 (vendor_id) = 17
    assert_eq!(reassembled.len(), 17 + payload_len);
    let (rsp_hdr, rsp_rest) = SpdmMsgHdrPdu::ref_from_prefix(&reassembled).unwrap();
    assert_eq!(rsp_hdr.code, ReqRespCode::VENDOR_DEFINED_RESPONSE);

    let (vdm_rsp_hdr, rest2) = VendorDefinedRspPdu::ref_from_prefix(rsp_rest).unwrap();
    assert_eq!(
        vdm_rsp_hdr.param1.into_bits(),
        VendorDefinedParam1::LARGE_RESP
    );
    assert_eq!(&rest2[..4], &TEST_VENDOR_ID);
    assert_eq!(&rest2[4..6], &[0, 0]); // reserved
    assert_eq!(&rest2[6..10], &(payload_len as u32).to_le_bytes());
    assert_eq!(&rest2[10..], &rsp_payload[..]);
}
