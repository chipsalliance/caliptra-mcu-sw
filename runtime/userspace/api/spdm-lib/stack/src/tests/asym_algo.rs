// Licensed under the Apache-2.0 license

use alloc::vec::Vec;
use caliptra_mcu_spdm_codec::{
    GetCertificateReqBody, PqcAsymAlgos, ReqRespCode, SpdmMsgHdrPdu, SpdmVersion, WireWriter,
};
use caliptra_mcu_spdm_traits::SpdmPalAsymAlgo;
use futures::executor::block_on;
use zerocopy::little_endian::U16;

#[path = "support.rs"]
mod support;
use support::{TestHashState, TestIo, TestPal};

use super::*;

#[test]
fn test_asym_algo_selection() {
    let mut state = ConnectionState::<(), [u8; 0]>::caliptra();
    assert_eq!(state.asym_algo(), SpdmPalAsymAlgo::EccP384);

    state.negotiated_pqc_asym_sel = PqcAsymAlgos::MLDSA_87;
    assert_eq!(state.asym_algo(), SpdmPalAsymAlgo::MlDsa87);
}

#[test]
fn test_get_certificate_mldsa87_large_response_trigger() {
    let mut state = ConnectionState::<TestHashState, Vec<u8>>::caliptra();
    state.phase = Phase::AfterAlgorithms;
    state.version = SpdmVersion::V13;
    state.cap_flags |= CapFlags::CHUNK;
    state.peer_cap_flags |= CapFlags::CHUNK;
    state.negotiated_pqc_asym_sel = PqcAsymAlgos::MLDSA_87;

    state.transcript.m1 = Some(TestHashState { digest: [0u8; 48] });

    static MLDSA87_CHAIN: [u8; 4627] = [0u8; 4627];
    let mut pal = TestPal::default();
    pal.mtu = 256;
    pal.cert_chain = &MLDSA87_CHAIN;
    let mut req_buf = [0u8; 10];
    let mut writer = WireWriter::new(&mut req_buf);
    writer
        .write(&SpdmMsgHdrPdu::new(
            SpdmVersion::V14,
            ReqRespCode::GET_CERTIFICATE,
        ))
        .unwrap();
    writer
        .write(&GetCertificateReqBody {
            slot_id: 0,
            attributes: 0,
            offset: U16::new(0),
            length: U16::new(4627),
        })
        .unwrap();

    let io = TestIo::message(req_buf.to_vec());
    let res = block_on(crate::certificate::handle_get_certificate_req(
        &mut state, &pal, &io, &req_buf,
    ));
    let (resp_bytes, _) = res.expect("handle_get_certificate_req failed");
    assert_eq!(&resp_bytes[..5], &[0x13, 0x7F, 0x0F, 0x00, 0x01]);
}
