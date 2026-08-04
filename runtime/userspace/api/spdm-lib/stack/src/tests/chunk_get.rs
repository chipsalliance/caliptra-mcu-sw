// Licensed under the Apache-2.0 license

//! CHUNK_GET large-response sizing + drive tests at a 4 KiB `DataTransferSize`.
//!
//! These cover the transfer-buffer headroom accounting introduced so a buffered
//! large response can always allocate its next chunk: the advertised /
//! effective `MaxSPDMmsgSize` reserves [`large_msg_headroom`], and a pool too
//! small to hold one transport-sized message after that reservation strips
//! CHUNK from the advertised capabilities.

extern crate std;

use caliptra_mcu_spdm_codec::{
    CapFlags, ChunkResponseBody, ReqRespCode, SpdmMsgHdrPdu, SpdmVersion,
    CHUNK_ATTR_LAST_CHUNK, CHUNK_RESPONSE_FIXED_BODY_SIZE, LARGE_RESPONSE_SIZE_FIELD_SIZE,
};
use caliptra_mcu_spdm_traits::SpdmPalAlloc;
use futures::executor::block_on;
use std::vec;
use std::vec::Vec;
use zerocopy::FromBytes;

use crate::chunk::LargeResponse;
use crate::stack::{
    large_msg_headroom, usable_large_capacity, ConnectionState, Phase, SpdmStack,
};

#[path = "support.rs"]
mod support;
use support::*;

const MTU: usize = 4096;
const POOL_20K: usize = 20 * 1024;
const POOL_12K: usize = 12 * 1024;
/// Backing pool held by the buffered large response in the drive test.
const LARGE_RESP_SIZE: usize = 8 * 1024;

fn pal_with(mtu: usize, large_capacity: usize) -> TestPal {
    TestPal {
        mtu,
        large_capacity,
        ..Default::default()
    }
}

/// A negotiated state with CHUNK on both sides, ready to serve CHUNK_GET.
fn chunk_ready_state() -> ConnectionState<TestHashState, Vec<u8>> {
    let mut state = chunking_state();
    // chunking_state() only sets the peer flag; the responder must also
    // advertise CHUNK for `chunking_enabled()` to hold.
    state.cap_flags |= CapFlags::CHUNK;
    state
}

/// TestPal reports `header_size() == 0`, so the headroom formula reduces to
/// `2 * mtu + LARGE_MSG_SCRATCH_RESERVE`. Assert the helper agrees and that
/// `usable_large_capacity` subtracts exactly that from the raw pool.
#[test]
fn headroom_reserves_two_frames_plus_scratch() {
    let pal = pal_with(MTU, POOL_20K);
    // 2 KiB scratch reserve + two header+mtu frames (header 0 here).
    assert_eq!(large_msg_headroom(&pal), 2 * MTU + 2 * 1024);
    assert_eq!(usable_large_capacity(&pal), POOL_20K - (2 * MTU + 2 * 1024));
}

/// The advertised `MaxSPDMmsgSize` (CAPABILITIES) and the effective size both
/// reflect the headroom-reserved usable capacity, not the raw pool.
#[test]
fn capabilities_and_effective_size_match_usable_capacity() {
    let pal = pal_with(MTU, POOL_20K);
    let usable = usable_large_capacity(&pal);

    // Drive the CAPABILITIES handler with a V1.2 CHUNK-capable peer and read
    // the MaxSPDMmsgSize it advertises straight off the wire.
    let mut state = negotiated_state(SpdmVersion::V12);
    state.phase = Phase::AfterVersion;
    state.cap_flags |= CapFlags::CHUNK;

    let mut req = vec![SpdmVersion::V12.to_u8(), ReqRespCode::GET_CAPABILITIES.0];
    req.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // Param1/2, Reserved, CTExp, Reserved2
    req.extend_from_slice(&CapFlags::CHUNK.into_bits().to_le_bytes());
    req.extend_from_slice(&(MTU as u32).to_le_bytes()); // DataTransferSize
    req.extend_from_slice(&(MTU as u32).to_le_bytes()); // MaxSPDMmsgSize
    let io = TestIo::message(req);

    let resp = block_on(crate::capabilities::handle_get_capabilities(&mut state, &pal, &io)).unwrap();

    // header_size() == 0, so the SPDM body starts at offset 0:
    // version | code | CapabilitiesBodyV11(10) | DataTransferSize(4) | MaxSPDMmsgSize(4)
    let dts = u32::from_le_bytes(resp[12..16].try_into().unwrap()) as usize;
    let advertised_max = u32::from_le_bytes(resp[16..20].try_into().unwrap()) as usize;
    assert_eq!(dts, MTU);
    assert_eq!(advertised_max, usable.max(MTU));

    // The effective (min of local usable and peer) tracks the same usable value
    // once negotiated; the peer here advertised only 4 KiB, so it wins.
    state.peer_max_spdm_msg_size = MTU as u32;
    assert_eq!(state.effective_max_spdm_msg_size(&pal), MTU);
    // With a generous peer, the local usable capacity is the ceiling.
    state.peer_max_spdm_msg_size = u32::MAX;
    assert_eq!(state.effective_max_spdm_msg_size(&pal), usable.max(MTU));
}

/// A 20 KiB pool leaves >= one transport frame usable after headroom, so CHUNK
/// stays advertised; a 12 KiB pool does not, so CHUNK is stripped at build.
#[test]
fn chunk_strips_when_pool_cannot_hold_one_frame() {
    let pal_20k = pal_with(MTU, POOL_20K);
    assert!(usable_large_capacity(&pal_20k) >= MTU);
    let stack_20k: SpdmStack<TestPal> = SpdmStack::new(pal_20k);
    assert!(stack_20k.state.cap_flags.contains(CapFlags::CHUNK));

    let pal_12k = pal_with(MTU, POOL_12K);
    assert!(usable_large_capacity(&pal_12k) < MTU);
    let stack_12k: SpdmStack<TestPal> = SpdmStack::new(pal_12k);
    assert!(!stack_12k.state.cap_flags.contains(CapFlags::CHUNK));
}

/// Seed a buffered large response and walk it out over CHUNK_GET, asserting each
/// chunk is bounded by the effective transfer size and that `bytes_sent`
/// advances monotonically to the terminal LAST_CHUNK.
#[test]
fn chunk_get_walks_buffered_response_over_4k_frames() {
    let pal = pal_with(MTU, POOL_20K);
    let mut state = chunk_ready_state();

    // Fill a large buffer with an identifiable pattern and park it as a
    // buffered large response (as vendor_defined / start_buffered would).
    let mut buf = pal.alloc_large_buf(LARGE_RESP_SIZE).unwrap();
    for (i, b) in buf.iter_mut().enumerate() {
        *b = i as u8;
    }
    state.large_msg_ctx.set_buffer(buf);
    let rent = state.large_msg_ctx.take_buffer();
    state
        .large_msg_ctx
        .start_response(LargeResponse::Buffered, LARGE_RESP_SIZE, rent)
        .unwrap();
    let handle = state.large_msg_ctx.response().unwrap().handle;

    let mut total = 0usize;
    let mut seq = 0u16;
    loop {
        let req = chunk_get_request(handle, seq);
        let io = TestIo::message(req.clone());
        let rsp = block_on(crate::chunk::handle_chunk_get(&mut state, &pal, &io, &req)).unwrap();

        let (body, _) =
            ChunkResponseBody::ref_from_prefix(&rsp[SpdmMsgHdrPdu::SIZE..]).unwrap();
        let chunk_size = body.chunk_size.get() as usize;
        let last = (body.chunk_sender_attr & CHUNK_ATTR_LAST_CHUNK) != 0;
        assert_eq!(body.handle, handle);
        assert_eq!(body.chunk_seq_num.get(), seq);

        // Chunk payload must fit one effective frame, minus the CHUNK_RESPONSE
        // fixed body and (on the first chunk) the LargeResponseSize field.
        let extra = if seq == 0 { LARGE_RESPONSE_SIZE_FIELD_SIZE } else { 0 };
        let max_chunk = state.effective_data_transfer_size(&pal)
            - (SpdmMsgHdrPdu::SIZE + CHUNK_RESPONSE_FIXED_BODY_SIZE + extra);
        assert!(chunk_size <= max_chunk, "chunk {} exceeds frame budget", seq);

        // Verify the emitted chunk bytes are the parked buffer's slice.
        let payload_off = SpdmMsgHdrPdu::SIZE + CHUNK_RESPONSE_FIXED_BODY_SIZE + extra;
        for (j, b) in rsp[payload_off..payload_off + chunk_size].iter().enumerate() {
            assert_eq!(*b, (total + j) as u8);
        }

        total += chunk_size;
        if last {
            break;
        }
        seq += 1;
    }

    assert_eq!(total, LARGE_RESP_SIZE);
    // The context resets itself once the whole response has been sent.
    assert!(state.large_msg_ctx.response().is_none());
}

/// Builds a CHUNK_GET request: SPDM header + ChunkGetReqBody(param1=0, handle,
/// chunk_seq_num).
fn chunk_get_request(handle: u8, seq: u16) -> Vec<u8> {
    let mut req = vec![SpdmVersion::V12.to_u8(), ReqRespCode::CHUNK_GET.0, 0, handle];
    req.extend_from_slice(&seq.to_le_bytes());
    req
}
