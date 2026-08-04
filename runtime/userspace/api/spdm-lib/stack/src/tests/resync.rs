// Licensed under the Apache-2.0 license

//! Out-of-order -> `ERROR(RequestResynch, 0x43)` latch tests.
//!
//! OCP 2.7 SPDM-19: when a request is received out of
//! order, the responder answers with `ERROR(RequestResynch, 0x43)` and must
//! return the same error for **every** subsequent request until a `GET_VERSION`
//! is received and processed (which resets the connection and clears the
//! latch). The latch is per-connection, so a resync on one connection must not
//! affect another.

extern crate std;

use super::*;
use caliptra_mcu_spdm_traits::NoVdmBackend;
use futures::executor::block_on;
use std::vec;
use std::vec::Vec;

// `support.rs` is also included by other test modules in this crate; loading
// it here is intentional and its cost is test-only.
#[allow(clippy::duplicate_mod)]
#[path = "support.rs"]
mod support;
use support::*;

/// A minimal, well-formed `GET_VERSION` request (header version 0x10, code 0x84,
/// Param1/Param2 reserved-zero). This is the only message that clears the latch.
fn get_version_io() -> TestIo {
    TestIo::message(vec![
        SpdmVersion::V10.to_u8(),
        ReqRespCode::GET_VERSION.0,
        0,
        0,
    ])
}

/// Dispatch `code` on `state`, returning the handler/dispatcher result.
fn dispatch_code(
    state: &mut ConnectionState<TestHashState, Vec<u8>>,
    sessions: &mut Sessions<TestPal, 1>,
    pal: &TestPal,
    code: ReqRespCode,
    io: &TestIo,
) -> SpdmResult<Vec<u8>> {
    block_on(dispatch(state, sessions, pal, io, code, &NoVdmBackend))
}

// SPDM-19: a GET_CAPABILITIES received in Phase::Start (before GET_VERSION) is
// out of order and must return ERROR(RequestResynch), not UnexpectedRequest,
// and must latch the connection into the resync-required state.
#[test]
fn out_of_order_request_returns_request_resynch_and_latches() {
    let pal = TestPal::default();
    let mut state = ConnectionState::<TestHashState, Vec<u8>>::default();
    let mut sessions = crate::session::SessionManager::new();
    assert_eq!(state.phase, Phase::Start);
    assert!(!state.resync_required);

    let io = TestIo::message(vec![
        SpdmVersion::V12.to_u8(),
        ReqRespCode::GET_CAPABILITIES.0,
    ]);
    let err = dispatch_code(
        &mut state,
        &mut sessions,
        &pal,
        ReqRespCode::GET_CAPABILITIES,
        &io,
    )
    .unwrap_err();

    assert_eq!(err.spec_byte(), SPDM_REQUEST_RESYNCH.spec_byte());
    assert_eq!(err.spec_byte(), 0x43);
    assert!(state.resync_required);
}

// SPDM-19: once latched, ALL subsequent requests (even ones that would
// otherwise be legal in the current phase) return ERROR(RequestResynch).
#[test]
fn latched_connection_rejects_all_subsequent_requests() {
    let pal = TestPal::default();
    // Start already negotiated so GET_DIGESTS would normally be accepted; the
    // latch alone must still short-circuit it.
    let mut state = negotiated_state(SpdmVersion::V12);
    let mut sessions = crate::session::SessionManager::new();
    state.resync_required = true;

    for code in [
        ReqRespCode::GET_DIGESTS,
        ReqRespCode::GET_CERTIFICATE,
        ReqRespCode::CHALLENGE,
        ReqRespCode::GET_CAPABILITIES,
        ReqRespCode::NEGOTIATE_ALGORITHMS,
    ] {
        let io = TestIo::message(vec![SpdmVersion::V12.to_u8(), code.0]);
        let err = dispatch_code(&mut state, &mut sessions, &pal, code, &io).unwrap_err();
        assert_eq!(
            err.spec_byte(),
            SPDM_REQUEST_RESYNCH.spec_byte(),
            "code {:#x} should be answered with RequestResynch while latched",
            code.0
        );
    }
}

// SPDM-19: GET_VERSION is exempt from the latch and clears it; normal operation
// resumes afterwards.
#[test]
fn get_version_clears_the_latch() {
    let pal = TestPal::default();
    let mut state = negotiated_state(SpdmVersion::V12);
    let mut sessions = crate::session::SessionManager::new();
    state.resync_required = true;

    let io = get_version_io();
    let rsp = dispatch_code(
        &mut state,
        &mut sessions,
        &pal,
        ReqRespCode::GET_VERSION,
        &io,
    )
    .expect("GET_VERSION must succeed even while latched");

    // GET_VERSION cleared the latch and reset the connection to AfterVersion.
    assert!(!state.resync_required);
    assert_eq!(state.phase, Phase::AfterVersion);
    // Response is a VERSION message (code 0x04 in the response-code space, spelled
    // via the common header); assert it is not an ERROR PDU.
    assert_ne!(rsp[1], ReqRespCode::ERROR.0);
}

// SPDM-19 isolation: latching resync on one connection must not affect another.
// Each ConnectionState is per-connection (per MboxTransportId), so the latch is
// physically independent - mutating one leaves the other untouched, and the
// other can still be driven normally.
#[test]
fn resync_latch_is_isolated_per_connection() {
    let pal = TestPal::default();
    let mut conn_a = ConnectionState::<TestHashState, Vec<u8>>::default();
    let mut conn_b = ConnectionState::<TestHashState, Vec<u8>>::default();
    let mut sessions_a = crate::session::SessionManager::new();
    let mut sessions_b = crate::session::SessionManager::new();

    // Force connection A out of order -> A latches.
    let io_a = TestIo::message(vec![
        SpdmVersion::V12.to_u8(),
        ReqRespCode::GET_CAPABILITIES.0,
    ]);
    let err = dispatch_code(
        &mut conn_a,
        &mut sessions_a,
        &pal,
        ReqRespCode::GET_CAPABILITIES,
        &io_a,
    )
    .unwrap_err();
    assert_eq!(err.spec_byte(), SPDM_REQUEST_RESYNCH.spec_byte());

    // A is latched; B is completely unaffected.
    assert!(conn_a.resync_required);
    assert!(!conn_b.resync_required);

    // B still processes GET_VERSION normally (no residual latch from A).
    let io_b = get_version_io();
    dispatch_code(
        &mut conn_b,
        &mut sessions_b,
        &pal,
        ReqRespCode::GET_VERSION,
        &io_b,
    )
    .expect("connection B must be unaffected by A's resync latch");
    assert!(!conn_b.resync_required);
    assert_eq!(conn_b.phase, Phase::AfterVersion);
}

// DSP0274 1.4.0 section 7 (SPDM message exchanges): an in-session request that
// is not valid for the current session phase (e.g. a negotiation-phase
// GET_CAPABILITIES received inside an established session) is an unexpected
// request. It must be answered with ERROR(UnexpectedRequest, 0x04) - not
// RequestResynch - and must not latch.
#[test]
fn secured_in_session_unexpected_request_returns_unexpected_request() {
    let pal = TestPal::default();
    let (mut state, mut sessions, session_id) = established_session(&pal);
    assert!(!state.resync_required);

    // GET_CAPABILITIES is a negotiation-phase message; inside an established
    // session it is an unexpected request.
    let inner = vec![SpdmVersion::V12.to_u8(), ReqRespCode::GET_CAPABILITIES.0];
    let io = secured_io(session_id, &inner);
    let rsp = block_on(handle_secured_request(
        &mut state,
        &mut sessions,
        &pal,
        &io,
        &NoVdmBackend,
    ))
    .expect("secured handler must not fatally error")
    .expect("an ERROR PDU must be produced");

    // Decrypt the secured envelope and inspect the inner ERROR PDU.
    let spdm = secured_spdm_response(&rsp);
    assert_eq!(spdm[1], ReqRespCode::ERROR.0);
    assert_eq!(spdm[2], SPDM_UNEXPECTED_REQUEST.spec_byte());
    assert_eq!(spdm[2], 0x04);
    // An in-session unexpected request must not latch resync.
    assert!(!state.resync_required);
}

// DSP0274 1.4.0 section 17 (General ordering rules): a NEGOTIATE_ALGORITHMS
// re-sent after algorithms were already negotiated (a non-identical retry, past
// the expected phase) is an unexpected request answered with
// ERROR(UnexpectedRequest, 0x04) - not RequestResynch, and it must not latch.
// Only a skipped prerequisite (arriving before the expected phase) is out of order.
#[test]
fn duplicate_negotiate_algorithms_returns_unexpected_request() {
    let pal = TestPal::default();
    // negotiated_state advances past NEGOTIATE_ALGORITHMS, so a second one is a
    // duplicate rather than a skipped-prerequisite out-of-order request.
    let mut state = negotiated_state(SpdmVersion::V12);
    let mut sessions = crate::session::SessionManager::new();
    assert!(!state.resync_required);
    assert!(state.phase as u8 > Phase::AfterCapabilities as u8);

    let io = TestIo::message(vec![
        SpdmVersion::V12.to_u8(),
        ReqRespCode::NEGOTIATE_ALGORITHMS.0,
    ]);
    let err = dispatch_code(
        &mut state,
        &mut sessions,
        &pal,
        ReqRespCode::NEGOTIATE_ALGORITHMS,
        &io,
    )
    .unwrap_err();

    assert_eq!(err.spec_byte(), SPDM_UNEXPECTED_REQUEST.spec_byte());
    assert_eq!(err.spec_byte(), 0x04);
    assert!(!state.resync_required);
}

// DSP0274 1.4.0 section 17 (General ordering rules): an out-of-order request
// nullifies the transcript. out_of_order() must drop any partially-accumulated
// VCA/M1/L1 context so it cannot be carried into the post-resync negotiation.
#[test]
fn out_of_order_nullifies_transcript() {
    let pal = TestPal::default();
    let io = TestIo::message(vec![]);
    let mut state = negotiated_state(SpdmVersion::V12);
    // Seed a running transcript context (as a mid-negotiation connection has),
    // using the real append path so the slots hold genuine hash states.
    block_on(state.transcript.append_vca(&pal, &io, &[0xAA, 0xBB])).unwrap();
    block_on(state.transcript.append_m1(&pal, &io, &[0xCC])).unwrap();
    assert!(state.transcript.vca.is_some());
    assert!(state.transcript.m1.is_some());

    let err = state.out_of_order();

    assert_eq!(err.spec_byte(), 0x43);
    assert!(state.resync_required);
    // Every transcript slot is cleared.
    assert!(state.transcript.vca.is_none());
    assert!(state.transcript.m1.is_none());
    assert!(state.transcript.l1.is_none());
}
