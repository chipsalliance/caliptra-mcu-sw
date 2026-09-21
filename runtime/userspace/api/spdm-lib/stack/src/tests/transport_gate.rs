// Licensed under the Apache-2.0 license

//! Transport-ownership gate tests.
//!
//! A single [`SpdmStack`] holds one [`ConnectionState`]. When a transport
//! multiplexes several physical interfaces onto that one stack, the
//! responder must refuse to serve post-`GET_VERSION` requests to any transport
//! other than the one that ran VCA.
//!
//! Interface tags here are arbitrary distinct `u8` values — the stack treats
//! them as opaque and only compares them for equality.

extern crate std;

use super::*;
use caliptra_mcu_spdm_traits::NoVdmBackend;
use futures::executor::block_on;
use std::vec;
use std::vec::Vec;

#[path = "support.rs"]
mod support;
use support::*;

/// Interface tag standing in for the transport that runs VCA.
const TID_OWNER: u8 = 0;
/// A different interface tag on the same multiplexed transport.
const TID_OTHER: u8 = 1;

fn get_version_request() -> Vec<u8> {
    // DSP0274: the GET_VERSION header version is always 0x10; Param1/Param2
    // are reserved and must be zero.
    vec![SpdmVersion::V10.to_u8(), ReqRespCode::GET_VERSION.0, 0, 0]
}

fn plain_request(version: SpdmVersion, code: ReqRespCode) -> Vec<u8> {
    vec![version.to_u8(), code.0, 0, 0]
}

/// Runs one plain request through the real dispatcher.
fn dispatch_plain(
    state: &mut ConnectionState<TestHashState, Vec<u8>>,
    sessions: &mut Sessions<TestPal, 1>,
    pal: &TestPal,
    io: &TestIo,
    code: ReqRespCode,
) -> SpdmResult<()> {
    block_on(dispatch(state, sessions, pal, io, code, &NoVdmBackend)).map(|_| ())
}

/// Connection already through VCA and owned by `tid`.
///
/// Seeds the running VCA hash as a real `GET_VERSION` … `ALGORITHMS` exchange
/// would, so post-VCA handlers that fork M1/L1 off it (`GET_DIGESTS`,
/// `CHALLENGE`) behave as they do in production.
fn owned_state(pal: &TestPal, tid: Option<u8>) -> ConnectionState<TestHashState, Vec<u8>> {
    let mut state = negotiated_state(SpdmVersion::V12);
    let seed_io = TestIo::message(Vec::new());
    block_on(state.transcript.append_vca(pal, &seed_io, b"vca")).unwrap();
    state.active_transport_id = tid;
    state
}

// ── Case 1: GET_VERSION records the claim ───────────────────────────

#[test]
fn get_version_claims_ownership() {
    let pal = TestPal::default();
    let mut state = ConnectionState::default();
    let mut sessions: Sessions<TestPal, 1> = crate::session::SessionManager::new();
    assert_eq!(state.active_transport_id, None);

    let io = TestIo::message(get_version_request()).from_transport(TID_OWNER);
    dispatch_plain(
        &mut state,
        &mut sessions,
        &pal,
        &io,
        ReqRespCode::GET_VERSION,
    )
    .expect("GET_VERSION must succeed");

    assert_eq!(state.active_transport_id, Some(TID_OWNER));
    assert_eq!(state.phase, Phase::AfterVersion);
}

// ── Case 2: the owner is unaffected ─────────────────────────────────

#[test]
fn owning_transport_may_issue_post_vca_request() {
    let pal = TestPal::default();
    let mut state = owned_state(&pal, Some(TID_OWNER));
    let mut sessions: Sessions<TestPal, 1> = crate::session::SessionManager::new();

    let io = TestIo::message(plain_request(SpdmVersion::V12, ReqRespCode::GET_DIGESTS))
        .from_transport(TID_OWNER);
    dispatch_plain(
        &mut state,
        &mut sessions,
        &pal,
        &io,
        ReqRespCode::GET_DIGESTS,
    )
    .expect("owner's GET_DIGESTS must still be served");

    assert_eq!(state.phase, Phase::AfterDigests);
}

// ── Case 3: foreign plain request is rejected ───────────────────────

#[test]
fn foreign_transport_get_digests_rejected() {
    let pal = TestPal::default();
    let mut state = owned_state(&pal, Some(TID_OWNER));
    let mut sessions: Sessions<TestPal, 1> = crate::session::SessionManager::new();

    let io = TestIo::message(plain_request(SpdmVersion::V12, ReqRespCode::GET_DIGESTS))
        .from_transport(TID_OTHER);
    let err = dispatch_plain(
        &mut state,
        &mut sessions,
        &pal,
        &io,
        ReqRespCode::GET_DIGESTS,
    )
    .expect_err("non-owning transport must be refused");

    assert_eq!(err.spec_byte(), SPDM_REQUEST_RESYNCH.spec_byte());
    // The rejected request must not have advanced the owner's connection.
    assert_eq!(state.phase, Phase::AfterAlgorithms);
    assert_eq!(state.active_transport_id, Some(TID_OWNER));
}

// ── Case 4: foreign KEY_EXCHANGE is rejected before any crypto ──────

#[test]
fn foreign_transport_key_exchange_rejected() {
    let pal = TestPal::default();
    let mut state = owned_state(&pal, Some(TID_OWNER));
    let mut sessions: Sessions<TestPal, 1> = crate::session::SessionManager::new();

    let io = TestIo::message(plain_request(SpdmVersion::V12, ReqRespCode::KEY_EXCHANGE))
        .from_transport(TID_OTHER);
    let err = dispatch_plain(
        &mut state,
        &mut sessions,
        &pal,
        &io,
        ReqRespCode::KEY_EXCHANGE,
    )
    .expect_err("non-owning transport must not reach KEY_EXCHANGE");

    assert_eq!(err.spec_byte(), SPDM_REQUEST_RESYNCH.spec_byte());
    // Gated ahead of the handler: the single session slot is untouched.
    assert!(!sessions.has_handshake_in_progress());
}

// ── Case 5: GET_VERSION from another transport takes over ───────────

#[test]
fn get_version_from_second_transport_takes_ownership() {
    let pal = TestPal::default();
    let mut state = owned_state(&pal, Some(TID_OWNER));
    let mut sessions: Sessions<TestPal, 1> = crate::session::SessionManager::new();

    let io = TestIo::message(get_version_request()).from_transport(TID_OTHER);
    dispatch_plain(
        &mut state,
        &mut sessions,
        &pal,
        &io,
        ReqRespCode::GET_VERSION,
    )
    .expect("GET_VERSION is how a transport claims the connection");

    assert_eq!(state.active_transport_id, Some(TID_OTHER));
    assert_eq!(state.phase, Phase::AfterVersion);
}

// ── Case 6: foreign secured message is rejected ─────────────────────

#[test]
fn foreign_transport_secured_message_rejected() {
    let pal = TestPal::default();
    let (mut state, mut sessions, session_id) = established_session(&pal);
    state.active_transport_id = Some(TID_OWNER);

    let heartbeat = plain_request(SpdmVersion::V12, ReqRespCode::HEARTBEAT);
    let io = secured_io(session_id, &heartbeat).from_transport(TID_OTHER);
    let err = block_on(handle_secured_request(
        &mut state,
        &mut sessions,
        &pal,
        &io,
        &NoVdmBackend,
    ))
    .expect_err("secured traffic from a non-owning transport must be refused");

    assert_eq!(err.spec_byte(), SPDM_REQUEST_RESYNCH.spec_byte());
    // The owner's session survives — rejection is not a session teardown.
    assert!(sessions.find(session_id).is_some());
}

#[test]
fn owning_transport_secured_message_reaches_session_lookup() {
    let pal = TestPal::default();
    let (mut state, mut sessions, session_id) = established_session(&pal);
    state.active_transport_id = Some(TID_OWNER);

    let heartbeat = plain_request(SpdmVersion::V12, ReqRespCode::HEARTBEAT);
    let io = secured_io(session_id, &heartbeat).from_transport(TID_OWNER);
    // Not asserting the HEARTBEAT_ACK body here — only that the gate does not
    // stand in the owner's way.
    let result = block_on(handle_secured_request(
        &mut state,
        &mut sessions,
        &pal,
        &io,
        &NoVdmBackend,
    ));
    assert!(
        result.is_ok(),
        "owner's secured message must not be gated: {:?}",
        result.err().map(|e| e.spec_byte())
    );
}

// ── Case 7: regression guard for the no-identity transports ─────────

/// MCTP and DOE each own a dedicated stack instance and report no identity, so
/// the gate must be completely inert for them. Without this the two native
/// responders would break the moment `active_transport_id` stayed `None`.
#[test]
fn transports_without_identity_are_unaffected() {
    let pal = TestPal::default();
    let mut state = ConnectionState::<TestHashState, Vec<u8>>::default();
    let mut sessions: Sessions<TestPal, 1> = crate::session::SessionManager::new();

    // GET_VERSION leaves ownership unset rather than recording a sentinel.
    let io = TestIo::message(get_version_request());
    dispatch_plain(
        &mut state,
        &mut sessions,
        &pal,
        &io,
        ReqRespCode::GET_VERSION,
    )
    .expect("GET_VERSION must succeed with no transport identity");
    assert_eq!(state.active_transport_id, None);

    // A post-VCA request still goes through with ownership unset.
    let mut state = owned_state(&pal, None);
    let io = TestIo::message(plain_request(SpdmVersion::V12, ReqRespCode::GET_DIGESTS));
    dispatch_plain(
        &mut state,
        &mut sessions,
        &pal,
        &io,
        ReqRespCode::GET_DIGESTS,
    )
    .expect("GET_DIGESTS must be served when identity is not applicable");
    assert_eq!(state.phase, Phase::AfterDigests);

    // Secured traffic likewise.
    let (mut state, mut sessions, session_id) = established_session(&pal);
    assert_eq!(state.active_transport_id, None);
    let heartbeat = plain_request(SpdmVersion::V12, ReqRespCode::HEARTBEAT);
    let io = secured_io(session_id, &heartbeat);
    assert!(block_on(handle_secured_request(
        &mut state,
        &mut sessions,
        &pal,
        &io,
        &NoVdmBackend,
    ))
    .is_ok());
}

/// A transport that reports an identity must not be able to use a connection
/// negotiated by a no-identity transport. `None` is "not applicable", never a
/// value that compares equal to a real tag.
#[test]
fn identified_transport_cannot_inherit_unclaimed_connection() {
    let pal = TestPal::default();
    let mut state = owned_state(&pal, None);
    let mut sessions: Sessions<TestPal, 1> = crate::session::SessionManager::new();

    let io = TestIo::message(plain_request(SpdmVersion::V12, ReqRespCode::GET_DIGESTS))
        .from_transport(TID_OWNER);
    let err = dispatch_plain(
        &mut state,
        &mut sessions,
        &pal,
        &io,
        ReqRespCode::GET_DIGESTS,
    )
    .expect_err("an unclaimed connection must not be usable by a tagged transport");

    assert_eq!(err.spec_byte(), SPDM_REQUEST_RESYNCH.spec_byte());
}

// ── Case 8: the evicted owner loses access ──────────────────────────

/// `GET_VERSION` already destroys all sessions and resets negotiation, so a
/// takeover is pre-existing behaviour. The gate makes it *visible*: the
/// displaced transport is now told to resynch instead of being silently served
/// with the new owner's connection state.
#[test]
fn evicted_owner_is_refused_after_takeover() {
    let pal = TestPal::default();
    let mut state = owned_state(&pal, Some(TID_OWNER));
    let mut sessions: Sessions<TestPal, 1> = crate::session::SessionManager::new();

    let io = TestIo::message(get_version_request()).from_transport(TID_OTHER);
    dispatch_plain(
        &mut state,
        &mut sessions,
        &pal,
        &io,
        ReqRespCode::GET_VERSION,
    )
    .unwrap();
    assert_eq!(state.active_transport_id, Some(TID_OTHER));

    let io = TestIo::message(plain_request(SpdmVersion::V12, ReqRespCode::GET_DIGESTS))
        .from_transport(TID_OWNER);
    let err = dispatch_plain(
        &mut state,
        &mut sessions,
        &pal,
        &io,
        ReqRespCode::GET_DIGESTS,
    )
    .expect_err("the displaced transport must be refused");

    assert_eq!(err.spec_byte(), SPDM_REQUEST_RESYNCH.spec_byte());
}

// ── Case 9: the ERROR PDU on the wire ───────────────────────────────

/// End-to-end through `send_error_pdu`: the rejected requester gets
/// `ERROR(RequestResynch)` at **its own** header version, not the responder's
/// negotiated one, so a requester still at `Phase::Start` can parse it.
#[test]
fn error_pdu_reports_request_resynch_at_requester_version() {
    let mut stack: SpdmStack<TestPal, 1> = SpdmStack::new(TestPal::default());
    stack.state = owned_state(&stack.pal, Some(TID_OWNER));

    let request = plain_request(SpdmVersion::V13, ReqRespCode::GET_DIGESTS);
    let io = TestIo::message(request).from_transport(TID_OTHER);
    let (code, req_version) = decode_header(io.request());
    assert_eq!(req_version, SpdmVersion::V13);

    let err = block_on(dispatch(
        &mut stack.state,
        &mut stack.sessions,
        &stack.pal,
        &io,
        code,
        &NoVdmBackend,
    ))
    .expect_err("must be refused");

    block_on(stack.send_error_pdu(&io, err, req_version)).expect("ERROR PDU must be sent");

    let sent = stack.pal.sent.borrow();
    assert_eq!(sent.len(), 1);
    let pdu = &sent[0];
    // header_size() == 0 for TestPal, so the SPDM message starts at byte 0.
    assert_eq!(
        pdu[0],
        SpdmVersion::V13.to_u8(),
        "ERROR must echo the requester's header version"
    );
    assert_eq!(pdu[1], ReqRespCode::ERROR.0);
    assert_eq!(pdu[2], 0x43, "param1 = RequestResynch");
    assert_eq!(pdu[3], 0x00, "param2 reserved for RequestResynch");
}
