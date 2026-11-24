// Licensed under the Apache-2.0 license

//! HEARTBEAT liveness-watchdog tests (DSP0274 1.3.0 section 10.20).
//!
//! Covers the per-session watchdog independent of the run loop: arming at
//! establishment, keep-alive on secured traffic, and teardown after two missed
//! HeartbeatPeriods. Also asserted: HBEAT_CAP advertisement, feature-off
//! behavior, and the HeartbeatPeriod that KEY_EXCHANGE_RSP selects
//! (`heartbeat_period_for`: non-zero only when both endpoints set HBEAT_CAP),
//! and that a secured HEARTBEAT is acknowledged only under that same rule.
//! The KEY_EXCHANGE_RSP encoding of that byte is not checked here.

extern crate std;

use super::*;
use caliptra_mcu_spdm_codec::HeartBeatPeriod;
use caliptra_mcu_spdm_traits::NoVdmBackend;
use futures::executor::block_on;
use std::vec;
use std::vec::Vec;

#[path = "support.rs"]
mod support;
use support::*;

// 2 x period x 1000 ms; period defaults to 3 s in the reference config.
const PERIOD_SECS: u8 = 3;
const WINDOW_MS: u64 = 2 * PERIOD_SECS as u64 * 1000;

// Arming at establishment sets the deadline to now + 2*period*1000 ms.
#[test]
fn arm_sets_deadline_from_period() {
    let pal = TestPal::default();
    let (_state, mut sessions, session_id) = established_session(&pal);
    let session = sessions.find_mut(session_id).unwrap();
    session.heartbeat_period = HeartBeatPeriod(PERIOD_SECS);
    session.arm_heartbeat(1000);
    assert_eq!(session.deadline_ms, Some(1000 + WINDOW_MS));
}

// A zero period (heartbeat not desired) leaves the watchdog unarmed.
#[test]
fn arm_is_inert_when_period_zero() {
    let pal = TestPal::default();
    let (_state, mut sessions, session_id) = established_session(&pal);
    let session = sessions.find_mut(session_id).unwrap();
    session.heartbeat_period = HeartBeatPeriod::DISABLED;
    session.arm_heartbeat(1000);
    assert_eq!(session.deadline_ms, None);
}

// Keep-alive: touch restarts an armed watchdog, but never arms a disabled one.
#[test]
fn touch_restarts_only_armed_watchdog() {
    let pal = TestPal::default();
    let (_state, mut sessions, session_id) = established_session(&pal);
    let session = sessions.find_mut(session_id).unwrap();
    session.heartbeat_period = HeartBeatPeriod(PERIOD_SECS);
    session.arm_heartbeat(1000);
    session.touch_heartbeat(5000);
    assert_eq!(session.deadline_ms, Some(5000 + WINDOW_MS));

    // Disabled watchdog: touch is a no-op.
    session.deadline_ms = None;
    session.touch_heartbeat(9000);
    assert_eq!(session.deadline_ms, None);
}

// nearest_deadline_ms reports the minimum armed deadline (or None).
#[test]
fn nearest_deadline_reports_min() {
    let pal = TestPal::default();
    let (_state, mut sessions, session_id) = established_session(&pal);
    assert_eq!(sessions.nearest_deadline_ms(), None);
    let session = sessions.find_mut(session_id).unwrap();
    session.heartbeat_period = HeartBeatPeriod(PERIOD_SECS);
    session.arm_heartbeat(1000);
    assert_eq!(sessions.nearest_deadline_ms(), Some(1000 + WINDOW_MS));
}

// Teardown: a session whose deadline has passed is cleared by expire_due; a
// not-yet-expired session survives.
#[test]
fn expire_due_clears_only_expired_sessions() {
    let pal = TestPal::default();
    let (_state, mut sessions, session_id) = established_session(&pal);
    let session = sessions.find_mut(session_id).unwrap();
    session.heartbeat_period = HeartBeatPeriod(PERIOD_SECS);
    session.arm_heartbeat(1000);
    let deadline = 1000 + WINDOW_MS;

    // Just before the deadline: survives.
    assert_eq!(sessions.expire_due(deadline - 1), 0);
    assert!(sessions.find(session_id).is_some());

    // At the deadline: torn down.
    assert_eq!(sessions.expire_due(deadline), 1);
    assert!(sessions.find(session_id).is_none());
}

// Armed established session at `now = 0` for the run-loop tests below.
#[cfg(feature = "spdm-set-heartbeat")]
fn armed_session(pal: &TestPal) -> (Sessions<TestPal, 1>, u32) {
    let (_state, mut sessions, session_id) = established_session(pal);
    let session = sessions.find_mut(session_id).unwrap();
    session.heartbeat_period = HeartBeatPeriod(PERIOD_SECS);
    session.arm_heartbeat(0);
    (sessions, session_id)
}

// A session already past its deadline when the run loop starts waiting is
// reaped before the wait (no timer is armed).
#[cfg(feature = "spdm-set-heartbeat")]
#[test]
fn recv_next_reaps_expired_session_before_waiting() {
    let pal = TestPal::default();
    let (mut sessions, session_id) = armed_session(&pal);
    pal.set_now_ms(WINDOW_MS);
    let r = block_on(recv_next(&pal, &mut sessions));
    assert_eq!(r.err(), Some(mcu_error::codes::NOT_IMPLEMENTED));
    assert!(sessions.find(session_id).is_none());
    assert_eq!(pal.recv_calls.get(), 1);
}

// A request that arrives after a session's deadline does not keep that session
// alive. The session is live when the wait starts; the deadline passes while
// the receive is pending, and the receive (not the timer) wins. The reap after
// arrival must tear the session down before the request is dispatched.
#[cfg(feature = "spdm-set-heartbeat")]
#[test]
fn recv_next_reaps_expired_session_when_request_arrives() {
    let pal = TestPal::default();
    let (mut sessions, session_id) = armed_session(&pal);
    pal.now_on_recv_ms.set(Some(WINDOW_MS));
    let r = block_on(recv_next(&pal, &mut sessions));
    assert_eq!(r.err(), Some(mcu_error::codes::NOT_IMPLEMENTED));
    assert!(sessions.find(session_id).is_none());
    assert_eq!(pal.recv_calls.get(), 1);
    // The fake sleep moves the clock forward when it runs. The clock still
    // reads exactly the arrival time, so the timer never ran and only the
    // post-arrival reap could have removed the session.
    assert_eq!(pal.now().0, WINDOW_MS);
}

// A request that arrives before the deadline leaves the session in place.
#[cfg(feature = "spdm-set-heartbeat")]
#[test]
fn recv_next_keeps_live_session() {
    let pal = TestPal::default();
    let (mut sessions, session_id) = armed_session(&pal);
    pal.set_now_ms(WINDOW_MS - 1);
    let r = block_on(recv_next(&pal, &mut sessions));
    assert_eq!(r.err(), Some(mcu_error::codes::NOT_IMPLEMENTED));
    assert!(sessions.find(session_id).is_some());
}

// Silent peer: the timer wins while the receive is still pending, so the
// session is torn down. The same receive is then polled to completion. It is
// not dropped and re-created, which the real transport would not survive.
#[cfg(feature = "spdm-set-heartbeat")]
#[test]
fn recv_next_timer_win_expires_session_and_keeps_receive() {
    let pal = TestPal::default();
    let (mut sessions, session_id) = armed_session(&pal);
    pal.recv_pending_polls.set(1);
    let r = block_on(recv_next(&pal, &mut sessions));
    assert_eq!(r.err(), Some(mcu_error::codes::NOT_IMPLEMENTED));
    assert!(sessions.find(session_id).is_none());
    assert_eq!(pal.recv_calls.get(), 1);
    assert_eq!(pal.recv_pending_polls.get(), 0);
}

const HANDSHAKE_MS: u64 = crate::heartbeat::HANDSHAKE_TIMEOUT_MS;

// KEY_EXCHANGE arms the handshake timeout whatever the HeartbeatPeriod. (A const
// assert in heartbeat.rs keeps the timeout longer than the heartbeat window.)
#[test]
fn handshake_timeout_armed_independent_of_period() {
    let pal = TestPal::default();
    let (_state, mut sessions, session_id) = handshake_session(&pal);
    let session = sessions.find_mut(session_id).unwrap();
    session.heartbeat_period = HeartBeatPeriod::DISABLED;
    session.arm_handshake_timeout(1000);
    assert_eq!(session.deadline_ms, Some(1000 + HANDSHAKE_MS));
    session.heartbeat_period = HeartBeatPeriod(PERIOD_SECS);
    session.arm_handshake_timeout(1000);
    assert_eq!(session.deadline_ms, Some(1000 + HANDSHAKE_MS));
}

// The handshake timeout is never put on an established session.
#[test]
fn handshake_timeout_not_armed_on_established_session() {
    let pal = TestPal::default();
    let (_state, mut sessions, session_id) = established_session(&pal);
    let session = sessions.find_mut(session_id).unwrap();
    session.arm_handshake_timeout(1000);
    assert_eq!(session.deadline_ms, None);
}

// Traffic before FINISH neither extends nor clears the handshake deadline.
#[test]
fn touch_does_not_move_handshake_deadline() {
    let pal = TestPal::default();
    let (_state, mut sessions, session_id) = handshake_session(&pal);
    let session = sessions.find_mut(session_id).unwrap();
    session.heartbeat_period = HeartBeatPeriod(PERIOD_SECS);
    session.arm_handshake_timeout(0);
    session.touch_heartbeat(5000);
    assert_eq!(session.deadline_ms, Some(HANDSHAKE_MS));
    session.heartbeat_period = HeartBeatPeriod::DISABLED;
    session.touch_heartbeat(6000);
    assert_eq!(session.deadline_ms, Some(HANDSHAKE_MS));
}

// An abandoned handshake outlives the heartbeat window and is torn down at the
// handshake deadline.
#[test]
fn expire_due_tears_down_abandoned_handshake() {
    let pal = TestPal::default();
    let (_state, mut sessions, session_id) = handshake_session(&pal);
    sessions
        .find_mut(session_id)
        .unwrap()
        .arm_handshake_timeout(0);
    assert_eq!(sessions.expire_due(WINDOW_MS), 0);
    assert_eq!(sessions.expire_due(HANDSHAKE_MS - 1), 0);
    assert!(sessions.find(session_id).is_some());
    assert_eq!(sessions.expire_due(HANDSHAKE_MS), 1);
    assert!(sessions.find(session_id).is_none());
}

// FINISH: arm_heartbeat replaces the handshake deadline with the heartbeat
// deadline, or clears it when the period is zero.
#[test]
fn finish_replaces_handshake_deadline() {
    for (period, expected) in [
        (HeartBeatPeriod(PERIOD_SECS), Some(100 + WINDOW_MS)),
        (HeartBeatPeriod::DISABLED, None),
    ] {
        let pal = TestPal::default();
        let (_state, mut sessions, session_id) = handshake_session(&pal);
        let session = sessions.find_mut(session_id).unwrap();
        session.heartbeat_period = period;
        session.arm_handshake_timeout(0);
        session.state = crate::session::SessionState::Established;
        session.arm_heartbeat(100);
        assert_eq!(session.deadline_ms, expected);
    }
}

// Run loop: a requester that goes silent after KEY_EXCHANGE. The timer wins and
// the half-open session is torn down, freeing the slot.
#[cfg(feature = "spdm-set-heartbeat")]
#[test]
fn recv_next_tears_down_abandoned_handshake() {
    let pal = TestPal::default();
    let (_state, mut sessions, session_id) = handshake_session(&pal);
    sessions
        .find_mut(session_id)
        .unwrap()
        .arm_handshake_timeout(0);
    pal.recv_pending_polls.set(1);
    let r = block_on(recv_next(&pal, &mut sessions));
    assert_eq!(r.err(), Some(mcu_error::codes::NOT_IMPLEMENTED));
    assert!(sessions.find(session_id).is_none());
    assert!(pal.now().0 >= HANDSHAKE_MS);
}

// Keep-alive through the secured dispatch path: a HEARTBEAT received after the
// clock advances pushes the deadline forward rather than letting it expire.
#[cfg(feature = "spdm-set-heartbeat")]
#[test]
fn secured_heartbeat_refreshes_deadline() {
    let pal = TestPal::default();
    let (mut state, mut sessions, session_id) = established_session(&pal);
    // HEARTBEAT is acknowledged only when both endpoints set HBEAT_CAP.
    set_hbeat_both(&mut state);
    {
        let session = sessions.find_mut(session_id).unwrap();
        session.heartbeat_period = HeartBeatPeriod(PERIOD_SECS);
        session.arm_heartbeat(0);
        assert_eq!(session.deadline_ms, Some(WINDOW_MS));
    }

    // Advance the clock and deliver a secured HEARTBEAT.
    pal.set_now_ms(1500);
    let inner = vec![state.version.to_u8(), ReqRespCode::HEARTBEAT.0, 0, 0];
    let io = secured_io(session_id, &inner);
    let rsp = block_on(handle_secured_request(
        &mut state,
        &mut sessions,
        &pal,
        &io,
        &NoVdmBackend,
    ))
    .expect("secured handler must not fatally error")
    .expect("a HEARTBEAT_ACK must be produced");

    // An encrypted ERROR would also pass the expects above; check the bytes.
    assert_eq!(
        secured_spdm_response(&rsp),
        &[state.version.to_u8(), ReqRespCode::HEARTBEAT_ACK.0, 0, 0]
    );

    let session = sessions.find(session_id).unwrap();
    assert_eq!(session.deadline_ms, Some(1500 + WINDOW_MS));
}

// Sets HBEAT_CAP on both the responder and the peer, as after a GET_CAPABILITIES
// exchange in which both advertised heartbeat support.
#[cfg(feature = "spdm-set-heartbeat")]
fn set_hbeat_both(state: &mut ConnectionState<TestHashState, Vec<u8>>) {
    use caliptra_mcu_spdm_codec::CapFlags;
    let hbeat = CapFlags::HBEAT.into_bits();
    state.cap_flags = CapFlags::from_bits(state.cap_flags.into_bits() | hbeat);
    state.peer_cap_flags = CapFlags::from_bits(state.peer_cap_flags.into_bits() | hbeat);
}

// With the feature on, a secured HEARTBEAT from a Requester that did not set
// HBEAT_CAP is answered with ERROR(UnsupportedRequest), not HEARTBEAT_ACK
// (HEARTBEAT applies only if both endpoints support it, as in libspdm).
#[cfg(feature = "spdm-set-heartbeat")]
#[test]
fn secured_heartbeat_unsupported_without_peer_hbeat_cap() {
    use caliptra_mcu_spdm_codec::CapFlags;
    let pal = TestPal::default();
    let (mut state, mut sessions, session_id) = established_session(&pal);
    set_hbeat_both(&mut state);
    state.peer_cap_flags =
        CapFlags::from_bits(state.peer_cap_flags.into_bits() & !CapFlags::HBEAT.into_bits());
    assert!(!state.heartbeat_enabled());

    let inner = vec![state.version.to_u8(), ReqRespCode::HEARTBEAT.0, 0, 0];
    let io = secured_io(session_id, &inner);
    let rsp = block_on(handle_secured_request(
        &mut state,
        &mut sessions,
        &pal,
        &io,
        &NoVdmBackend,
    ))
    .expect("secured handler must not fatally error")
    .expect("an ERROR response must be produced");

    assert_eq!(
        secured_spdm_response(&rsp),
        &[
            state.version.to_u8(),
            ReqRespCode::ERROR.0,
            SPDM_UNSUPPORTED_REQUEST.spec_byte(),
            ReqRespCode::HEARTBEAT.0,
        ]
    );
    assert!(sessions.find(session_id).is_some());
}

// KEY_EXCHANGE_RSP HeartbeatPeriod: non-zero only when the feature is on and
// both endpoints set HBEAT_CAP; zero in every other case.
#[test]
fn heartbeat_period_requires_both_caps() {
    use caliptra_mcu_spdm_codec::CapFlags;
    let hbeat = |flags: CapFlags, on: bool| {
        let mask = if on { CapFlags::HBEAT.into_bits() } else { 0 };
        CapFlags::from_bits((flags.into_bits() & !CapFlags::HBEAT.into_bits()) | mask)
    };
    let on = HeartBeatPeriod(crate::heartbeat::DEFAULT_HEARTBEAT_PERIOD_SECS);
    for (ours, peer) in [(true, true), (true, false), (false, true), (false, false)] {
        let mut state = negotiated_state(SpdmVersion::V12);
        state.cap_flags = hbeat(state.cap_flags, ours);
        state.peer_cap_flags = hbeat(state.peer_cap_flags, peer);
        let expected = if cfg!(feature = "spdm-set-heartbeat") && ours && peer {
            on
        } else {
            HeartBeatPeriod::DISABLED
        };
        assert_eq!(
            crate::key_exchange::heartbeat_period_for::<TestPal>(&state),
            expected,
            "ours={ours} peer={peer}"
        );
    }
}

// An authenticated in-session request that draws an ERROR is still session
// traffic (DSP0274 1.4.0 section 10.21): GET_VERSION inside a session is
// rejected with UnexpectedRequest, yet the watchdog deadline moves forward.
#[test]
fn secured_error_response_refreshes_deadline() {
    let pal = TestPal::default();
    let (mut state, mut sessions, session_id) = established_session(&pal);
    {
        let session = sessions.find_mut(session_id).unwrap();
        session.heartbeat_period = HeartBeatPeriod(PERIOD_SECS);
        session.arm_heartbeat(0);
        assert_eq!(session.deadline_ms, Some(WINDOW_MS));
    }

    pal.set_now_ms(1500);
    let inner = vec![state.version.to_u8(), ReqRespCode::GET_VERSION.0, 0, 0];
    let io = secured_io(session_id, &inner);
    let rsp = block_on(handle_secured_request(
        &mut state,
        &mut sessions,
        &pal,
        &io,
        &NoVdmBackend,
    ))
    .expect("secured handler must not fatally error")
    .expect("an ERROR response must be produced");

    assert_eq!(secured_spdm_response(&rsp)[1], ReqRespCode::ERROR.0);
    let session = sessions.find(session_id).unwrap();
    assert_eq!(session.deadline_ms, Some(1500 + WINDOW_MS));
}

// With the feature enabled, the responder advertises HBEAT_CAP.
#[cfg(feature = "spdm-set-heartbeat")]
#[test]
fn responder_advertises_hbeat_cap_when_enabled() {
    use caliptra_mcu_spdm_codec::CapFlags;
    let state = ConnectionState::<TestHashState, Vec<u8>>::caliptra();
    assert!(state.cap_flags.contains(CapFlags::HBEAT));
}

// With the feature disabled, HBEAT_CAP is not advertised (spec-legal
// "heartbeat not supported").
#[cfg(not(feature = "spdm-set-heartbeat"))]
#[test]
fn responder_hides_hbeat_cap_when_disabled() {
    use caliptra_mcu_spdm_codec::CapFlags;
    let state = ConnectionState::<TestHashState, Vec<u8>>::caliptra();
    assert!(!state.cap_flags.contains(CapFlags::HBEAT));
}

// With the feature disabled, a secured HEARTBEAT is answered with
// ERROR(UnsupportedRequest), matching the cleared HBEAT_CAP, not HEARTBEAT_ACK.
#[cfg(not(feature = "spdm-set-heartbeat"))]
#[test]
fn secured_heartbeat_unsupported_when_disabled() {
    let pal = TestPal::default();
    let (mut state, mut sessions, session_id) = established_session(&pal);

    let inner = vec![state.version.to_u8(), ReqRespCode::HEARTBEAT.0, 0, 0];
    let io = secured_io(session_id, &inner);
    let rsp = block_on(handle_secured_request(
        &mut state,
        &mut sessions,
        &pal,
        &io,
        &NoVdmBackend,
    ))
    .expect("secured handler must not fatally error")
    .expect("an ERROR response must be produced");

    assert_eq!(
        secured_spdm_response(&rsp),
        &[
            state.version.to_u8(),
            ReqRespCode::ERROR.0,
            SPDM_UNSUPPORTED_REQUEST.spec_byte(),
            ReqRespCode::HEARTBEAT.0,
        ]
    );
    assert!(sessions.find(session_id).is_some());
}

// Outside a session, HEARTBEAT is SessionRequired with the feature (the command
// is supported, just not here) ...
#[cfg(feature = "spdm-set-heartbeat")]
#[test]
fn plaintext_heartbeat_session_required_when_enabled() {
    let pal = TestPal::default();
    let mut state = negotiated_state(SpdmVersion::V12);
    let mut sessions: Sessions<TestPal, 1> = crate::session::SessionManager::new();
    let io = TestIo::message(vec![
        SpdmVersion::V12.to_u8(),
        ReqRespCode::HEARTBEAT.0,
        0,
        0,
    ]);
    let err = block_on(dispatch(
        &mut state,
        &mut sessions,
        &pal,
        &io,
        ReqRespCode::HEARTBEAT,
        &NoVdmBackend,
    ))
    .unwrap_err();
    assert_eq!(err, SPDM_SESSION_REQUIRED);
}

// ... and UnsupportedRequest without it, since HBEAT_CAP is not advertised.
#[cfg(not(feature = "spdm-set-heartbeat"))]
#[test]
fn plaintext_heartbeat_unsupported_when_disabled() {
    let pal = TestPal::default();
    let mut state = negotiated_state(SpdmVersion::V12);
    let mut sessions: Sessions<TestPal, 1> = crate::session::SessionManager::new();
    let io = TestIo::message(vec![
        SpdmVersion::V12.to_u8(),
        ReqRespCode::HEARTBEAT.0,
        0,
        0,
    ]);
    let err = block_on(dispatch(
        &mut state,
        &mut sessions,
        &pal,
        &io,
        ReqRespCode::HEARTBEAT,
        &NoVdmBackend,
    ))
    .unwrap_err();
    assert_eq!(
        err,
        SPDM_UNSUPPORTED_REQUEST.with_data(ReqRespCode::HEARTBEAT.0)
    );
}

// Without the feature, a HEARTBEAT during the handshake phase is also
// UnsupportedRequest, not the phase gate's UnexpectedRequest.
#[cfg(not(feature = "spdm-set-heartbeat"))]
#[test]
fn handshake_heartbeat_unsupported_when_disabled() {
    let pal = TestPal::default();
    let (mut state, mut sessions, session_id) = handshake_session(&pal);

    let inner = vec![state.version.to_u8(), ReqRespCode::HEARTBEAT.0, 0, 0];
    let io = secured_io(session_id, &inner);
    let rsp = block_on(handle_secured_request(
        &mut state,
        &mut sessions,
        &pal,
        &io,
        &NoVdmBackend,
    ))
    .expect("secured handler must not fatally error")
    .expect("an ERROR response must be produced");

    assert_eq!(
        secured_spdm_response(&rsp),
        &[
            state.version.to_u8(),
            ReqRespCode::ERROR.0,
            SPDM_UNSUPPORTED_REQUEST.spec_byte(),
            ReqRespCode::HEARTBEAT.0,
        ]
    );
}
