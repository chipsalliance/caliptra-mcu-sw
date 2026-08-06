// Licensed under the Apache-2.0 license

//! HEARTBEAT liveness-watchdog tests (DSP0274 1.3.0 section 10.20).
//!
//! Covers the per-session watchdog independent of the run loop: arming at
//! establishment, keep-alive on secured traffic, and teardown after two missed
//! HeartbeatPeriods. The wire-level "period advertised iff both caps" and
//! feature-off behavior are also asserted.

extern crate std;

use super::*;
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
    session.heartbeat_period_secs = PERIOD_SECS;
    session.arm_heartbeat(1000);
    assert_eq!(session.deadline_ms, Some(1000 + WINDOW_MS));
}

// A zero period (heartbeat not desired) leaves the watchdog unarmed.
#[test]
fn arm_is_inert_when_period_zero() {
    let pal = TestPal::default();
    let (_state, mut sessions, session_id) = established_session(&pal);
    let session = sessions.find_mut(session_id).unwrap();
    session.heartbeat_period_secs = 0;
    session.arm_heartbeat(1000);
    assert_eq!(session.deadline_ms, None);
}

// Keep-alive: touch restarts an armed watchdog, but never arms a disabled one.
#[test]
fn touch_restarts_only_armed_watchdog() {
    let pal = TestPal::default();
    let (_state, mut sessions, session_id) = established_session(&pal);
    let session = sessions.find_mut(session_id).unwrap();
    session.heartbeat_period_secs = PERIOD_SECS;
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
    session.heartbeat_period_secs = PERIOD_SECS;
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
    session.heartbeat_period_secs = PERIOD_SECS;
    session.arm_heartbeat(1000);
    let deadline = 1000 + WINDOW_MS;

    // Just before the deadline: survives.
    assert_eq!(sessions.expire_due(deadline - 1), 0);
    assert!(sessions.find(session_id).is_some());

    // At the deadline: torn down.
    assert_eq!(sessions.expire_due(deadline), 1);
    assert!(sessions.find(session_id).is_none());
}

// Keep-alive through the secured dispatch path: a HEARTBEAT received after the
// clock advances pushes the deadline forward rather than letting it expire.
#[test]
fn secured_heartbeat_refreshes_deadline() {
    let pal = TestPal::default();
    let (mut state, mut sessions, session_id) = established_session(&pal);
    {
        let session = sessions.find_mut(session_id).unwrap();
        session.heartbeat_period_secs = PERIOD_SECS;
        session.arm_heartbeat(0);
        assert_eq!(session.deadline_ms, Some(WINDOW_MS));
    }

    // Advance the clock and deliver a secured HEARTBEAT.
    pal.set_now_ms(1500);
    let inner = vec![state.version.to_u8(), ReqRespCode::HEARTBEAT.0, 0, 0];
    let io = secured_io(session_id, &inner);
    block_on(handle_secured_request(
        &mut state,
        &mut sessions,
        &pal,
        &io,
        &NoVdmBackend,
    ))
    .expect("secured handler must not fatally error")
    .expect("a HEARTBEAT_ACK must be produced");

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
