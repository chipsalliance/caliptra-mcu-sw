// Licensed under the Apache-2.0 license
//
// Regression test for the EmulatorState ordering contract.
//
// The per-instance emulator state design (in this crate's lib.rs) requires
// that every thread which calls `is_emulator_running()`, `stop_emulator()`,
// `wait_for_runtime_start()`, etc. has had `init_emulator_state(...)` called
// on it first. Workers normally inherit state via `spawn_with_emulator_state`,
// which captures the parent's state at spawn time and re-installs it in the
// child before the closure runs.
//
// An earlier revision of this code used a process-wide global as a silent
// fallback: any thread without per-instance state would transparently use
// the globals. Producers writing to `self.state.*` and consumers reading
// the globals therefore desynced silently, hanging tests until the nextest
// SLOW-to-TIMEOUT cap fired (~15 min in CI).
//
// The current design replaces that silent fallback with a panic at the
// offending call site, so ordering bugs surface immediately. These tests
// pin that contract:
//
//   1. spawn_with_emulator_state called from a thread WITHOUT state panics
//      at the spawn site (not later in the worker).
//   2. Any free function (is_emulator_running, etc.) called from a thread
//      WITHOUT state panics on first use.
//   3. Workers spawned via spawn_with_emulator_state AFTER init observe
//      the parent's per-instance writes (e.g. running=false propagates).
//
// Each test runs in its own process (cargo test's default for separate
// integration test files), so the thread-local on the test main thread
// starts unset for every test.

use caliptra_mcu_testing_common::{
    init_emulator_state, is_emulator_running, spawn_with_emulator_state, EmulatorState,
};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

/// Spawning a worker before `init_emulator_state` must panic immediately at
/// the spawn site -- the bug that hung PR #1290's test_emulator shards.
#[test]
#[should_panic(expected = "spawn_with_emulator_state called from a thread without per-instance")]
fn spawn_before_init_panics_at_spawn_site() {
    let _ = spawn_with_emulator_state(|| {});
}

/// Calling `is_emulator_running()` (or any other state-touching free fn)
/// on a thread without per-instance state must panic, not silently read
/// stale data from a process-wide global.
#[test]
#[should_panic(expected = "EmulatorState not initialized on this thread")]
fn free_fn_without_init_panics() {
    let _ = is_emulator_running();
}

/// The fix for PR #1290: call `init_emulator_state` BEFORE spawning workers.
/// Workers inherit the same Arc<EmulatorState>, so a per-instance write on
/// the parent (e.g. running=false) propagates to the child within one
/// poll cycle.
#[test]
fn init_before_spawn_propagates_per_instance_state() {
    let state = EmulatorState::new_arc();
    init_emulator_state(state.clone());

    let worker = spawn_with_emulator_state(move || {
        let start = Instant::now();
        while is_emulator_running() {
            if start.elapsed() > Duration::from_secs(2) {
                return "TIMED_OUT_WORKER";
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        "SAW_STOP"
    });

    // Producer writes per-instance running=false. Worker shares the same
    // Arc<EmulatorState>, so its is_emulator_running() returns false on
    // the next poll.
    state.running.store(false, Ordering::Relaxed);

    assert_eq!(
        worker.join().unwrap(),
        "SAW_STOP",
        "Worker spawned after init must observe parent's per-instance write."
    );
}
