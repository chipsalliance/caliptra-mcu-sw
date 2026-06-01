// Licensed under the Apache-2.0 license

//! Per-instance emulator coordination state.
//!
//! Lives in its own crate so both the test-harness crate
//! (`caliptra-mcu-testing-common`) and the PLDM user-agent crate
//! (`caliptra-mcu-pldm-ua`) can depend on it without creating a Cargo
//! dependency cycle.

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// Tick-notify quantum. Producers (emulator step loops) call
/// `update_ticks()` every `TICK_NOTIFY_TICKS` cycles to wake consumers.
pub const TICK_NOTIFY_TICKS: u64 = 1000;

// ---------------------------------------------------------------------------
// Per-instance emulator state
// ---------------------------------------------------------------------------

/// Per-instance emulator coordination state. Each emulator instance owns
/// one `Arc<EmulatorState>` and stores its clone in the current thread's
/// thread-local via `init_emulator_state()`. Worker threads must be spawned
/// via `spawn_with_emulator_state()` so the parent's state is propagated.
///
/// There is no process-wide fallback: free functions like
/// `is_emulator_running()` panic if called from a thread without an
/// initialized state, so ordering bugs surface immediately instead of as
/// silent deadlocks.
pub struct EmulatorState {
    pub running: AtomicBool,
    pub runtime_started: AtomicBool,
    pub ticks: AtomicU64,
    pub tick_lock: Mutex<()>,
    pub tick_cond: Condvar,
}

impl EmulatorState {
    pub fn new() -> Self {
        Self {
            running: AtomicBool::new(true),
            runtime_started: AtomicBool::new(false),
            ticks: AtomicU64::new(0),
            tick_lock: Mutex::new(()),
            tick_cond: Condvar::new(),
        }
    }

    pub fn new_arc() -> Arc<Self> {
        Arc::new(Self::new())
    }
}

impl Default for EmulatorState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Thread-local per-instance state
// ---------------------------------------------------------------------------

thread_local! {
    static CURRENT_EMULATOR_STATE: RefCell<Option<Arc<EmulatorState>>> = const { RefCell::new(None) };
}

/// Set the per-instance emulator state for the current thread. Call this at
/// thread startup for any thread that belongs to a specific emulator instance.
/// After this call, the free functions (`sleep_emulator_ticks`, etc.) read
/// and write this instance's state.
pub fn init_emulator_state(state: Arc<EmulatorState>) {
    CURRENT_EMULATOR_STATE.with(|cell| {
        *cell.borrow_mut() = Some(state);
    });
}

/// Returns a clone of the current thread's per-instance state, if set.
/// Use this to propagate state to spawned child threads.
pub fn get_emulator_state() -> Option<Arc<EmulatorState>> {
    CURRENT_EMULATOR_STATE.with(|cell| cell.borrow().clone())
}

/// Spawn a thread that inherits the current thread's per-instance emulator
/// state. The child thread's thread-local is set before `f` runs.
///
/// Panics if the calling thread has not called `init_emulator_state()`.
/// This catches ordering bugs at the spawn site rather than letting the
/// child silently desync from the parent.
#[track_caller]
pub fn spawn_with_emulator_state<F, T>(f: F) -> std::thread::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let state = get_emulator_state().expect(
        "spawn_with_emulator_state called from a thread without per-instance \
         emulator state. Call init_emulator_state(...) on this thread first \
         (typically inside Emulator::from_args or McuHwModel::new_unbooted).",
    );
    std::thread::spawn(move || {
        init_emulator_state(state);
        f()
    })
}

/// Execute `f` with the current thread's per-instance state. Panics if no
/// state has been initialized on this thread.
fn with_state<F, R>(f: F) -> R
where
    F: FnOnce(&EmulatorState) -> R,
{
    CURRENT_EMULATOR_STATE.with(|cell| {
        let borrow = cell.borrow();
        let state = borrow.as_ref().expect(
            "EmulatorState not initialized on this thread. Call \
             init_emulator_state(...) on the main thread before any \
             spawn_with_emulator_state(...), or use spawn_with_emulator_state \
             so workers inherit state.",
        );
        f(state)
    })
}

// ---------------------------------------------------------------------------
// Free functions (per-instance only; no process-wide fallback)
// ---------------------------------------------------------------------------

pub fn wait_for_runtime_start() {
    with_state(|state| {
        while state.running.load(Ordering::Relaxed)
            && !state.runtime_started.load(Ordering::Relaxed)
        {
            std::thread::sleep(Duration::from_millis(10));
        }
    });
}

/// Sleep for the specified number of emulator ticks.
/// This is deterministic and exact if ticks is a multiple of 1,000, unless
/// the emulator is very slow (<1,000 ticks per second), in which case
/// the exact number of ticks slept may vary by up to 1,000.
pub fn sleep_emulator_ticks(ticks: u32) {
    with_state(|state| {
        let wait = ticks as u64;
        let start = state.ticks.load(Ordering::Relaxed);
        while state.running.load(Ordering::Relaxed) {
            let now = state.ticks.load(Ordering::Relaxed);
            if now - start >= wait {
                break;
            }
            let lock = state.tick_lock.lock().unwrap();
            let _ = state.tick_cond.wait_timeout(lock, Duration::from_secs(1));
        }
    });
}

/// Wait for the specified number of emulator ticks, or until the emulator stops.
/// Returns true if the wait completed successfully, false if the emulator stopped.
pub fn wait_emulator_ticks(ticks: u64) -> bool {
    with_state(|state| {
        let start = state.ticks.load(Ordering::Relaxed);
        while state.running.load(Ordering::Relaxed) {
            let now = state.ticks.load(Ordering::Relaxed);
            if now.saturating_sub(start) >= ticks {
                return true;
            }
            let lock = state.tick_lock.lock().unwrap();
            let _ = state.tick_cond.wait_timeout(lock, Duration::from_secs(1));
        }
        false
    })
}

/// Get the current emulator tick count.
pub fn get_emulator_ticks() -> u64 {
    with_state(|state| state.ticks.load(Ordering::Relaxed))
}

/// Check if the emulator is still running.
pub fn is_emulator_running() -> bool {
    with_state(|state| state.running.load(Ordering::Relaxed))
}

/// Signal the current thread's emulator to stop.
pub fn stop_emulator() {
    with_state(|state| state.running.store(false, Ordering::Relaxed));
}

/// Set the emulator running flag. Typically called with `true` to reset state
/// between tests.
pub fn set_emulator_running(val: bool) {
    with_state(|state| state.running.store(val, Ordering::Relaxed));
}

/// Set the runtime-started flag.
pub fn set_runtime_started(val: bool) {
    with_state(|state| state.runtime_started.store(val, Ordering::Relaxed));
}

/// Check if a timeout has elapsed based on emulator ticks.
/// Returns true if the timeout has elapsed.
pub fn emulator_ticks_elapsed(start_ticks: u64, timeout_ticks: u64) -> bool {
    with_state(|state| {
        let now = state.ticks.load(Ordering::Relaxed);
        now.saturating_sub(start_ticks) >= timeout_ticks
    })
}

pub fn update_ticks(ticks: u64) {
    with_state(|state| {
        state.ticks.store(ticks, Ordering::Relaxed);
        state.tick_cond.notify_all();
    });
}
