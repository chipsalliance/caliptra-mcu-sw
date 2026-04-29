// Licensed under the Apache-2.0 license

//! Common variables and methods to coordinate between tests
//! and the platform.

pub mod doe_util;
pub mod i3c;
pub mod i3c_socket;
pub mod i3c_socket_server;
pub mod mctp_transport;
pub mod mctp_vdm_transport;
#[macro_use]
pub mod mctp_util;
pub mod spdm_responder_validator;

pub use caliptra_api_types::DeviceLifecycle;
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Process-wide default globals (single-instance backward compatibility)
// ---------------------------------------------------------------------------

pub static MCU_RUNTIME_STARTED: AtomicBool = AtomicBool::new(false);
pub static MCU_RUNNING: AtomicBool = AtomicBool::new(true);
pub static MCU_TICKS: AtomicU64 = AtomicU64::new(0);
pub static TICK_NOTIFY_TICKS: u64 = 1000; // wake up every 1000 ticks to check
pub static TICK_LOCK: Mutex<()> = Mutex::new(());
pub static TICK_COND: Condvar = Condvar::new();

// ---------------------------------------------------------------------------
// Per-instance emulator state (multi-instance support)
// ---------------------------------------------------------------------------

/// Per-instance emulator state. When multiple emulator instances run in the
/// same process, each instance gets its own state so
/// that stopping one does not stop the other.
///
/// Threads that belong to a specific instance call `init_emulator_state()`
/// at startup. The free functions (`sleep_emulator_ticks`, etc.) then
/// transparently use the per-instance state with no signature changes.
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
/// After this call, the free functions (`sleep_emulator_ticks`, etc.) will
/// use this instance's state instead of the process-wide globals.
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
/// state. The child thread's thread-local will be set before `f` runs.
pub fn spawn_with_emulator_state<F, T>(f: F) -> std::thread::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let state = get_emulator_state();
    std::thread::spawn(move || {
        if let Some(s) = state {
            init_emulator_state(s);
        }
        f()
    })
}

/// Execute `f` with the per-instance state if set, otherwise use the globals.
fn with_state<F, R>(f: F) -> R
where
    F: FnOnce(&AtomicBool, &AtomicBool, &AtomicU64, &Mutex<()>, &Condvar) -> R,
{
    CURRENT_EMULATOR_STATE.with(|cell| {
        let borrow = cell.borrow();
        if let Some(ref state) = *borrow {
            f(
                &state.running,
                &state.runtime_started,
                &state.ticks,
                &state.tick_lock,
                &state.tick_cond,
            )
        } else {
            f(
                &MCU_RUNNING,
                &MCU_RUNTIME_STARTED,
                &MCU_TICKS,
                &TICK_LOCK,
                &TICK_COND,
            )
        }
    })
}

// ---------------------------------------------------------------------------
// Free functions (unchanged signatures, now thread-local-aware)
// ---------------------------------------------------------------------------

pub fn wait_for_runtime_start() {
    with_state(|running, runtime_started, _ticks, _lock, _cond| {
        while running.load(Ordering::Relaxed) && !runtime_started.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(10));
        }
    });
}

/// Sleep for the specified number of emulator ticks.
/// This is deterministic and exact if ticks is a multiple of 1,000, unless
/// the emulator is very slow (<1,000 ticks per second), in which case it
/// the exact number of ticks slept may vary by up to 1,000.
pub fn sleep_emulator_ticks(ticks: u32) {
    with_state(
        |running, _runtime_started, mcu_ticks, tick_lock, tick_cond| {
            let wait = ticks as u64;
            let start = mcu_ticks.load(Ordering::Relaxed);
            while running.load(Ordering::Relaxed) {
                let now = mcu_ticks.load(Ordering::Relaxed);
                if now - start >= wait {
                    break;
                }
                let lock = tick_lock.lock().unwrap();
                let _ = tick_cond.wait_timeout(lock, Duration::from_secs(1));
            }
        },
    );
}

/// Wait for the specified number of emulator ticks, or until the emulator stops.
/// Returns true if the wait completed successfully, false if the emulator stopped.
pub fn wait_emulator_ticks(ticks: u64) -> bool {
    with_state(
        |running, _runtime_started, mcu_ticks, tick_lock, tick_cond| {
            let start = mcu_ticks.load(Ordering::Relaxed);
            while running.load(Ordering::Relaxed) {
                let now = mcu_ticks.load(Ordering::Relaxed);
                if now.saturating_sub(start) >= ticks {
                    return true;
                }
                let lock = tick_lock.lock().unwrap();
                let _ = tick_cond.wait_timeout(lock, Duration::from_secs(1));
            }
            false
        },
    )
}

/// Get the current emulator tick count.
pub fn get_emulator_ticks() -> u64 {
    with_state(|_running, _runtime_started, mcu_ticks, _lock, _cond| {
        mcu_ticks.load(Ordering::Relaxed)
    })
}

/// Check if the emulator is still running.
pub fn is_emulator_running() -> bool {
    with_state(|running, _runtime_started, _ticks, _lock, _cond| running.load(Ordering::Relaxed))
}

/// Signal the emulator to stop. Uses per-instance state if set, otherwise
/// the process-wide global.
pub fn stop_emulator() {
    with_state(|running, _runtime_started, _ticks, _lock, _cond| {
        running.store(false, Ordering::Relaxed)
    });
}

/// Set the emulator running flag. Uses per-instance state if set, otherwise
/// the process-wide global. Typically called with `true` to reset state
/// between tests.
pub fn set_emulator_running(val: bool) {
    with_state(|running, _runtime_started, _ticks, _lock, _cond| {
        running.store(val, Ordering::Relaxed)
    });
}

/// Set the runtime-started flag. Uses per-instance state if set, otherwise
/// the process-wide global.
pub fn set_runtime_started(val: bool) {
    with_state(|_running, runtime_started, _ticks, _lock, _cond| {
        runtime_started.store(val, Ordering::Relaxed)
    });
}

/// Check if a timeout has elapsed based on emulator ticks.
/// Returns true if the timeout has elapsed.
pub fn emulator_ticks_elapsed(start_ticks: u64, timeout_ticks: u64) -> bool {
    with_state(|_running, _runtime_started, mcu_ticks, _lock, _cond| {
        let now = mcu_ticks.load(Ordering::Relaxed);
        now.saturating_sub(start_ticks) >= timeout_ticks
    })
}

pub fn update_ticks(ticks: u64) {
    with_state(|_running, _runtime_started, mcu_ticks, _lock, tick_cond| {
        mcu_ticks.store(ticks, Ordering::Relaxed);
        tick_cond.notify_all();
    });
}
