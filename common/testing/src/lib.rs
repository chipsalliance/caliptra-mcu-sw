// Licensed under the Apache-2.0 license

//! Common variables and methods to coordinate between tests
//! and the platform.

pub mod i3c;
pub mod i3c_socket;
pub mod i3c_socket_server;
pub mod mctp_transport;
#[macro_use]
pub mod mctp_util;

pub use caliptra_api_types::DeviceLifecycle;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

pub static MCU_RUNTIME_STARTED: AtomicBool = AtomicBool::new(false);
pub static MCU_RUNNING: AtomicBool = AtomicBool::new(true);
pub static MCU_TICKS: AtomicU64 = AtomicU64::new(0);
pub static TICK_NOTIFY_TICKS: u64 = 1000; // wake up every 1000 ticks to check
pub static TICK_LOCK: Mutex<()> = Mutex::new(());
pub static TICK_COND: Condvar = Condvar::new();

// Condition variable for I3C data availability - signaled when socket server writes data
pub static I3C_DATA_COND: Condvar = Condvar::new();

pub fn wait_for_runtime_start() {
    while MCU_RUNNING.load(Ordering::Relaxed) && !MCU_RUNTIME_STARTED.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Sleep for the specified number of emulator ticks.
/// This is deterministic and exact if ticks is a multiple of 1,000, unless
/// the emulator is very slow (<1,000 ticks per second), in which case it
/// the exact number of ticks slept may vary by up to 1,000.
pub fn sleep_emulator_ticks(ticks: u32) {
    let wait = ticks as u64;
    let start = MCU_TICKS.load(Ordering::Relaxed);
    while MCU_RUNNING.load(Ordering::Relaxed) {
        let now = MCU_TICKS.load(Ordering::Relaxed);
        if now - start >= wait {
            break;
        }
        let lock = TICK_LOCK.lock().unwrap();
        let _ = TICK_COND.wait_timeout(lock, Duration::from_secs(1));
    }
}

/// Wait for the specified number of emulator ticks, or until the emulator stops.
/// Returns true if the wait completed successfully, false if the emulator stopped.
pub fn wait_emulator_ticks(ticks: u64) -> bool {
    let start = MCU_TICKS.load(Ordering::Relaxed);
    while MCU_RUNNING.load(Ordering::Relaxed) {
        let now = MCU_TICKS.load(Ordering::Relaxed);
        if now.saturating_sub(start) >= ticks {
            return true;
        }
        let lock = TICK_LOCK.lock().unwrap();
        let _ = TICK_COND.wait_timeout(lock, Duration::from_secs(1));
    }
    false
}

/// Get the current emulator tick count.
pub fn get_emulator_ticks() -> u64 {
    MCU_TICKS.load(Ordering::Relaxed)
}

/// Check if the emulator is still running.
pub fn is_emulator_running() -> bool {
    MCU_RUNNING.load(Ordering::Relaxed)
}

/// Check if a timeout has elapsed based on emulator ticks.
/// Returns true if the timeout has elapsed.
pub fn emulator_ticks_elapsed(start_ticks: u64, timeout_ticks: u64) -> bool {
    let now = MCU_TICKS.load(Ordering::Relaxed);
    now.saturating_sub(start_ticks) >= timeout_ticks
}

pub fn update_ticks(ticks: u64) {
    MCU_TICKS.store(ticks, Ordering::Relaxed);
    TICK_COND.notify_all();
}

/// Notify that I3C data is available. Called by the I3C socket server when
/// it writes data to the socket.
pub fn notify_i3c_data() {
    I3C_DATA_COND.notify_all();
}

/// Wait for I3C data to become available, with optional timeout based on emulator ticks.
/// Returns WaitResult indicating why the wait ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitResult {
    /// Data notification was received (check if data is actually available)
    DataNotified,
    /// Timeout expired (only when timeout_ticks is Some)
    Timeout,
    /// Emulator stopped running
    EmulatorStopped,
}

/// Wait for I3C data notification or timeout.
/// - If `timeout_ticks` is `Some(n)`, waits up to n emulator ticks then returns `Timeout`.
/// - If `timeout_ticks` is `None`, waits indefinitely for data notification.
/// - Returns immediately if emulator stops running.
pub fn wait_for_i3c_data(timeout_ticks: Option<u64>) -> WaitResult {
    let start = MCU_TICKS.load(Ordering::Relaxed);

    // Check if emulator is still running
    if !MCU_RUNNING.load(Ordering::Relaxed) {
        return WaitResult::EmulatorStopped;
    }

    // Check timeout if specified
    if let Some(timeout) = timeout_ticks {
        let now = MCU_TICKS.load(Ordering::Relaxed);
        if now.saturating_sub(start) >= timeout {
            return WaitResult::Timeout;
        }
    }

    // Wait on I3C data notification with a short wall-clock timeout
    // This handles the case where we might miss a notification
    let lock = TICK_LOCK.lock().unwrap();
    let _ = I3C_DATA_COND.wait_timeout(lock, Duration::from_millis(10));

    // After waking up, return to let caller check for data
    // The caller will call us again if no data is available
    WaitResult::DataNotified
}
