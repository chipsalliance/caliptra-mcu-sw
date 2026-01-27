// Licensed under the Apache-2.0 license

//! Common variables and methods to coordinate between tests
//! and the platform.

pub mod i3c;
pub mod i3c_socket;
pub mod i3c_socket_server;
pub mod mctp_transport;
pub mod mctp_vdm_transport;
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

pub fn update_ticks(ticks: u64) {
    MCU_TICKS.store(ticks, Ordering::Relaxed);
    TICK_COND.notify_all();
}
