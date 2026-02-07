// Licensed under the Apache-2.0 license

//! System/timing utilities

use crate::ffi;
use core::time::Duration;

/// Check and process lwIP timeouts
pub fn check_timeouts() {
    unsafe {
        ffi::sys_check_timeouts();
    }
}

/// Get time until next timeout
pub fn timeouts_sleeptime() -> Duration {
    let ms = unsafe { ffi::sys_timeouts_sleeptime() };
    Duration::from_millis(ms as u64)
}
