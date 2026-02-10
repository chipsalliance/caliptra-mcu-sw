// Licensed under the Apache-2.0 license

//! System/timing utilities

use crate::ffi;
use core::time::Duration;

pub fn check_timeouts() {
    unsafe {
        ffi::sys_check_timeouts();
    }
}

pub fn timeouts_sleeptime() -> Duration {
    let ms = unsafe { ffi::sys_timeouts_sleeptime() };
    Duration::from_millis(ms as u64)
}
