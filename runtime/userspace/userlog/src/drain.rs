// Licensed under the Apache-2.0 license

//! Async task that ships staged defmt frames to the flash log capsule.
//!
//! The logger runs in a critical section and only stages frames; this task pops
//! them one at a time and appends each as a flash log entry.

use crate::logger::RING;
use crate::FRAME_MAX;
use caliptra_mcu_libsyscall_caliptra::logging::LoggingSyscall;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;

/// Signalled by the logger after each frame is staged.
pub(crate) static WAKE: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// Drains staged defmt frames into the flash log. Spawn this once from the
/// userspace app's executor. Parks immediately if no logging-flash capsule is
/// present (e.g. host fake-kernel unit tests).
#[embassy_executor::task]
pub async fn drain_task() {
    let log = LoggingSyscall::<DefaultSyscalls>::default();
    if log.exists().is_err() {
        return;
    }
    let mut frame = [0u8; FRAME_MAX];
    loop {
        WAKE.wait().await;
        while let Some(n) = RING.pop_frame(&mut frame) {
            // Best-effort: drop a frame that fails to append rather than stall.
            let _ = log.append_entry(&frame[..n]).await;
        }
    }
}
