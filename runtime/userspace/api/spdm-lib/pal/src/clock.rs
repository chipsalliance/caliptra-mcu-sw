// Licensed under the Apache-2.0 license

//! Monotonic clock for the HEARTBEAT liveness watchdog.
//!
//! Wraps the libtock alarm capsule (driver 0) so [`McuSpdmPal`] can hand the
//! stack a real millisecond clock (`now_ms`) and an async delay (`sleep_ms`).
//! The delay is raced against `recv_request` in the responder run loop, so a
//! silent peer's session is torn down on watchdog expiry.
//!
//! This mirrors the async-alarm pattern already used by `pldm-lib/src/timer.rs`
//! and `mcu-mbox-lib/src/fips_periodic.rs`. It is compiled only when the
//! `spdm-set-heartbeat` feature is enabled.

use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_alarm::{Convert, Hz, Milliseconds};
use caliptra_mcu_libtock_platform::{ErrorCode, Syscalls};
use caliptra_mcu_libtockasync::TockSubscribe;

const DRIVER_NUM: u32 = 0;

mod command {
    pub const FREQUENCY: u32 = 1;
    pub const TIME: u32 = 2;
    pub const SET_RELATIVE: u32 = 5;
}

fn get_frequency() -> Result<u32, ErrorCode> {
    DefaultSyscalls::command(DRIVER_NUM, command::FREQUENCY, 0, 0).to_result()
}

fn get_ticks() -> Result<u32, ErrorCode> {
    DefaultSyscalls::command(DRIVER_NUM, command::TIME, 0, 0).to_result()
}

/// Current value of the free-running monotonic millisecond clock. Returns 0 if
/// the alarm capsule is unavailable, which keeps the watchdog inert rather than
/// tearing sessions down spuriously.
pub(crate) fn now_ms() -> u64 {
    let (Ok(ticks), Ok(freq)) = (get_ticks(), get_frequency()) else {
        return 0;
    };
    if freq == 0 {
        return 0;
    }
    (ticks as u64).saturating_div((freq as u64).saturating_div(1000).max(1))
}

/// Sleep for at least `ms` milliseconds using the alarm capsule.
pub(crate) async fn sleep_ms(ms: u32) {
    let Ok(freq) = get_frequency() else {
        // No clock: fall back to never-resolving so the run loop waits on
        // recv_request alone (the pre-heartbeat behavior).
        core::future::pending::<()>().await;
        return;
    };
    let ticks = Milliseconds(ms).to_ticks(Hz(freq)).0;
    let sub = TockSubscribe::subscribe::<DefaultSyscalls>(DRIVER_NUM, 0);
    if DefaultSyscalls::command(DRIVER_NUM, command::SET_RELATIVE, ticks, 0)
        .to_result::<u32, ErrorCode>()
        .is_err()
    {
        core::future::pending::<()>().await;
        return;
    }
    let _ = sub.await;
}
