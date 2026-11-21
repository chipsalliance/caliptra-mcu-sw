// Licensed under the Apache-2.0 license

//! Clock and delay for the HEARTBEAT liveness watchdog.
//!
//! `now_ms` is the libtock alarm capsule's (driver 0) free-running tick count
//! converted to milliseconds.
//!
//! `sleep_ms` arms the same alarm to wake the run loop at the nearest
//! deadline. The run loop races it against `recv_request`, and it usually
//! loses, so it is cancellation-safe: dropping it before the alarm fires stops
//! the alarm, unsubscribes the upcall (the kernel also discards a queued upcall
//! on unsubscribe) and cancels the `TockSubscribe`, so nothing panics and the
//! kernel keeps no pointer to the freed subscription. A mutex serializes the
//! SPDM responder tasks, which share the process's one alarm.
//!
//! The wake can come early or late. The run loop re-reads `now_ms` on every
//! wake and re-arms for the time left, and it also reaps expired sessions
//! whenever a request arrives.
//!
//! Compiled only when the `spdm-set-heartbeat` feature is enabled.

use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_alarm::Alarm;
use caliptra_mcu_libtock_platform::{ErrorCode, Syscalls};
use caliptra_mcu_libtockasync::TockSubscribe;
use core::ops::DerefMut;
use core::pin::Pin;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;

/// libtock alarm driver, plus the two commands `sleep_ms` needs that the
/// `Alarm` API does not expose.
const DRIVER_NUM: u32 = 0;
const SUBSCRIBE_CALLBACK: u32 = 0;
mod command {
    pub const STOP: u32 = 3;
    pub const SET_RELATIVE: u32 = 5;
}

/// One alarm per process: serializes `sleep_ms` across the SPDM responder
/// tasks (one per transport), each of which runs its own stack and PAL.
/// It does not cover other alarm users in the same process: the pldm-lib
/// timer and mcu-mbox-lib `fips_periodic` each hold their own private mutex.
static ALARM_MUTEX: Mutex<CriticalSectionRawMutex, ()> = Mutex::new(());

/// Current value of the free-running monotonic millisecond clock. Returns 0 if
/// the alarm capsule is unavailable, which keeps the watchdog inert rather than
/// tearing sessions down spuriously.
pub(crate) fn now_ms() -> u64 {
    let (Ok(ticks), Ok(freq)) = (
        Alarm::<DefaultSyscalls>::get_ticks(),
        Alarm::<DefaultSyscalls>::get_frequency(),
    ) else {
        return 0;
    };
    if freq.0 == 0 {
        return 0;
    }
    (ticks as u64).saturating_div((freq.0 as u64).saturating_div(1000).max(1))
}

/// An armed alarm subscription. If it is dropped before the upcall arrives (the
/// run loop dropped the sleep because a request came first), it stops the
/// alarm, unsubscribes, and cancels the future so `TockSubscribe`'s drop check
/// does not panic.
struct ArmedAlarm<P: DerefMut<Target = TockSubscribe> + Unpin> {
    sub: Pin<P>,
    done: bool,
}

impl<P: DerefMut<Target = TockSubscribe> + Unpin> Drop for ArmedAlarm<P> {
    fn drop(&mut self) {
        if !self.done {
            let _ = DefaultSyscalls::command(DRIVER_NUM, command::STOP, 0, 0);
            DefaultSyscalls::unsubscribe(DRIVER_NUM, SUBSCRIBE_CALLBACK);
            self.sub.as_mut().get_mut().cancel();
        }
    }
}

/// Alarm ticks for `ms` milliseconds at `freq_hz`, rounded up. The multiply is
/// done in u64: libtock's `Milliseconds::to_ticks` saturates `ms * freq` in
/// u32, which caps a sleep at about 214 ms at 20 MHz. Only the final count is
/// clamped to `u32::MAX` (about 214 s at 20 MHz).
fn ms_to_ticks(ms: u32, freq_hz: u32) -> u32 {
    u32::try_from((u64::from(ms) * u64::from(freq_hz)).div_ceil(1000)).unwrap_or(u32::MAX)
}

/// Sleep for about `ms` alarm milliseconds (the alarm can run early or late;
/// see the module doc). Safe to drop at any await point.
/// If the alarm is unavailable or rejects the request, this never resolves. It
/// does not return early, because the run loop would then re-arm in a tight
/// loop without yielding.
pub(crate) async fn sleep_ms(ms: u32) {
    let guard = ALARM_MUTEX.lock().await;
    let Ok(freq) = Alarm::<DefaultSyscalls>::get_frequency() else {
        drop(guard);
        core::future::pending::<()>().await;
        return;
    };
    let ticks = ms_to_ticks(ms, freq.0);
    let mut armed = ArmedAlarm {
        sub: TockSubscribe::subscribe::<DefaultSyscalls>(DRIVER_NUM, SUBSCRIBE_CALLBACK),
        done: false,
    };
    let armed_ok = DefaultSyscalls::command(DRIVER_NUM, command::SET_RELATIVE, ticks, 0)
        .to_result::<u32, ErrorCode>()
        .is_ok();
    let fired = armed_ok && (&mut armed.sub).await.is_ok();
    armed.done = fired;
    drop(armed);
    drop(guard);
    if !fired {
        core::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests {
    use super::ms_to_ticks;

    #[test]
    fn ms_to_ticks_does_not_saturate_at_fpga_rate() {
        // 20 MHz (FPGA): the u32 product would cap at ~214 ms of ticks.
        assert_eq!(ms_to_ticks(6_000, 20_000_000), 120_000_000);
        assert_eq!(ms_to_ticks(30_000, 20_000_000), 600_000_000);
        // 1 MHz (emulator) and round-up of a partial tick.
        assert_eq!(ms_to_ticks(30_000, 1_000_000), 30_000_000);
        assert_eq!(ms_to_ticks(1, 1_500), 2);
        // Only the final count is clamped.
        assert_eq!(ms_to_ticks(u32::MAX, 20_000_000), u32::MAX);
        assert_eq!(ms_to_ticks(0, 20_000_000), 0);
    }
}
