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
use caliptra_mcu_libtock_alarm::{Alarm, Convert, Milliseconds};
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

/// Sleep for at least `ms` alarm milliseconds. Safe to drop at any await point.
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
    let ticks = Milliseconds(ms).to_ticks(freq).0;
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
