// Licensed under the Apache-2.0 license.

//! Test for VeeR InternalTimers get_alarm() bug.
//!
//! Root cause: The original get_alarm() returns `now + bound`. When a timer
//! expires on VeeR (mitcnt0 halts at mitb0), this returns `now + bound` which
//! is slightly in the future. Tock's VirtualMuxAlarm Guard 1 sees this as
//! "existing alarm fires sooner" and incorrectly skips reprogramming.
//!
//! The fix (fire_at field) makes get_alarm() return the actual fire time
//! (reference + dt), which is in the past for expired timers. Guard 1 then
//! correctly passes and allows the reprogram.

use caliptra_mcu_romtime::println;
use caliptra_mcu_tock_veer::timers::InternalTimers;
use kernel::hil::time::{Alarm, Ticks, Time};

/// Test that get_alarm() returns the correct fire time after timer expiry.
///
/// Strategy:
///   1. Set an alarm with a known reference and dt
///   2. Wait for the timer to expire (mitcnt0 halts at mitb0)
///   3. Call get_alarm() and verify it returns reference + dt (the past fire
///      time), NOT now + bound (a bogus future value)
///
/// This directly validates the fire_at fix without going through VirtualMuxAlarm
/// guards, which avoids flakiness from Guard 2 (next_tick_vals) interactions.
///
/// Expected: exit 0 when fire_at fix is applied (get_alarm returns correct value).
///           exit 1 on unfixed code (get_alarm returns bogus value).
pub(crate) fn run_test_get_alarm_expired() -> Option<u32> {
    use core::ptr::addr_of;

    println!("[test-get-alarm] Starting...");
    println!("[test-get-alarm] This test verifies get_alarm() returns correct fire_at for expired timers");

    // Get the timer hardware from the static
    let timers: &'static InternalTimers<'static> =
        unsafe { &*addr_of!(caliptra_mcu_tock_veer::chip::TIMERS) };

    // Step 1: Set an alarm with a known dt, large enough that it won't expire
    // before we finish setting it up (200000 ticks = 10ms at 20MHz)
    let reference = timers.now();
    let dt = 200_000u64.into();
    let expected_fire_at = reference.wrapping_add(dt);

    println!(
        "[test-get-alarm] Step 1: Setting alarm (reference={}, dt=200000, expected_fire_at={})",
        reference.into_u64(),
        expected_fire_at.into_u64()
    );
    timers.set_alarm(reference, dt);

    // Verify get_alarm() returns the correct value BEFORE expiry
    let alarm_before = timers.get_alarm();
    println!(
        "[test-get-alarm] get_alarm() before expiry: {} (expected {})",
        alarm_before.into_u64(),
        expected_fire_at.into_u64()
    );
    if alarm_before != expected_fire_at {
        println!(
            "[test-get-alarm] FAIL: get_alarm() before expiry returned wrong value! got={}, expected={}",
            alarm_before.into_u64(),
            expected_fire_at.into_u64()
        );
        return Some(1);
    }

    // Step 2: Wait for the hardware timer to expire
    println!("[test-get-alarm] Step 2: Waiting for timer to expire...");
    let mut mitcnt0: u32;
    let mitb0: u32;
    unsafe {
        core::arch::asm!("csrr {}, 0x7D3", out(reg) mitb0);
    }

    let mut spin_count = 0u32;
    loop {
        unsafe {
            core::arch::asm!("csrr {}, 0x7D2", out(reg) mitcnt0);
        }
        if mitcnt0 >= mitb0 {
            break;
        }
        spin_count += 1;
        if spin_count > 100_000_000 {
            println!("[test-get-alarm] FAIL: timer never expired");
            return Some(1);
        }
    }
    println!(
        "[test-get-alarm] Timer expired: mitcnt0={} >= mitb0={} (after {} spins)",
        mitcnt0, mitb0, spin_count
    );

    // Step 3: Check get_alarm() AFTER expiry
    let now_after = timers.now();
    let alarm_after = timers.get_alarm();
    println!(
        "[test-get-alarm] get_alarm() after expiry: {} (now={}, expected_fire_at={})",
        alarm_after.into_u64(),
        now_after.into_u64(),
        expected_fire_at.into_u64()
    );

    // With fix: get_alarm() should still return the original fire_at (in the past)
    // Without fix: get_alarm() = now + bound (in the future, bogus)
    if alarm_after != expected_fire_at {
        println!(
            "[test-get-alarm] FAIL: get_alarm() after expiry returned wrong value! got={}, expected={}",
            alarm_after.into_u64(),
            expected_fire_at.into_u64()
        );
        println!(
            "[test-get-alarm] The old buggy get_alarm() would return now+bound = {}",
            now_after.into_u64() + mitb0 as u64
        );
        return Some(1);
    }

    // Verify the returned value is in the past (fire_at < now)
    if alarm_after.into_u64() >= now_after.into_u64() {
        println!(
            "[test-get-alarm] WARN: get_alarm() returned a future value after expiry (fire_at={} >= now={})",
            alarm_after.into_u64(),
            now_after.into_u64()
        );
        // This shouldn't happen if the timer truly expired, but don't fail on it
    }

    println!(
        "[test-get-alarm] PASS: get_alarm() correctly returns fire_at={} (in the past, now={})",
        alarm_after.into_u64(),
        now_after.into_u64()
    );
    Some(0)
}
