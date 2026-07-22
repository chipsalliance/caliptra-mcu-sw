// Licensed under the Apache-2.0 license.

//! Test to demonstrate the VirtualMuxAlarm set_alarm() race condition
//! with stale next_tick_vals.

use caliptra_mcu_romtime::println;
use caliptra_mcu_tock_veer::timers::InternalTimers;
use kernel::hil::time::{Alarm, Time};

/// Reproduce the VirtualMuxAlarm set_alarm() race condition.
///
/// Strategy:
/// - Create a scenario where:
///   (a) One VirtualMuxAlarm (simulating MCU_MBOX) sets a SHORT alarm (dt=1000)
///   (b) That alarm expires (mitcnt0 >= mitb0) but MuxAlarm::alarm() is NOT called
///   (c) A second VirtualMuxAlarm (simulating Mailbox) calls set_alarm() with enabled > 0
///   (d) Guard 2 sees stale next_tick_vals and skips mux.set_alarm()
///   (e) The second alarm never fires → demonstrates the bug
///
/// Expected: exit 0 when fix is applied (hardware reprogrammed correctly).
///           exit 1 on unfixed code (hardware NOT reprogrammed — bug present).
pub(crate) fn run_test_alarm_race_condition() -> Option<u32> {
    use caliptra_mcu_virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
    use core::ptr::addr_of;
    use kernel::hil::time::Alarm as AlarmTrait;
    use kernel::static_init;

    println!("[test-alarm-race] Starting...");
    println!("[test-alarm-race] This test demonstrates stale next_tick_vals in VirtualMuxAlarm");

    // Get the timer hardware from the static
    let timers: &'static InternalTimers<'static> =
        unsafe { &*addr_of!(caliptra_mcu_tock_veer::chip::TIMERS) };

    // Create a fresh MuxAlarm and two VirtualMuxAlarms for this test
    let mux_alarm = unsafe {
        static_init!(
            MuxAlarm<'static, InternalTimers<'static>>,
            MuxAlarm::new(timers)
        )
    };
    timers.set_alarm_client(mux_alarm);

    let va1 = unsafe {
        static_init!(
            VirtualMuxAlarm<'static, InternalTimers<'static>>,
            VirtualMuxAlarm::new(mux_alarm)
        )
    };
    va1.setup();

    let va2 = unsafe {
        static_init!(
            VirtualMuxAlarm<'static, InternalTimers<'static>>,
            VirtualMuxAlarm::new(mux_alarm)
        )
    };
    va2.setup();

    println!("[test-alarm-race] Created MuxAlarm + 2 VirtualMuxAlarms");

    // Step 1: VA1 sets a SHORT alarm (simulating MCU_MBOX's schedule_send_done)
    let now = timers.now();
    let short_dt = 1000u64.into();
    println!(
        "[test-alarm-race] Step 1: VA1 sets alarm (now={}, dt=1000)",
        now.into_u64()
    );
    va1.set_alarm(now, short_dt);
    println!(
        "[test-alarm-race] VA1 armed={}, timer enabled={}",
        va1.is_armed(),
        timers.is_armed()
    );

    // Step 2: Wait for the hardware timer to expire (spin without calling
    // service_pending_interrupts — simulates kernel busy in syscall handler)
    println!("[test-alarm-race] Step 2: Waiting for timer to expire in hardware...");
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
        if spin_count > 10_000_000 {
            println!("[test-alarm-race] FAIL: timer never expired");
            return Some(1);
        }
    }
    println!(
        "[test-alarm-race] Timer expired: mitcnt0={} >= mitb0={} (after {} spins)",
        mitcnt0, mitb0, spin_count
    );

    // CRITICAL: We do NOT call mux_alarm.alarm() here.
    // VA1 is still armed=true, enabled=1, next_tick_vals stale.

    // Step 3: VA2 tries to set an alarm (simulating Mailbox's execute())
    let now2 = timers.now();
    let long_dt = 100_000u64.into();
    println!(
        "[test-alarm-race] Step 3: VA2 sets alarm (now={}, dt=100000) with VA1 still 'armed'",
        now2.into_u64()
    );
    va2.set_alarm(now2, long_dt);
    println!("[test-alarm-race] VA2 armed={}", va2.is_armed());

    // Step 4: Check if hardware was reprogrammed for VA2
    let mitcnt0_after: u32;
    let mitb0_after: u32;
    let mitctl0_after: u32;
    unsafe {
        core::arch::asm!("csrr {}, 0x7D2", out(reg) mitcnt0_after);
        core::arch::asm!("csrr {}, 0x7D3", out(reg) mitb0_after);
        core::arch::asm!("csrr {}, 0x7D4", out(reg) mitctl0_after);
    }
    println!(
        "[test-alarm-race] After VA2 set_alarm: mitcnt0={}, mitb0={}, mitctl0={}",
        mitcnt0_after, mitb0_after, mitctl0_after
    );

    let hardware_was_reprogrammed = mitb0_after > 1000 || mitcnt0_after < mitb0_after;

    if !hardware_was_reprogrammed {
        println!("[test-alarm-race] FAIL: Hardware NOT reprogrammed for VA2!");
        println!("[test-alarm-race] Stale next_tick_vals caused set_alarm() guards to skip.");
        Some(1)
    } else {
        println!(
            "[test-alarm-race] PASS: Hardware WAS reprogrammed (mitb0={}). Alarm works correctly.",
            mitb0_after
        );
        Some(0)
    }
}
