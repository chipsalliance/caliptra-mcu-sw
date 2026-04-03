// Licensed under the Apache-2.0 license

//! Periodic FIPS self-test module.
//!
//! This module provides functionality to run FIPS self-tests periodically
//! in the background. It can be enabled/disabled via MCU mailbox commands.

use caliptra_api::mailbox::CommandId as CaliptraCommandId;
use core::fmt::Write;
use core::sync::atomic::{AtomicU32, Ordering};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_sync::signal::Signal;
use libapi_caliptra::mailbox_api::execute_mailbox_cmd;
use libsyscall_caliptra::mailbox::Mailbox;
use libsyscall_caliptra::DefaultSyscalls;
use libtock_alarm::{Convert, Hz, Milliseconds};
use libtock_console::Console;
use libtock_platform::Syscalls;
use libtockasync::TockSubscribe;

/// Periodic FIPS self-test interval in milliseconds.
/// Default: 60 seconds (60000 ms)
pub const FIPS_PERIODIC_INTERVAL_MS: u32 = 60_000;

/// Result status values
pub const RESULT_NOT_RUN: u32 = 0;
pub const RESULT_PASS: u32 = 1;
pub const RESULT_FAIL: u32 = 2;

/// Global state for periodic FIPS self-test
static ENABLED: AtomicU32 = AtomicU32::new(0);
static ITERATIONS: AtomicU32 = AtomicU32::new(0);
static LAST_RESULT: AtomicU32 = AtomicU32::new(RESULT_NOT_RUN);

/// Signal to wake up the periodic task when state changes
static STATE_CHANGED: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// Mutex for alarm access
static ALARM_MUTEX: Mutex<CriticalSectionRawMutex, ()> = Mutex::new(());

/// Driver number for alarm
const DRIVER_NUM: u32 = 0;

/// Command IDs for alarm
mod command {
    pub const FREQUENCY: u32 = 1;
    pub const SET_RELATIVE: u32 = 5;
}

/// Check if periodic FIPS self-test is enabled.
pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::SeqCst) != 0
}

/// Enable or disable periodic FIPS self-test.
pub fn set_enabled(enable: bool) {
    let new_value = if enable { 1 } else { 0 };
    ENABLED.store(new_value, Ordering::SeqCst);
    STATE_CHANGED.signal(());
}

/// Get the number of completed iterations.
pub fn get_iterations() -> u32 {
    ITERATIONS.load(Ordering::SeqCst)
}

/// Get the last result status.
pub fn get_last_result() -> u32 {
    LAST_RESULT.load(Ordering::SeqCst)
}

/// Get full status: (enabled, iterations, last_result)
pub fn get_status() -> (bool, u32, u32) {
    (is_enabled(), get_iterations(), get_last_result())
}

/// Async sleep helper
async fn sleep_ms(ms: u32) {
    use libtock_platform::ErrorCode;

    let _guard = ALARM_MUTEX.lock().await;
    let freq: Result<u32, ErrorCode> =
        DefaultSyscalls::command(DRIVER_NUM, command::FREQUENCY, 0, 0).to_result();
    let freq = freq.map(Hz).unwrap_or(Hz(1000)); // Default to 1kHz if frequency read fails

    let ticks = Milliseconds(ms).to_ticks(freq).0;

    let sub = TockSubscribe::subscribe::<DefaultSyscalls>(DRIVER_NUM, 0);
    let _ = DefaultSyscalls::command(DRIVER_NUM, command::SET_RELATIVE, ticks, 0);
    let _ = sub.await;
}

/// Run a single FIPS self-test iteration using the Caliptra mailbox.
///
/// This function:
/// 1. Sends SELF_TEST_START to Caliptra
/// 2. Polls SELF_TEST_GET_RESULTS until completion
/// 3. Returns true on success, false on failure
async fn run_fips_self_test(caliptra_mbox: &Mailbox) -> bool {
    // Start the self-test
    let mut req_buf = [0u8; 8]; // Minimal request buffer (just header)
    let mut resp_buf = [0u8; 8]; // Response buffer

    let start_result = execute_mailbox_cmd(
        caliptra_mbox,
        CaliptraCommandId::SELF_TEST_START.into(),
        &mut req_buf,
        &mut resp_buf,
    )
    .await;

    if start_result.is_err() {
        writeln!(
            Console::<DefaultSyscalls>::writer(),
            "Periodic FIPS: SELF_TEST_START failed"
        )
        .ok();
        return false;
    }

    // Poll for completion (with timeout via iteration limit)
    const MAX_POLL_ITERATIONS: u32 = 100;
    for _ in 0..MAX_POLL_ITERATIONS {
        // Wait a bit between polls
        sleep_ms(100).await;

        // Get results
        let get_results = execute_mailbox_cmd(
            caliptra_mbox,
            CaliptraCommandId::SELF_TEST_GET_RESULTS.into(),
            &mut req_buf,
            &mut resp_buf,
        )
        .await;

        match get_results {
            Ok(_) => {
                // Success - self-test completed
                return true;
            }
            Err(_) => {
                // Still in progress or error - continue polling
                continue;
            }
        }
    }

    writeln!(
        Console::<DefaultSyscalls>::writer(),
        "Periodic FIPS: self-test timeout"
    )
    .ok();
    false
}

/// Embassy task for periodic FIPS self-test.
///
/// This task runs in the background and periodically executes FIPS self-tests
/// when enabled.
#[embassy_executor::task]
pub async fn fips_periodic_task() {
    let caliptra_mbox = Mailbox::new();

    writeln!(
        Console::<DefaultSyscalls>::writer(),
        "Periodic FIPS self-test task started"
    )
    .ok();

    loop {
        if is_enabled() {
            // Run self-test
            let result = run_fips_self_test(&caliptra_mbox).await;

            // Update state (load-modify-store since fetch_add not available on riscv32)
            let current = ITERATIONS.load(Ordering::SeqCst);
            ITERATIONS.store(current.wrapping_add(1), Ordering::SeqCst);
            LAST_RESULT.store(
                if result { RESULT_PASS } else { RESULT_FAIL },
                Ordering::SeqCst,
            );

            let iterations = get_iterations();
            writeln!(
                Console::<DefaultSyscalls>::writer(),
                "Periodic FIPS: iteration {} result: {}",
                iterations,
                if result { "PASS" } else { "FAIL" }
            )
            .ok();

            // Wait for the interval before next test
            sleep_ms(FIPS_PERIODIC_INTERVAL_MS).await;
        } else {
            // Wait for enable signal
            STATE_CHANGED.wait().await;
        }
    }
}
