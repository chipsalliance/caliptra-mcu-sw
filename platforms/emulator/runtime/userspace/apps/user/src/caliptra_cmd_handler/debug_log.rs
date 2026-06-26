// Licensed under the Apache-2.0 license

extern crate alloc;
use caliptra_mcu_common_commands::{CaliptraCompletionCode, GetLogResult};
use caliptra_mcu_libsyscall_caliptra::logging::LoggingSyscall;
use caliptra_mcu_libtock_platform::ErrorCode;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;

struct DebugLogState {
    cursor_at_start: bool,
}

impl DebugLogState {
    const fn new() -> Self {
        Self {
            cursor_at_start: false,
        }
    }
}

static STATE: Mutex<CriticalSectionRawMutex, DebugLogState> = Mutex::new(DebugLogState::new());

fn probe(log: &LoggingSyscall) -> Result<(), CaliptraCompletionCode> {
    log.exists()
        .map_err(|_| CaliptraCompletionCode::UnsupportedOperation)
}

/// Drain debug-log entries into `dst`, honoring entry-boundary truncation.
///
/// Reads directly into successive slices of `dst`; the kernel logging-flash
/// capsule guarantees entry-atomic semantics — if the next entry will not fit
/// in the buffer it is given, the capsule returns `ErrorCode::SIZE` without
/// consuming the entry, so it is preserved for the caller's next invocation.
/// We therefore need no holdover buffer or scratch array of our own.
pub async fn drain(dst: &mut [u8]) -> Result<GetLogResult, CaliptraCompletionCode> {
    let log: LoggingSyscall = LoggingSyscall::default();
    probe(&log)?;

    let mut state = STATE.lock().await;

    if !state.cursor_at_start {
        log.seek_beginning()
            .await
            .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
        state.cursor_at_start = true;
    }

    let mut written = 0usize;
    let mut more_data = false;

    loop {
        let Some(remaining) = dst.get_mut(written..) else {
            // `written > dst.len()` is impossible by construction, but the
            // get_mut keeps this loop panic-free.
            break;
        };
        if remaining.is_empty() {
            // dst is full; if there is more in the log we'd see SIZE on next
            // call. Signal more_data so the caller polls again.
            more_data = true;
            break;
        }
        match log.read_entry(remaining).await {
            Ok(0) => break, // defensive: empty entry => treat as drained
            Ok(n) => written += n,
            Err(ErrorCode::Size) => {
                // Next entry does not fit in the remaining slice; the kernel
                // preserved it. Tell the caller to come back with a fresh
                // buffer.
                more_data = true;
                break;
            }
            // The capsule reports "no more entries" via Err. Any I/O error
            // surfaces the same way; treat it as end-of-drain so the caller
            // gets whatever was already accumulated.
            Err(_) => break,
        }
    }

    Ok(GetLogResult {
        bytes_written: written,
        more_data,
    })
}

/// Erase the debug log and reset the read cursor.
pub async fn clear() -> Result<(), CaliptraCompletionCode> {
    let log: LoggingSyscall = LoggingSyscall::default();
    probe(&log)?;

    let mut state = STATE.lock().await;
    log.clear()
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    // Force the next `drain` to re-seek to the (now empty) head of log.
    state.cursor_at_start = false;
    Ok(())
}
