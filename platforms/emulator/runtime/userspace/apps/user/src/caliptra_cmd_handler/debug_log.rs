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
pub async fn drain(dst: &mut [u8]) -> Result<GetLogResult, CaliptraCompletionCode> {
    let log: LoggingSyscall = LoggingSyscall::new();
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
        if written == dst.len() {
            // We cannot probe for another entry without either consuming it or
            // violating the entry-boundary contract. Return a conservative
            // `more_data`; a follow-up call will either drain the next entry or
            // report an empty final chunk.
            more_data = true;
            break;
        }

        match log.read_entry(&mut dst[written..]).await {
            Ok(0) => break, // defensive: empty entry => treat as drained
            Ok(n) => written += n,
            Err(ErrorCode::Size) => {
                // The next entry does not fit in the remaining caller buffer.
                // The logging capsule leaves its read cursor unchanged on
                // SIZE, so the caller can retry and receive that entry first.
                more_data = true;
                break;
            }
            // The capsule reports "no more entries" via Err. Other I/O errors
            // surface the same way; treat them as end-of-drain so the caller
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
    let log: LoggingSyscall = LoggingSyscall::new();
    probe(&log)?;

    let mut state = STATE.lock().await;
    log.clear()
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    // Force the next `drain` to re-seek to the (now empty) head of log.
    state.cursor_at_start = false;
    Ok(())
}
