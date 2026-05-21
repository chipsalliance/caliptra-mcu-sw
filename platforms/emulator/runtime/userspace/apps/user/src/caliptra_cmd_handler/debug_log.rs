// Licensed under the Apache-2.0 license

extern crate alloc;
use caliptra_mcu_common_commands::{CaliptraCompletionCode, GetLogResult};
use caliptra_mcu_libsyscall_caliptra::logging::LoggingSyscall;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;

const LOG_ENTRY_SCRATCH: usize = 256;

struct DebugLogState {
    holdover_len: usize,
    holdover: [u8; LOG_ENTRY_SCRATCH],
    cursor_at_start: bool,
}

impl DebugLogState {
    const fn new() -> Self {
        Self {
            holdover_len: 0,
            holdover: [0; LOG_ENTRY_SCRATCH],
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

    // 1) Flush a held-over entry from a prior call, if any.
    if state.holdover_len > 0 {
        if state.holdover_len <= dst.len() {
            let n = state.holdover_len;
            dst[..n].copy_from_slice(&state.holdover[..n]);
            written += n;
            state.holdover_len = 0;
        } else {
            // Caller buffer cannot fit even the held entry. Per the
            // entry-boundary contract we must not partial-copy; signal
            // more_data and let the caller retry with a larger buffer.
            return Ok(GetLogResult {
                bytes_written: 0,
                more_data: true,
            });
        }
    }

    // 2) Pull fresh entries from the kernel.
    let mut scratch = [0u8; LOG_ENTRY_SCRATCH];
    loop {
        match log.read_entry(&mut scratch).await {
            Ok(0) => break, // defensive: empty entry => treat as drained
            Ok(n) => {
                if written + n <= dst.len() {
                    dst[written..written + n].copy_from_slice(&scratch[..n]);
                    written += n;
                } else {
                    // Stash for the next call; this call returns short.
                    state.holdover[..n].copy_from_slice(&scratch[..n]);
                    state.holdover_len = n;
                    more_data = true;
                    break;
                }
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
    state.holdover_len = 0;
    // Force the next `drain` to re-seek to the (now empty) head of log.
    state.cursor_at_start = false;
    Ok(())
}
