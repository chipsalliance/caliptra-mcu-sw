// Licensed under the Apache-2.0 license

//! The `#[defmt::global_logger]` for the MCU userspace.
//!
//! Each `defmt` macro call stages one complete rzCOBS frame in a critical
//! section, then pushes it whole into [`RING`] for the async [`drain_task`].

use crate::drain::WAKE;
use crate::ring::ByteRing;
use crate::FRAME_MAX;
use caliptra_mcu_libsyscall_caliptra::logging::LoggingSyscall;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_platform::{Syscalls, YieldNoWaitReturn};
use portable_atomic::{AtomicBool, AtomicUsize, Ordering};

/// Largest single defmt frame that can be staged; larger frames are dropped.
const STAGE_LEN: usize = FRAME_MAX;

/// Upper bound on `yield_no_wait` calls `flush` makes to let an in-flight async
/// append complete before it starts synchronous appends. Bounded so a
/// panic-time flush can never hang.
const MAX_FLUSH_DRAIN_YIELDS: usize = 8;

/// Byte capacity of the frame ring between the logger and the drain task.
const RING_LEN: usize = 1024;

/// Complete rzCOBS frames awaiting the async drain task.
pub(crate) static RING: ByteRing<RING_LEN> = ByteRing::new();

/// Frames dropped because the ring was full or the frame exceeded `STAGE_LEN`.
pub(crate) static DROPPED: AtomicUsize = AtomicUsize::new(0);

/// Number of defmt frames dropped so far.
pub fn dropped() -> usize {
    DROPPED.load(Ordering::Relaxed)
}

static TAKEN: AtomicBool = AtomicBool::new(false);
static mut CS_RESTORE: critical_section::RestoreState = critical_section::RestoreState::invalid();

static mut ENCODER: defmt::Encoder = defmt::Encoder::new();
static mut STAGE: [u8; STAGE_LEN] = [0; STAGE_LEN];
static mut STAGE_USED: usize = 0;
static mut STAGE_TRUNCATED: bool = false;

/// Encoder `write` sink: append bytes to the staging buffer, flagging overflow
/// so [`release`](Logger::release) drops the whole frame instead of a corrupt one.
fn stage(bytes: &[u8]) {
    // SAFETY: only ever called between `acquire` and `release`, i.e. inside the
    // critical section, so access to the statics is exclusive.
    unsafe {
        let used = STAGE_USED;
        let n = core::cmp::min(bytes.len(), STAGE_LEN - used);
        if n < bytes.len() {
            STAGE_TRUNCATED = true;
        }
        STAGE[used..used + n].copy_from_slice(&bytes[..n]);
        STAGE_USED = used + n;
    }
}

#[defmt::global_logger]
struct Logger;

unsafe impl defmt::Logger for Logger {
    fn acquire() {
        // One frame at a time: hold a critical section across the whole frame.
        let restore = unsafe { critical_section::acquire() };
        if TAKEN.load(Ordering::Relaxed) {
            // Re-entrancy (should be impossible under the critical section).
            // Drop this frame and release the CS we just took rather than
            // panic here, which would leak `restore` and recurse if the panic
            // handler is what emitted the log.
            DROPPED.fetch_add(1, Ordering::Relaxed);
            unsafe { critical_section::release(restore) };
            return;
        }
        TAKEN.store(true, Ordering::Relaxed);
        // SAFETY: exclusive access guaranteed by the critical section + TAKEN.
        unsafe {
            CS_RESTORE = restore;
            STAGE_USED = 0;
            STAGE_TRUNCATED = false;
            #[allow(static_mut_refs)]
            ENCODER.start_frame(stage);
        }
    }

    unsafe fn flush() {
        // Point of no return: the async drain task will not run again. Let any
        // append it left in flight drain first (bounded, never hangs), then
        // synchronously push the frames still staged in RING to flash.
        for _ in 0..MAX_FLUSH_DRAIN_YIELDS {
            if DefaultSyscalls::yield_no_wait() == YieldNoWaitReturn::NoUpcall {
                break;
            }
        }

        let log = LoggingSyscall::<DefaultSyscalls>::default();
        if log.exists().is_err() {
            return;
        }
        let mut frame = [0u8; STAGE_LEN];
        while let Some(n) = RING.pop_frame(&mut frame) {
            // Best-effort: drop a frame that fails to append rather than spin.
            let _ = log.append_entry_sync(&frame[..n]);
        }
    }

    unsafe fn release() {
        // SAFETY: still inside the critical section established by `acquire`.
        #[allow(static_mut_refs)]
        ENCODER.end_frame(stage);
        if !STAGE_TRUNCATED {
            #[allow(static_mut_refs)]
            let frame = &STAGE[..STAGE_USED];
            if !RING.push_slice(frame) {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            // Frame overflowed the staging buffer; drop it.
            DROPPED.fetch_add(1, Ordering::Relaxed);
        }
        TAKEN.store(false, Ordering::Relaxed);
        let restore = CS_RESTORE;
        critical_section::release(restore);
        // Wake the drain task to ship the frame(s) to flash.
        WAKE.signal(());
    }

    unsafe fn write(bytes: &[u8]) {
        // SAFETY: inside the critical section established by `acquire`.
        #[allow(static_mut_refs)]
        ENCODER.write(bytes, stage);
    }
}
