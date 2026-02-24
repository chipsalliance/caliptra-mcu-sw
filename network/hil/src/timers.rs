/*++

Licensed under the Apache-2.0 license.

File Name:

    timers.rs

Abstract:

    Hardware Interface Layer trait for Timer peripherals.
--*/

/// Timer peripheral trait providing tick counters and elapsed time helpers.
pub trait Timers {
    /// Get the current CPU tick count (monotonically increasing).
    fn ticks(&self) -> u64;

    /// Get the CPU clock frequency in Hz.
    fn clock_freq_hz(&self) -> u64;

    /// Get elapsed time in microseconds between two tick values.
    fn elapsed_us(&self, start: u64, end: u64) -> u64 {
        let elapsed_ticks = end.wrapping_sub(start);
        let freq = self.clock_freq_hz();
        if freq == 0 {
            return 0;
        }
        elapsed_ticks * 1_000_000 / freq
    }

    /// Get elapsed time in milliseconds between two tick values.
    fn elapsed_ms(&self, start: u64, end: u64) -> u64 {
        let elapsed_ticks = end.wrapping_sub(start);
        let freq = self.clock_freq_hz();
        if freq == 0 {
            return 0;
        }
        elapsed_ticks * 1_000 / freq
    }
}
