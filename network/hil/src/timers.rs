/*++

Licensed under the Apache-2.0 license.

File Name:

    timers.rs

Abstract:

    Hardware Interface Layer trait for Timer peripherals.
--*/

// Hardware Interface Layer trait for Timer peripherals
//
// Provides access to CPU tick counters and clock frequency information.
// Future extensions may include scheduling timers, one-shot/periodic callbacks, etc.
pub trait Timers {
    // Get the current CPU tick count
    //
    // Returns a monotonically increasing tick counter value. The resolution
    // depends on the clock frequency returned by `clock_freq_hz()`.
    //
    // # Returns
    // The current tick count as a 64-bit value.
    fn ticks(&self) -> u64;

    // Get the CPU clock frequency in Hz
    //
    // # Returns
    // The clock frequency in Hz.
    fn clock_freq_hz(&self) -> u64;

    // Get elapsed time in microseconds between two tick values
    //
    // # Arguments
    // * `start` - The starting tick count
    // * `end` - The ending tick count
    //
    // # Returns
    // Elapsed time in microseconds.
    fn elapsed_us(&self, start: u64, end: u64) -> u64 {
        let elapsed_ticks = end.wrapping_sub(start);
        let freq = self.clock_freq_hz();
        if freq == 0 {
            return 0;
        }
        elapsed_ticks * 1_000_000 / freq
    }

    // Get elapsed time in milliseconds between two tick values
    //
    // # Arguments
    // * `start` - The starting tick count
    // * `end` - The ending tick count
    //
    // # Returns
    // Elapsed time in milliseconds.
    fn elapsed_ms(&self, start: u64, end: u64) -> u64 {
        let elapsed_ticks = end.wrapping_sub(start);
        let freq = self.clock_freq_hz();
        if freq == 0 {
            return 0;
        }
        elapsed_ticks * 1_000 / freq
    }
}
