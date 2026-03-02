/*++

Licensed under the Apache-2.0 license.

File Name:

    timer.rs

Abstract:

    Timer driver for the Network Coprocessor.

    Implements the Timers HIL trait using the RISC-V mcycle CSR to
    read the current CPU tick count.

--*/

use caliptra_mcu_network_hil::timers::Timers;

/// Estimated CPU clock frequency in Hz for the emulator.
const EMULATOR_CPU_CLOCK_HZ: u64 = 1_000_000;

pub struct TimerDriver {
    clock_freq: u64,
}

impl TimerDriver {
    pub fn new() -> Self {
        Self {
            clock_freq: EMULATOR_CPU_CLOCK_HZ,
        }
    }

    pub fn with_freq(clock_freq_hz: u64) -> Self {
        Self {
            clock_freq: clock_freq_hz,
        }
    }
}

impl Default for TimerDriver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_arch = "riscv32")]
fn mcycle() -> u64 {
    use riscv_csr::csr::{ReadWriteRiscvCsr, MCYCLE, MCYCLEH};
    use tock_registers::interfaces::Readable;
    use tock_registers::register_bitfields;
    register_bitfields![usize,
        value [
            value OFFSET(0) NUMBITS(32) [],
        ],
    ];
    let mcycle: ReadWriteRiscvCsr<usize, value::Register, { MCYCLE }> = ReadWriteRiscvCsr::new();
    let mcycleh: ReadWriteRiscvCsr<usize, value::Register, { MCYCLEH }> = ReadWriteRiscvCsr::new();
    (mcycleh.get() as u64) << 32 | (mcycle.get() as u64)
}

#[cfg(not(target_arch = "riscv32"))]
fn mcycle() -> u64 {
    0
}

impl Timers for TimerDriver {
    fn ticks(&self) -> u64 {
        mcycle()
    }

    fn clock_freq_hz(&self) -> u64 {
        self.clock_freq
    }
}
