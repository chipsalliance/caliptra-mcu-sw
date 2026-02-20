/*++

Licensed under the Apache-2.0 license.

File Name:

    timer.rs

Abstract:

    Timer driver for the Network Coprocessor.

    Implements the Timers HIL trait using the RISC-V mcycle CSR to
    read the current CPU tick count.

--*/

use network_hil::timers::Timers;

/// Estimated CPU clock frequency in Hz for the emulator. This is used to
/// convert tick counts (1 tick = 1 instruction) into elapsed time.
///
/// In the emulator, mcycle increments once per executed instruction.
/// At 1 MHz: 1 tick = 1 µs virtual time. This balances:
///   - ARP timing: the host kernel responds to ARP in ~100 µs real-time,
///     during which the emulator runs ~50 000 instructions = 50 ms virtual,
///     well under the 5-second ARP pending-entry timeout.
///   - TFTP timeouts (10 s virtual) = 10 000 000 ticks, giving ample time
///     for ARP to resolve and the first DATA packet to arrive.
///   - DHCP timers (~500 ms virtual) fire every 500 000 ticks, still quick
///     enough to keep the handshake responsive.
const EMULATOR_CPU_CLOCK_HZ: u64 = 1_000_000;

/// Timer driver for the Network Coprocessor.
///
/// Uses the RISC-V `mcycle` / `mcycleh` CSRs for a monotonic tick counter.
pub struct TimerDriver {
    clock_freq: u64,
}

impl TimerDriver {
    /// Create a new TimerDriver with the default clock frequency.
    pub fn new() -> Self {
        Self {
            clock_freq: EMULATOR_CPU_CLOCK_HZ,
        }
    }

    /// Create a new TimerDriver with a specific clock frequency.
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

/// Returns the current cycle count using the RISC-V mcycle CSRs.
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
    let mcycle: ReadWriteRiscvCsr<usize, value::Register, { MCYCLE }> =
        ReadWriteRiscvCsr::new();
    let mcycleh: ReadWriteRiscvCsr<usize, value::Register, { MCYCLEH }> =
        ReadWriteRiscvCsr::new();
    (mcycleh.get() as u64) << 32 | (mcycle.get() as u64)
}

/// Placeholder for non-RISC-V targets.
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
