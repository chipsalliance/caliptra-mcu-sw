# FPGA `test_mcu_mbox_cmds` Debug Findings

## Overview

The `test_mcu_mbox_cmds` integration test was failing on FPGA hardware with a timeout. The test exercises MCU mailbox commands (crypto operations including ECDSA, ECDH, HMAC, HKDF, LMS, and MLDSA) by sending commands from a host thread to the MCU firmware running on the VeeR-EL2 RISC-V core, which processes them and returns results.

Multiple independent issues were identified and fixed, each of which would independently cause the test to hang or fail.

---

## Hardware Architecture

### VeeR-EL2 RISC-V Core
- M-mode only core (no S/U mode)
- Internal timers (MIT) accessed via CSRs
- Timer interrupt fires on MIE BIT29 (mcause `0x8000_001D`)
- **Critical finding: BIT29 timer interrupt NEVER fires on FPGA hardware**
- Clock frequency: ~20 MHz (`TIMER_FREQUENCY_HZ = 20_000_000`)
- Observed effective speed: ~17.8M cycles/second on the FPGA

### MCU Mailbox 0 (mcu_mbox0) Hardware
- RTL source: `hw/caliptra-ss/src/mci/rtl/mcu_mbox.sv`
- **SHARED resource**: Used for BOTH host→MCU commands AND MCU→SoC flash I/O
- SRAM size: 16KB (16 × 1024 bytes)
- Lock mechanism:
  - Lock acquired by **reading** `mcu_mbox0_csr_mbox_lock` (returns 0 = acquired, hardware sets lock=1)
  - Lock released: write `execute=0` → `execute_valid_write` (requires `valid_requester_req`) → `mbox_release` → SRAM zeroing → `mbox_sram_zero_done` → lock cleared
  - `valid_requester_req = lock_set & (mbox_axi_root_user_req | mbox_requester_user_req)` — only the acquirer can release
- Notification mechanism:
  - `intr_block_rf_notif0_intr_trig_r` — software trigger register (write-only, sets status bits)
  - `intr_block_rf_notif0_internal_intr_r` — status register (W1C — write-1-to-clear)
  - Bit 5: `NotifMbox0CmdAvail` — indicates a mailbox command is available for MCU
  - `intr_block_rf_global_intr_en_r` — global interrupt enable
  - `intr_block_rf_notif0_intr_en_r` — per-notification enable mask
- AXI user discrimination:
  - `target_user` + `target_user_valid` — set by MCU when sending flash commands to SoC
  - `soc_mbox_data_available` = execute.value && (user != root_user)
  - `root_mbox_data_available` = execute.value && (user == root_user)

### Software Stack
- **Tock OS kernel**: CooperativeSched scheduler, DeferredCall mechanism, Grant-based per-process state
- **Embassy async executor**: TockExecutor in userspace, uses `yield1(1)` (Tock yield-wait) when no tasks ready
- **ProcessStandard::create**: Requires `min_process_ram_size + initial_kernel_memory_size` bytes of available RAM

---

## Issues Found and Fixed

### Issue 1: Userspace Process Fails to Load (Stack Overflow / Insufficient RAM)

**Symptom**: The MCU mbox userspace app never starts. No "SPDM main" or "MCU_MBOX task" messages appear on UART.

**Root Cause**: The TBF (Tock Binary Format) header's `min_ram_size` field was set exactly equal to `data_mem.size` from the ELF binary. Tock's `ProcessStandard::create()` allocates `min_process_ram_size` from the available memory region, but the kernel also needs `initial_kernel_memory_size` (typically 4096 bytes) from the SAME region. When `min_ram_size == data_mem.size`, there's no room for kernel overhead, and process loading fails silently.

**Fix** (`firmware-bundler/src/tbf.rs`):
```rust
// Before:
let min_ram_size: u32 = binary.data_mem.as_ref().map(|d| d.size).unwrap_or_default().try_into()?;

// After:
let min_ram_size: u32 = binary.data_mem.as_ref()
    .map(|d| d.size.saturating_sub(4096))
    .unwrap_or_default()
    .try_into()?;
```

**Key insight**: The TBF `min_ram_size` should represent the minimum the *process* needs, not the total memory region size. Tock subtracts kernel overhead from the region before comparing against `min_ram_size`.

---

### Issue 2: VeeR Timer Interrupt Never Fires on FPGA

**Symptom**: After process loads, the system hangs. The kernel's main loop calls `chip.has_pending_interrupts()` which always returns false, so the kernel never wakes up to service deferred calls or run processes.

**Root Cause**: The VeeR-EL2 MIT (Machine Internal Timer) interrupt on BIT29 of the MIE CSR does not fire on the FPGA hardware. This appears to be a hardware-level issue — the timer counts but the interrupt line never asserts. The emulator works fine because it simulates the interrupt.

**Fix** (`runtime/kernel/veer/src/timers.rs`, `runtime/kernel/veer/src/chip.rs`):

Added a `poll_expired()` method to the timers module that checks if any timer has expired by comparing the current `mcycle` CSR against the timer's target value:

```rust
// timers.rs
pub fn poll_expired(&self) -> bool {
    // Check if any timer's compare value has been reached
    let cycle = riscv::register::mcycle::read() as u32;
    // ... compare against mitcnt0/mitcnt1 bounds
}
```

Called from two critical paths in `chip.rs`:
1. `has_pending_interrupts()` — so the kernel loop detects work to do
2. `sleep()` — so the kernel services work between process yields

**Key insight**: Without hardware timer interrupts, the kernel needs a polling-based fallback to detect expired timers. This is a known limitation of the VeeR-EL2 FPGA implementation.

---

### Issue 3: MCU Mailbox Commands Not Detected (No MCI IRQ on FPGA)

**Symptom**: Host sends a mailbox command (sets execute, triggers notification), but MCU firmware never processes it. The `NotifMbox0CmdAvailSts` bit is set in hardware but the MCU driver never reads it.

**Root Cause**: The MCU mbox kernel driver relied on the MCI interrupt (external interrupt) to trigger `handle_interrupt()` which would then call `handle_incoming_request()`. On FPGA, the MCI interrupt routing doesn't work the same way as in the emulator — the interrupt line from the MCI notification block to the VeeR PLIC/interrupt controller is either not connected or not configured.

**Fix** (`platforms/emulator/runtime/kernel/drivers/mcu_mbox/src/lib.rs`):

Added `poll_for_command()` method to the MCU mbox driver:
```rust
pub fn poll_for_command(&self) {
    if self.state.get() != McuMboxState::RxWait {
        return;
    }
    let status = self.registers.intr_block_rf_notif0_internal_intr_r.get();
    if status & (1 << 5) != 0 {  // NotifMbox0CmdAvailSts
        // Clear the notification (W1C)
        self.registers.intr_block_rf_notif0_internal_intr_r.set(1 << 5);
        self.handle_incoming_request();
    }
}
```

Called from `chip.rs` `service_interrupt(0)` on every kernel iteration:
```rust
fn service_interrupt(&self, _interrupt: u32) {
    self.peripherals.mcu_mbox0.poll_for_command();
    // ... other interrupt handling
}
```

**Additionally** (`platforms/fpga/runtime/src/board.rs`): Enabled the notification in hardware:
```rust
// Enable NotifMbox0CmdAvailEn so the hardware actually latches the trigger
mci.intr_block_rf_notif0_intr_en_r.set(
    Notif0IntrEnT::NotifCptraMcuResetReqEn::SET.value
    | Notif0IntrEnT::NotifMbox0CmdAvailEn::SET.value
);
```

**Key insight**: On FPGA, the notification STATUS bit is set (confirmed via PRE-TRIG/POST-TRIG diagnostics showing `notif_status` changing from `0x88` to `0xa8` after trigger), but the notification-to-interrupt path doesn't generate a VeeR external interrupt. Polling the status register directly is required.

---

### Issue 4: Mailbox Lock Acquired During `reset_before_use()` (Deadlock)

**Symptom**: After the first flash I/O or mbox command, subsequent operations hang because the mailbox lock is permanently held.

**Root Cause**: Both the MCU mbox driver and the flash_ctrl driver called `self.registers.mcu_mbox0_csr_mbox_lock.get()` in their `reset_before_use()` methods. On real hardware, **reading the lock register acquires it** (returns 0 = now locked). The lock can only be released by the acquirer writing `execute=0`. If the driver reads the lock during init but never properly goes through the full acquire→execute→release cycle, the lock stays held forever.

**Fix** (both `platforms/emulator/runtime/kernel/drivers/mcu_mbox/src/lib.rs` and `platforms/fpga/runtime/drivers/flash_ctrl/src/lib.rs`):

```rust
// Before:
fn reset_before_use(&self) {
    self.registers.mcu_mbox0_csr_mbox_lock.get(); // BUG: acquires lock!
    self.registers.mcu_mbox0_csr_mbox_execute.set(0);
}

// After:
fn reset_before_use(&self) {
    // Do NOT read mbox_lock — on FPGA hardware, reading acquires it.
    self.registers.mcu_mbox0_csr_mbox_execute.set(0);
}
```

**Key insight**: The mbox_lock register has *read side-effects*. This is a common pattern in hardware mailbox designs but is easy to forget during software initialization. The emulator likely doesn't enforce the AXI user check on release, masking this bug.

---

### Issue 5: Host Notification Trigger Not Sent

**Symptom**: MCU firmware's `poll_for_command()` checks `NotifMbox0CmdAvailSts` but it's never set after the host sends a command.

**Root Cause**: The host-side `McuMailboxTransport::send_request()` in the emulator model set the execute bit but never triggered the MCU-side notification. In the emulator, the model would directly fire the interrupt. On FPGA, there's no automatic interrupt — the host must explicitly write the notification trigger register.

**Fix** (`hw/model/src/mcu_mbox_transport.rs`):
```rust
pub fn send_request(&self, cmd: u32, payload: &[u8]) -> Result<(), McuMailboxError> {
    // ... acquire lock, write cmd/dlen/data ...

    // Set execute
    self.mci.mcu_mbox0_csr_mbox_execute.set(MboxExecute::Execute::SET.value);

    // Manually trigger the notification (FPGA HW doesn't auto-generate it)
    // Use .set() instead of .modify() to avoid read-modify-write on a trigger register
    self.mci.intr_block_rf_notif0_intr_trig_r
        .set(Notif0IntrTrigT::NotifMbox0CmdAvailTrig::SET.value);

    Ok(())
}
```

**Key insight**: Trigger registers are write-only/fire-and-forget. Using `.modify()` (read-modify-write) on them is incorrect because reading a trigger register may return stale or undefined data. Always use `.set()` with the exact value.

---

### Issue 6: Flash Controller Holds Lock Forever (No I/O Responder)

**Symptom**: The MCU's flash_ctrl driver acquires the mbox0 lock to send a flash read/write command to the SoC. It sets `target_user` + `target_user_valid=1` and `execute=1`. But nobody on the host side processes the flash command and sets `target_status.done`, so the MCU never releases the lock. Since mbox0 is shared between flash I/O and host mbox commands, the host can never acquire the lock to send MCU mbox commands.

**Root Cause**: The test didn't spawn a flash I/O responder thread. In normal operation, the SoC's flash controller would process these requests. In the test environment, the `ImaginaryFlashController` (which exists in `hw/model/src/flash_ctrl.rs`) must be explicitly instantiated and polled.

**Fix** (`tests/integration/src/test_mcu_mbox.rs`):
```rust
// Start flash IO responder thread
let flash_mci_ptr = mci_ptr;
caliptra_mcu_testing_common::spawn_with_emulator_state(move || {
    wait_for_runtime_start();
    if !caliptra_mcu_testing_common::is_emulator_running() {
        return;
    }
    let mci_base = unsafe {
        caliptra_mcu_romtime::StaticRef::new(flash_mci_ptr as *const mci::regs::Mci)
    };
    let flash_controller = ImaginaryFlashController::new(mci_base, None, None);
    loop {
        if !caliptra_mcu_testing_common::is_emulator_running() {
            break;
        }
        flash_controller.process_flash_ios();
        sleep_emulator_ticks(100);
    }
});
```

**Key insight**: On FPGA, flash_ctrl operations during firmware boot (loading flash images, etc.) use the same mbox0 hardware. Without a responder, the first flash operation permanently locks the mailbox.

---

### Issue 7: Flash Responder Incorrectly Processes MCU Mbox Commands

**Symptom**: After adding the flash responder, it would sometimes pick up host→MCU mbox commands (where execute=1 but the command is meant for the MCU, not the flash responder). This caused corruption.

**Root Cause**: The `ImaginaryFlashController::process_flash_ios()` only checked `execute=1` before processing. It couldn't distinguish between:
- Flash operations (MCU→SoC): `target_user_valid=1`, `target_user=SOC_RECEIVER_AXI_USER`
- Mbox commands (host→MCU): `target_user_valid=0` (host doesn't set it)

**Fix** (`hw/model/src/flash_ctrl.rs`):
```rust
pub fn process_flash_ios(&self) {
    if self.busy.load(atomic::Ordering::SeqCst) {
        return;
    }
    if self.mci.mcu_mbox0_csr_mbox_execute.get() != MboxExecute::Execute::SET.value {
        return;
    }
    // Only process if target_user_valid is set (flash_ctrl sets this;
    // host mbox commands do NOT set target_user_valid)
    if self.mci.mcu_mbox0_csr_mbox_target_user_valid.get() == 0 {
        return;
    }
    // ... process flash command ...
}
```

**Key insight**: The `target_user_valid` bit is the discriminator between flash commands (MCU is requester, sends to SoC target) and mbox commands (host is requester, MCU is target). The flash responder must check this bit to avoid consuming commands meant for the MCU.

---

### Issue 8: Test Timeout Too Short for MLDSA Operations

**Symptom**: Test exits with code 124 (killed by `timeout` command) despite all operations succeeding.

**Root Cause**: MLDSA (ML-DSA-87 / Dilithium) sign and verify operations are computationally expensive on the RISC-V core. Each sign takes ~10M cycles, each verify takes ~10M cycles. The test performs:
- LMS sign/verify iterations (~100M cycles total)
- MLDSA key import + 5 iterations × (sign + verify_correct + verify_modified) (~200M cycles)
- Plus all other crypto tests (ECDSA, ECDH, HMAC, HKDF)

Total: ~2.3B cycles from boot to completion, which at 17.8M cycles/second = ~130 seconds for the crypto operations alone, plus ~100 seconds of boot time = ~230-270 seconds total.

**Fix**: The nextest `nightly` profile already allows `slow-timeout = { period = "5m", terminate-after = 6 }` (up to 30 minutes), which is more than sufficient. The issue was only with manual testing using `timeout 90` or `timeout 120`. The actual CI timeout is adequate.

**Measured completion time**: 269 seconds consistently.

---

## FPGA Test Infrastructure Changes

### `model_fpga_realtime.rs` — Step/Exit Loop

Added `step_until_exit_success()` to the FPGA model so tests can run the firmware to completion:
```rust
fn step_until_exit_success(&mut self) -> std::io::Result<()> {
    let mut step_count: u64 = 0;
    loop {
        // Drain UART output
        if !self.output().peek().is_empty() {
            self.output().take(usize::MAX);
        }
        // Check exit status
        match self.output().exit_status().or(self.exit_status()) {
            Some(ExitStatus::Passed) => return Ok(()),
            Some(ExitStatus::Failed) => return Err(...),
            None => {}
        }
        // Check fatal error
        if let Some(fatal_error) = self.mci_fw_fatal_error() {
            return Err(...);
        }
        self.step();
        step_count += 1;
        // Progress diagnostic every 1M steps
        if step_count % 1_000_000 == 0 {
            println!("[fpga-diag] step_count={} cycle_count={}", step_count, self.cycle_count());
        }
    }
}
```

### `model_fpga_realtime.rs` — Tick Tracking

Added `update_ticks()` in the `step()` function so test threads can use `sleep_emulator_ticks()` for timing:
```rust
fn step(&mut self) {
    self.base.step();
    self.handle_i3c();
    let cc = self.cycle_count();
    let ticks = cc / 100;  // ~100 cycles per tick
    update_ticks(ticks);
}
```

---

## Debugging Methodology

1. **UART diagnostics**: The MCU firmware prints `[rt] Received command=0xXXXXXXXX (AAAA), len=N` for each processed command, confirming the firmware is alive and processing.

2. **Notification register inspection**: Reading `intr_block_rf_notif0_internal_intr_r` before and after the trigger write confirmed the notification mechanism works at the register level.

3. **Cycle counting**: The `[fpga-step]` diagnostic (every 10M cycles) showed exact timing of each operation, enabling calculation of whether timeouts are sufficient.

4. **Iterative elimination**: Each fix was deployed independently to determine which combination was needed. The issues were cumulative — ALL fixes were required for the test to pass.

---

## Files Modified

| File | Change |
|------|--------|
| `firmware-bundler/src/tbf.rs` | TBF min_ram_size -= 4096 |
| `runtime/kernel/veer/src/timers.rs` | Added `poll_expired()` method |
| `runtime/kernel/veer/src/chip.rs` | Call `poll_expired()` in `sleep()` and `has_pending_interrupts()` |
| `platforms/emulator/runtime/kernel/drivers/mcu_mbox/src/lib.rs` | Added `poll_for_command()`, removed lock read from `reset_before_use()` |
| `platforms/fpga/runtime/drivers/flash_ctrl/src/lib.rs` | Removed lock read from `reset_before_use()` |
| `platforms/fpga/runtime/src/board.rs` | Enabled `NotifMbox0CmdAvailEn` |
| `hw/model/src/mcu_mbox_transport.rs` | Added notification trigger after execute |
| `hw/model/src/flash_ctrl.rs` | Added `target_user_valid` check, timeout on execute-clear wait |
| `hw/model/src/model_fpga_realtime.rs` | Added `step_until_exit_success()`, `update_ticks()` |
| `tests/integration/src/test_mcu_mbox.rs` | Added flash responder thread, removed diagnostics |
| `tests/integration/src/lib.rs` | Added `finish_runtime_hw_model()` helper |

---

## Key Lessons Learned

1. **Hardware register side-effects matter**: Reading `mbox_lock` acquires it. Always understand register semantics before using `.get()`.

2. **FPGA ≠ Emulator**: The emulator's interrupt model is simplified. On real hardware, interrupt routing from MCI→VeeR may not work without explicit PLIC configuration or software triggers.

3. **Shared hardware resources need arbitration**: When mbox0 is used for both flash I/O and host commands, both paths must be handled in tests. A missing responder for one path blocks the other.

4. **Timer interrupts can't be assumed**: On VeeR-EL2 FPGA, the MIT interrupt (BIT29) doesn't fire. Any kernel that relies on timer interrupts for scheduling must have a polling fallback.

5. **TBF headers must account for kernel overhead**: The relationship between `min_ram_size` in TBF and the actual memory available to the process is not 1:1 — Tock reserves kernel memory from the same region.

6. **Trigger registers are write-only**: Never use read-modify-write (`.modify()`) on trigger registers. Use `.set()` with the exact trigger value.

7. **Discriminating shared-mailbox traffic**: Use `target_user_valid` to distinguish between flash I/O (MCU→SoC) and command traffic (host→MCU) on a shared mailbox.
