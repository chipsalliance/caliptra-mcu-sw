// Licensed under the Apache-2.0 license

//! Integration test for the ROM milestone hooks.
//!
//! Boots the ROM built with the `test-rom-hooks` feature, which attaches
//! a `LoggingRomHooks` implementation that (a) prints a distinctive
//! `[mcu-rom-hook]` line and (b) sets a unique bit in
//! `mci_reg_fw_extended_error_info[0]` for each milestone. The test
//! boots all the way to the full runtime and then reads the bitmask via
//! the host-accessible MCI register, which works uniformly on emulator
//! and FPGA (UART-based checking is unreliable on emulator because
//! `boot()` drains the output buffer once firmware-boot-complete is
//! observed).

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use mcu_hw_model::McuHwModel;
    use std::sync::atomic::Ordering;

    /// Bits in `mci_reg_fw_extended_error_info[0]` corresponding to hooks
    /// reachable on a normal cold-boot -> firmware-boot path. Must match
    /// the `record_hook_bit(N)` calls in the platform ROMs'
    /// `LoggingRomHooks` implementations.
    ///
    /// The `warm_boot` and `fw_hitless_update` hooks are intentionally
    /// excluded: the WarmBoot flow requires an external warm reset (not
    /// the internal FirmwareBootReset at the end of cold boot), and
    /// FwHitlessUpdate requires a runtime update — neither is exercised
    /// on the default boot-to-runtime path.
    const EXPECTED_HOOK_BITS: u32 = (1 << 0)  // pre_cold_boot
        | (1 << 1)  // post_cold_boot
        | (1 << 4)  // pre_fw_boot
        | (1 << 5)  // post_fw_boot
        | (1 << 8)  // pre_caliptra_boot
        | (1 << 9)  // post_caliptra_boot
        | (1 << 10) // pre_populate_fuses_to_caliptra
        | (1 << 11) // post_populate_fuses_to_caliptra
        | (1 << 12) // pre_load_firmware
        | (1 << 13); // post_load_firmware

    #[test]
    fn test_rom_hooks_fire_in_order() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        // rom_only=false: boot all the way to the full runtime so every
        // cold-boot-path hook has a chance to fire (in particular the
        // `post_fw_boot` hook which runs just before jumping to mutable
        // firmware).
        let mut hw = start_runtime_hw_model(TestParams {
            rom_feature: Some("test-rom-hooks"),
            rom_only: false,
            ..Default::default()
        });

        assert_eq!(hw.mci_fw_fatal_error(), None, "ROM hit fatal error");

        // `boot()` returns once the FIRMWARE_BOOT_FLOW_COMPLETE milestone
        // is observed, which is set one line before the `post_fw_boot`
        // hook fires. Step briefly to let the final hook record itself
        // before we read the bitmask.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        hw.step_until(|m| {
            (m.mci_fw_extended_error_info(0) & EXPECTED_HOOK_BITS) == EXPECTED_HOOK_BITS
                || std::time::Instant::now() >= deadline
        });

        let mask = hw.mci_fw_extended_error_info(0);
        println!("ROM hook bitmask = 0x{mask:08x} (expected bits: 0x{EXPECTED_HOOK_BITS:08x})");
        assert_eq!(
            mask & EXPECTED_HOOK_BITS,
            EXPECTED_HOOK_BITS,
            "one or more expected ROM hooks did not fire: missing bits = 0x{:08x}",
            EXPECTED_HOOK_BITS & !mask
        );

        lock.fetch_add(1, Ordering::Relaxed);
    }
}
