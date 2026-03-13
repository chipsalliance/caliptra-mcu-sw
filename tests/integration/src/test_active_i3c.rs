// Licensed under the Apache-2.0 license

//! Integration tests for the `active_i3c` strap selection.
//!
//! These tests verify that the MCU firmware can boot successfully when
//! `McuStraps.active_i3c` is set to select the second I3C core (i3c1).
//! Both ROM and runtime are compiled with the `active-i3c1` feature so
//! that the entire boot chain uses the second I3C core consistently.

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use std::sync::atomic::Ordering;

    /// Test that the emulator boots successfully with active_i3c=1.
    ///
    /// Compiles both ROM and runtime with the `active-i3c1` feature, which
    /// sets `McuStraps.active_i3c = 1` at build time. This exercises the
    /// full boot chain (ROM recovery + runtime MCTP transport) using the
    /// second I3C core.
    ///
    /// `start_runtime_hw_model` waits for the runtime to boot
    /// (`check_booted_to_runtime`), so if it returns the boot succeeded.
    #[test]
    fn test_boot_with_i3c1_active() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        let _hw = start_runtime_hw_model(TestParams {
            feature: Some("active-i3c1"),
            rom_feature: Some("active-i3c1"),
            ..Default::default()
        });

        // force the compiler to keep the lock
        lock.fetch_add(1, Ordering::Relaxed);
    }
}
