// Licensed under the Apache-2.0 license

/// Callbacks invoked by the common ROM at major boot milestones.
///
/// See the Integrator's Guide (`docs/src/integrator-guide.md`) for the
/// full description, reachability caveats, and usage examples.
pub trait RomHooks {
    /// Entry into the cold-boot flow, before any Caliptra interaction.
    fn pre_cold_boot(&self) {}
    /// End of the cold-boot flow, immediately before the warm reset that
    /// transitions to `FirmwareBootReset`. Best-effort — may not run if
    /// the flow aborts with a fatal error.
    fn post_cold_boot(&self) {}

    /// Entry into the warm-boot flow.
    fn pre_warm_boot(&self) {}
    /// End of the warm-boot flow, immediately before the warm reset.
    /// Best-effort — may not run if the flow aborts with a fatal error.
    fn post_warm_boot(&self) {}

    /// Entry into the firmware boot flow.
    fn pre_fw_boot(&self) {}
    /// End of the firmware boot flow, immediately before jumping to
    /// mutable firmware. Best-effort — may not run if the flow aborts
    /// with a fatal error.
    fn post_fw_boot(&self) {}

    /// Entry into the firmware hitless-update flow.
    fn pre_fw_hitless_update(&self) {}
    /// End of the firmware hitless-update flow, immediately before
    /// jumping to mutable firmware.
    fn post_fw_hitless_update(&self) {}

    /// Immediately before asserting Caliptra boot-go.
    fn pre_caliptra_boot(&self) {}
    /// Immediately after the Caliptra core boot-FSM reports `BOOT_DONE`.
    fn post_caliptra_boot(&self) {}

    /// Immediately before populating fuses into Caliptra (reads from OTP
    /// and writes to the Caliptra core fuse registers happen during this
    /// phase, followed by `fuse_write_done`).
    fn pre_populate_fuses_to_caliptra(&self) {}
    /// Immediately after `fuse_write_done` has been acknowledged by the
    /// Caliptra core.
    fn post_populate_fuses_to_caliptra(&self) {}

    /// Immediately before issuing `RI_DOWNLOAD_FIRMWARE` to Caliptra.
    fn pre_load_firmware(&self) {}
    /// Immediately after MCU firmware has been detected as loaded into
    /// SRAM (before any header verification).
    fn post_load_firmware(&self) {}
}

/// Convenience helper that invokes `f` on the hooks attached to `params`,
/// if any. Keeps call sites in the boot flows concise.
#[inline(always)]
pub fn call_hook<F: FnOnce(&dyn RomHooks)>(hooks: Option<&dyn RomHooks>, f: F) {
    if let Some(h) = hooks {
        f(h);
    }
}
