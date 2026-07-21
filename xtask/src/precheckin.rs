// Licensed under the Apache-2.0 license

use anyhow::Result;
use caliptra_mcu_builder::features::RomVariant;

pub(crate) fn precheckin(rom_variants: &[RomVariant]) -> Result<()> {
    crate::cargo_lock::cargo_lock()?;
    crate::format::format()?;
    crate::clippy::clippy(rom_variants)?;
    crate::header::check()?;
    crate::deps::check()?;
    crate::docs::check_docs()?;
    crate::registers::autogen(true, &[], &[], None, None)?;
    crate::test::nextest_list()?;

    // Default `devel` profile: 1 MB SRAM, no `release` feature, all debug
    // components present.  Catches code that the dev-time build would actually
    // exercise.  Artifacts land in `target/<tuple>/devel/`.
    caliptra_mcu_builder::runtime_build_with_apps(
        &caliptra_mcu_builder::CaliptraBuildArgs::default(),
    )?;
    caliptra_mcu_builder::runtime_build_with_apps(&caliptra_mcu_builder::CaliptraBuildArgs {
        platform: Some("fpga"),
        no_default_features: true,
        ..Default::default()
    })?;

    // `release` profile: strips kernel `debug!()`, romtime `println!`,
    // DebugWriter, Console, LowLevelDebug, ProcessConsole; uses the
    // constrained 512 KB SRAM layout that mirrors the real device.  Catches
    // size regressions before they reach a shipping build.  Artifacts land in
    // `target/<tuple>/release/`.
    caliptra_mcu_builder::runtime_build_with_apps(&caliptra_mcu_builder::CaliptraBuildArgs {
        features: Some("release"),
        profile: Some("release"),
        no_default_features: true,
        ..Default::default()
    })?;
    // FPGA does not have a `*-devel.toml` manifest variant (HW-fixed SRAM);
    // still exercise the `release` cargo feature / `release` cargo profile
    // against its single 512 KB layout so size regressions and
    // release-only `cfg`s are caught.
    caliptra_mcu_builder::runtime_build_with_apps(&caliptra_mcu_builder::CaliptraBuildArgs {
        platform: Some("fpga"),
        features: Some("release"),
        profile: Some("release"),
        no_default_features: true,
        ..Default::default()
    })?;

    crate::test::test_panic_missing(rom_variants)?;
    crate::test::e2e_tests()?;
    crate::test::test_hello_c_emulator()?;
    crate::rom::build_all_variants(rom_variants)?;
    Ok(())
}
