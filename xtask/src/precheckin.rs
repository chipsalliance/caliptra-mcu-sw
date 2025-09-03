// Licensed under the Apache-2.0 license

use anyhow::Result;

pub(crate) fn precheckin() -> Result<()> {
    crate::cargo_lock::cargo_lock()?;
    crate::format::format()?;
    crate::clippy::clippy()?;
    crate::header::check()?;
    crate::deps::check()?;
    mcu_builder::runtime_build_with_apps_cached(
        &[],
        None,
        false,
        None,
        None,
        false,
        None,
        None,
        None,
        None,
    )?;
    mcu_builder::runtime_build_with_apps_cached(
        &[],
        None,
        false,
        Some("fpga"),
        Some(&mcu_config_fpga::FPGA_MEMORY_MAP),
        false,
        None,
        None,
        None,
        None,
    )?;
    crate::test::test_panic_missing()?;
    Ok(())
}
