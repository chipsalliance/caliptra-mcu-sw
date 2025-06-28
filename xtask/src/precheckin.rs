// Licensed under the Apache-2.0 license

use anyhow::Result;
use mcu_builder::RuntimeBuildArgs;

pub(crate) fn precheckin() -> Result<()> {
    crate::cargo_lock::cargo_lock()?;
    crate::format::format()?;
    crate::clippy::clippy()?;
    crate::header::check()?;
    crate::deps::check()?;
    mcu_builder::runtime_build_with_apps_cached(&RuntimeBuildArgs::default())?;
    mcu_builder::runtime_build_with_apps_cached(&RuntimeBuildArgs {
        platform: Some("fpga".into()),
        memory_map: Some(&mcu_config_fpga::FPGA_MEMORY_MAP),
        ..Default::default()
    })?;
    crate::test::test_panic_missing()?;
    Ok(())
}
