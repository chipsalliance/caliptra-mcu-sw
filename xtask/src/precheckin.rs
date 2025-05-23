// Licensed under the Apache-2.0 license

use anyhow::Result;

pub(crate) fn precheckin() -> Result<()> {
    crate::cargo_lock::cargo_lock()?;
    crate::format::format()?;
    crate::clippy::clippy()?;
    crate::header::check()?;
    crate::deps::check()?;
    mcu_builder::runtime_build_with_apps(&[], None, false)
}
