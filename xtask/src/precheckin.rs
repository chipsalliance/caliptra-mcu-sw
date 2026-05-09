// Licensed under the Apache-2.0 license

use anyhow::Result;

pub(crate) fn precheckin() -> Result<()> {
    crate::cargo_lock::cargo_lock()?;
    crate::format::format()?;
    crate::clippy::clippy()?;
    crate::header::check()?;
    crate::deps::check()?;
    crate::docs::check_docs()?;
    crate::registers::autogen(true, &[], &[], None, None)?;
    mcu_builder::runtime_build_with_apps(&[], None, false, None, None)?;
    mcu_builder::runtime_build_with_apps(&[], None, false, Some("fpga"), None)?;
    crate::test::test_panic_missing()?;
    crate::test::e2e_tests()?;
    crate::test::test_hello_c_emulator()?;
    Ok(())
}
