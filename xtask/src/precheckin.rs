// Licensed under the Apache-2.0 license

pub(crate) fn precheckin() -> Result<(), crate::DynError> {
    crate::cargo_lock::cargo_lock()?;
    crate::format::format()?;
    crate::clippy::clippy()?;
    crate::header::check()?;
    crate::runtime_build::runtime_build_with_apps(&[], None)?;
    crate::test::test()
}
