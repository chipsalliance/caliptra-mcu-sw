// Licensed under the Apache-2.0 license

use std::process::Command;

use crate::{DynError, PROJECT_ROOT};

// These projects only build for RISC-V.
const SKIP_PROJECTS: &[&str] = &["emulator-examples", "runtime", "pldm-app"];

pub(crate) fn test() -> Result<(), DynError> {
    println!("Running: cargo test");
    let mut args = vec!["test", "--workspace"];
    SKIP_PROJECTS.iter().for_each(|p| {
        args.push("--exclude");
        args.push(*p);
    });
    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args(args)
        .status()?;

    if !status.success() {
        Err("cargo test failed")?;
    }
    Ok(())
}
