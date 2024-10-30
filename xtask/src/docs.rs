// Licensed under the Apache-2.0 license

use std::process::{Command, Stdio};

use crate::{DynError, PROJECT_ROOT};

pub(crate) fn docs() -> Result<(), DynError> {
    check_mdbook()?;
    println!("Running: mdbook");
    let dir = PROJECT_ROOT.join("docs");
    let mut args = vec!["clippy", "--workspace"];
    args.extend(["--", "-D", "warnings", "--no-deps"]);
    let status = Command::new("mdbook")
        .current_dir(&*dir)
        .args(["build"])
        .status()?;

    if !status.success() {
        Err("mdbook failed")?;
    }
    println!("Docs built successfully: view at at docs/book/index.html");
    Ok(())
}

fn check_mdbook() -> Result<(), DynError> {
    let status = Command::new("mdbook")
        .args(["--help"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if status.is_ok() {
        return Ok(());
    }
    println!("mdbook not found; installing...");
    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args(["install", "mdbook"])
        .status()?;
    if !status.success() {
        Err("mdbook installation failed")?;
    }
    Ok(())
}