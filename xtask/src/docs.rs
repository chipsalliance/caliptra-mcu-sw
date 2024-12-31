// Licensed under the Apache-2.0 license

use std::process::{Command, Stdio};

use crate::{DynError, PROJECT_ROOT};

pub(crate) fn docs() -> Result<(), DynError> {
    check_mdbook()?;
    check_mermaid()?;
    println!("Running: mdbook");
    let dir = PROJECT_ROOT.join("docs");
    let dest_dir = PROJECT_ROOT.join("target/book");
    let mut args = vec!["clippy", "--workspace"];
    args.extend(["--", "-D", "warnings", "--no-deps"]);
    let status = Command::new("mdbook")
        .current_dir(&*dir)
        .args(["build", "--dest-dir", dest_dir.to_str().unwrap()])
        .status()?;

    if !status.success() {
        Err("mdbook failed")?;
    }
    println!("Docs built successfully: view at at {}/book/index.html", dest_dir.display());
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

fn check_mermaid() -> Result<(), DynError> {
    let status = Command::new("mdbook-mermaid")
        .args(["--help"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if status.is_ok() {
        return Ok(());
    }
    println!("mdbook-mermaid not found; installing...");
    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args(["install", "mdbook-mermaid"])
        .status()?;
    if !status.success() {
        Err("mdbook-mermaid installation failed")?;
    }
    Ok(())
}
