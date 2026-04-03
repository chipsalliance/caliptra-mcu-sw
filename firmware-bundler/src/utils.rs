// Licensed under the Apache-2.0 license

//! A collection of simple utilities for use by the firmware-bundler.

use std::{
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
};

use anyhow::{anyhow, bail, Result};

/// Determine the workspace directory for the Cargo workspace being built.  It does so by recursing
/// up the directory tree to find the highest directory which contains a `Cargo.toml` file, and thus
/// is the workspace root.
//
// Note: This dynamic search must be used instead of relying on CARGO_... variables as we'd like to
// ship the `firmware-bundler` as a separate tool, which will not have access to those variables
// like xtask does.
pub fn find_workspace_directory() -> Result<PathBuf> {
    let mut proposed_dir = Option::default();
    let mut current_dir = Some(std::env::current_dir()?);

    // Iterate through the parent directories, until the Root is reached on either windows or a
    // unix system.
    while let Some(cdir) = current_dir.filter(|d| Some(d.as_path()) != d.parent()) {
        if cdir.join("Cargo.toml").exists() {
            proposed_dir = Some(cdir.clone());
        }

        current_dir = cdir.parent().map(|p| p.to_path_buf());
    }

    proposed_dir.ok_or_else(|| {
        anyhow!(
            "Unable to determine workspace directory for this project, \
            consider using the `--workspace-dir` flag to specify."
        )
    })
}

/// Determine the target directory for the Cargo workspace being built.  It does so by recursing
/// up the directory tree to find the highest directory which contains a `Cargo.toml` file, and thus
/// is the workspace root.  The target directory always hangs off the workspace root.
pub fn find_target_directory() -> Result<PathBuf> {
    find_workspace_directory().map(|d| d.join("target"))
}

/// Find the sysroot of the compiler used for this workspace.  This can be used to navigate to
/// binaries compatible with this compiler.
pub fn find_sysroot() -> Result<PathBuf> {
    // `rustc` is within the sysroot, and `rustup which` is compiler version aware.  Therefore we
    // can use it to find the base of the compiler directory.
    let mut rustc_cmd = Command::new("rustup");
    rustc_cmd.arg("which").arg("rustc");
    let output = rustc_cmd.output()?;
    if !output.status.success() {
        bail!("rustc which cmd {rustc_cmd:?} failed");
    }

    // The rustc application is located in `<sysroot>/bin/rustc`.  Therefore navigate up two
    // parents to get to the sysroot directory.
    let rustc = PathBuf::from_str(&String::from_utf8(output.stdout)?)?;
    let invalid_sysroot = || anyhow!("Invalid rustc location {rustc:?}");
    Ok(rustc
        .parent()
        .ok_or_else(invalid_sysroot)?
        .parent()
        .ok_or_else(invalid_sysroot)?
        .to_path_buf())
}

/// Iterate through the given directory to find the specified file.
pub fn find_file(dir: &Path, name: &str) -> Option<PathBuf> {
    for entry in walkdir::WalkDir::new(dir) {
        let entry = entry.unwrap();
        if entry.file_name() == name {
            return Some(entry.path().to_path_buf());
        }
    }
    None
}

/// Find the objcopy binary within the sysroot directory.
pub fn objcopy() -> Result<PathBuf> {
    find_file(&find_sysroot()?, "llvm-objcopy").ok_or_else(|| anyhow!("llvm-objcopy not found"))
}
