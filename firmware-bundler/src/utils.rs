// Licensed under the Apache-2.0 license

//! A collection of simple utilities for use by the firmware-bundler.

use std::path::PathBuf;

use anyhow::{anyhow, Result};

/// Determine the target directory for the Cargo workspace being built.  It does so by recursing
/// up the directory tree to find the highest directory which contains a `Cargo.toml` file, and thus
/// is the workspace root.  The target directory always hangs off the workspace root.
//
// Note: This dynamic search must be used instead of relying on CARGO_... variables as we'd like to
// ship the `firmware-bundler` as a separate tool, which will not have access to those variables
// like xtask does.
pub fn find_target_directory() -> Result<PathBuf> {
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

    proposed_dir.map(|d| d.join("target")).ok_or_else(|| {
        anyhow!(
            "Unable to determine workspace directory for this project, \
            consider using the `--workspace-dir` flag to specify."
        )
    })
}
