// Licensed under the Apache-2.0 license

//! Emulator build functionality.
//!
//! This module provides functions for building the emulator binary
//! and packaging it into a ZIP archive.

use anyhow::{bail, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use zip::{write::SimpleFileOptions, ZipWriter};

use crate::PROJECT_ROOT;

/// Build arguments for the emulator build.
#[derive(Default)]
pub struct EmulatorBuildArgs {
    /// Output path for the emulator ZIP file.
    pub output: Option<String>,
}

/// Build the emulator with a specific feature flag.
///
/// # Arguments
///
/// - `feature`: Feature flag to enable (empty string for no features).
///
/// # Returns
///
/// - `Ok(Some(PathBuf))`: Path to the built emulator binary.
/// - `Ok(None)`: If the feature is not supported by the emulator.
/// - `Err(anyhow::Error)`: If the build fails.
pub fn build_emulator_with_feature(feature: &str) -> Result<Option<PathBuf>> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&*PROJECT_ROOT)
        .args(["build", "-p", "emulator", "--profile", "test"]);

    if !feature.is_empty() {
        cmd.args(["--features", feature]);
    }

    let output = cmd.output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Check if the error is due to missing feature
        if stderr.contains("does not contain this feature") {
            println!(
                "Skipping emulator build for feature '{}' (feature not supported by emulator)",
                feature
            );
            return Ok(None);
        }
        bail!(
            "Failed to build emulator with feature {}: {}",
            feature,
            stderr
        );
    }

    // The emulator binary is at target/debug/emulator (profile "test" uses the debug directory)
    let emulator_path = PROJECT_ROOT.join("target").join("debug").join("emulator");

    if !emulator_path.exists() {
        bail!("Emulator binary not found at {:?}", emulator_path);
    }

    Ok(Some(emulator_path))
}

/// Build the emulator binary and package it in emulators.zip.
///
/// # Arguments
///
/// - `args`: Build arguments.
///
/// # Returns
///
/// - `Ok(())`: If the build and packaging succeeded.
/// - `Err(anyhow::Error)`: If any step fails.
pub fn emulator_build(args: EmulatorBuildArgs) -> Result<()> {
    // Build the emulator (no features needed anymore)
    let emulator_path = build_emulator_with_feature("")?
        .ok_or_else(|| anyhow::anyhow!("Failed to build emulator"))?;

    let default_path = crate::target_dir().join("emulators.zip");
    let path = args.output.as_ref().map(Path::new).unwrap_or(&default_path);

    println!("Creating emulator ZIP file: {}", path.display());
    let file = std::fs::File::create(path)?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o755) // Make emulator executable
        .last_modified_time(zip::DateTime::try_from(chrono::Local::now().naive_local())?);

    println!("Adding {} -> emulator", emulator_path.display());
    let data = std::fs::read(&emulator_path)?;
    println!("Adding emulator: {} bytes", data.len());
    zip.start_file("emulator", options)?;
    zip.write_all(&data)?;

    zip.finish()?;
    println!("Emulator build complete: {}", path.display());

    Ok(())
}
