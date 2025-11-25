// Licensed under the Apache-2.0 license

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::run_command;

pub fn run(
    release: bool,
    packages: Vec<String>,
    all: bool,
    rust_only: bool,
    c_only: bool,
) -> Result<()> {
    println!("Running caliptra-util-host library tests");

    if rust_only && c_only {
        anyhow::bail!("Cannot specify both --rust-only and --c-only");
    }

    let mode = if release { "Release" } else { "Debug" };
    println!("Mode: {}", mode);

    // Run Rust tests unless c_only is specified
    if !c_only {
        run_rust_tests(release, packages.clone(), all)?;
    }

    // Run C tests unless rust_only is specified
    if !rust_only {
        run_c_tests()?;
    }

    println!("✓ All tests completed successfully!");
    Ok(())
}

fn run_rust_tests(release: bool, packages: Vec<String>, all: bool) -> Result<()> {
    println!("Running Rust tests");

    let mut cmd = Command::new("cargo");
    cmd.arg("test");

    if release {
        cmd.arg("--release");
    }

    if all {
        cmd.arg("--workspace");
        println!("Target: All workspace packages");
    } else if !packages.is_empty() {
        println!("Target: {}", packages.join(", "));
        for package in packages {
            cmd.args(["-p", &package]);
        }
    } else {
        cmd.arg("--workspace");
        println!("Target: All workspace packages (default)");
    }

    // Add common test flags
    cmd.args(["--all-targets", "--all-features"]);

    run_command("cargo test", &mut cmd)?;

    println!("✓ Rust tests passed!");
    Ok(())
}

fn run_c_tests() -> Result<()> {
    println!("Running C binding tests");

    let cbinding_tests_dir = PathBuf::from("cbinding/tests");
    if !cbinding_tests_dir.exists() {
        println!("⚠ C binding tests directory not found, skipping");
        return Ok(());
    }

    // First ensure the C binding library is built
    println!("Building C binding library");
    let mut build_cmd = Command::new("cargo");
    build_cmd.args(["build", "-p", "caliptra-util-host-cbinding"]);
    run_command("cargo build cbinding", &mut build_cmd)?;

    // Change to the C tests directory
    let original_dir = std::env::current_dir().context("Failed to get current directory")?;

    std::env::set_current_dir(&cbinding_tests_dir).with_context(|| {
        format!(
            "Failed to change to directory: {}",
            cbinding_tests_dir.display()
        )
    })?;

    let result = run_c_tests_in_directory();

    // Always change back to original directory
    std::env::set_current_dir(original_dir)
        .context("Failed to change back to original directory")?;

    result?;

    println!("✓ C binding tests passed!");
    Ok(())
}

fn run_c_tests_in_directory() -> Result<()> {
    // Check if Makefile exists
    if !Path::new("Makefile").exists() {
        anyhow::bail!("Makefile not found in cbinding/tests directory");
    }

    // Clean only the test executables, not the rust library
    println!("Cleaning Cleaning previous C test executables");
    let _ = std::fs::remove_file("test_get_device_id");
    let _ = std::fs::remove_file("test_custom_c_transport");

    // Run the C tests via make
    println!("Executing C tests with make");
    let mut test_cmd = Command::new("make");
    test_cmd.arg("test");

    run_command("make test", &mut test_cmd)?;

    Ok(())
}
