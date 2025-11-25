// Licensed under the Apache-2.0 license

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::Command;

use crate::run_command;

pub fn run(target: bool, c_tests: bool, all: bool) -> Result<()> {
    println!("Cleaning build artifacts");

    if all {
        clean_target()?;
        clean_c_tests()?;
        println!("✓ All artifacts cleaned!");
        return Ok(());
    }

    if target || !c_tests {
        clean_target()?;
    }

    if c_tests {
        clean_c_tests()?;
    }

    println!("✓ Cleaning completed successfully!");
    Ok(())
}

fn clean_target() -> Result<()> {
    println!("Cleaning Cargo target directory");

    let mut cmd = Command::new("cargo");
    cmd.arg("clean");

    run_command("cargo clean", &mut cmd)?;

    println!("✓ Cargo target directory cleaned");
    Ok(())
}

fn clean_c_tests() -> Result<()> {
    println!("Cleaning C test artifacts");

    let cbinding_tests_dir = PathBuf::from("cbinding/tests");
    if !cbinding_tests_dir.exists() {
        println!("⚠ C binding tests directory not found, skipping");
        return Ok(());
    }

    // Change to the C tests directory
    let original_dir = std::env::current_dir().context("Failed to get current directory")?;

    std::env::set_current_dir(&cbinding_tests_dir).with_context(|| {
        format!(
            "Failed to change to directory: {}",
            cbinding_tests_dir.display()
        )
    })?;

    let result = clean_c_tests_in_directory();

    // Always change back to original directory
    std::env::set_current_dir(original_dir)
        .context("Failed to change back to original directory")?;

    result?;

    println!("✓ C test artifacts cleaned");
    Ok(())
}

fn clean_c_tests_in_directory() -> Result<()> {
    if !std::path::Path::new("Makefile").exists() {
        println!("ℹ No Makefile found, skipping C test cleanup");
        return Ok(());
    }

    let mut cmd = Command::new("make");
    cmd.arg("clean");

    // Don't fail if clean fails (might not have artifacts to clean)
    let status = cmd.status().context("Failed to execute make clean")?;

    if !status.success() {
        println!("ℹ make clean returned non-zero status (this may be normal)");
    }

    Ok(())
}
