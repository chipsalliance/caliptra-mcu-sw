// Licensed under the Apache-2.0 license

//! Build utilities for network applications

use anyhow::{Context, Result};
use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Build network applications
pub fn build(release: bool, lib_only: bool) -> Result<()> {
    if lib_only {
        println!("Building lwip-rs library...");
        build_package("lwip-rs", release)?;
    } else {
        println!("Building all network packages...");

        // Build lwip-rs library first
        println!("\n[1/2] Building lwip-rs...");
        build_package("lwip-rs", release)?;

        // Build example application
        println!("\n[2/2] Building example application...");
        build_package("lwip-rs-example", release)?;
    }

    println!("\nBuild complete!");
    Ok(())
}

/// Run an application by package name
pub fn run_example(package: &str, release: bool) -> Result<()> {
    // Build first
    println!("Building {}...", package);
    build_package(package, release)?;

    // Set environment variable for TAP interface
    println!("\nRunning {}...", package);
    println!("(Make sure TAP interface and server are running)\n");

    let mut cmd = Command::new("cargo");
    cmd.arg("run")
        .arg("-p")
        .arg(package)
        .env("PRECONFIGURED_TAPIF", "tap0");

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("Failed to run example")?;

    if !status.success() {
        anyhow::bail!("Example failed with exit code: {:?}", status.code());
    }

    Ok(())
}

/// Run an application with a timeout, returning output
///
/// This is useful for integration tests that need to verify the output.
/// If `timeout` is None, waits indefinitely.
#[allow(dead_code)] // Used by tests-integration
pub fn run_example_with_timeout(
    package: &str,
    release: bool,
    timeout: Option<Duration>,
    tap_interface: &str,
) -> Result<std::process::Output> {
    // Build first
    build_package(package, release)?;

    // Spawn the process using cargo run
    let mut cmd = Command::new("cargo");
    cmd.arg("run")
        .arg("-p")
        .arg(package)
        .env("PRECONFIGURED_TAPIF", tap_interface)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if release {
        cmd.arg("--release");
    }

    let child = cmd.spawn().context("Failed to spawn example")?;

    // Wait with optional timeout
    match timeout {
        Some(duration) => wait_with_timeout(child, duration),
        None => child
            .wait_with_output()
            .context("Failed to wait for example"),
    }
}

/// Wait for child process with timeout
#[allow(dead_code)] // Used by run_example_with_timeout
fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> Result<std::process::Output> {
    let start = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = child
                    .stdout
                    .take()
                    .map(|mut s| {
                        let mut buf = Vec::new();
                        let _ = s.read_to_end(&mut buf);
                        buf
                    })
                    .unwrap_or_default();

                let stderr = child
                    .stderr
                    .take()
                    .map(|mut s| {
                        let mut buf = Vec::new();
                        let _ = s.read_to_end(&mut buf);
                        buf
                    })
                    .unwrap_or_default();

                return Ok(std::process::Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    anyhow::bail!("Process timed out after {:?}", timeout);
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                anyhow::bail!("Error waiting for process: {}", e);
            }
        }
    }
}

/// Build a specific package by name
fn build_package(package: &str, release: bool) -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.arg("build").arg("-p").arg(package);

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("Failed to build")?;

    if !status.success() {
        anyhow::bail!("Build failed");
    }

    Ok(())
}
