// Licensed under the Apache-2.0 license

use anyhow::Result;
use std::process::Command;

use crate::run_command;

pub fn run(release: bool, packages: Vec<String>, all: bool) -> Result<()> {
    println!("Building caliptra-util-host library");

    let mut cmd = Command::new("cargo");
    cmd.arg("build");

    if release {
        cmd.arg("--release");
        println!("Mode: Release");
    } else {
        println!("Mode: Debug");
    }

    if all {
        cmd.arg("--workspace");
        println!("Target: All workspace packages");
    } else if !packages.is_empty() {
        println!("Target: {}", packages.join(", "));
        for package in &packages {
            cmd.args(["-p", package]);
        }
    } else {
        cmd.arg("--workspace");
        println!("Target: All workspace packages (default)");
    }

    // Add common build flags
    cmd.args(["--all-targets", "--all-features"]);

    run_command("cargo build", &mut cmd)?;

    // Also build C bindings if building all or cbinding package
    let build_cbindings =
        all || packages.is_empty() || packages.iter().any(|p| p.contains("cbinding"));

    if build_cbindings {
        println!("Building C bindings");
        let mut cbinding_cmd = Command::new("cargo");
        cbinding_cmd.args(["build", "-p", "caliptra-util-host-cbinding"]);

        if release {
            cbinding_cmd.arg("--release");
        }

        run_command("cargo build cbinding", &mut cbinding_cmd)?;
    }

    println!("✓ Build completed successfully!");
    Ok(())
}
