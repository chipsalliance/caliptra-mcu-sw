// Licensed under the Apache-2.0 license

use std::process::Command;

use crate::{DynError, PROJECT_ROOT, TARGET};

pub(crate) fn test() -> Result<(), DynError> {
    cargo_test()?;
    e2e_tests()
}

fn cargo_test() -> Result<(), DynError> {
    println!("Running: cargo test");
    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args(["test", "--workspace"])
        .status()?;

    if !status.success() {
        Err("cargo test failed")?;
    }
    Ok(())
}

fn e2e_tests() -> Result<(), DynError> {
    println!("Running: e2e tests");

    test_hello()
}

fn test_hello() -> Result<(), DynError> {
    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .env("RUSTFLAGS", "-C link-arg=-Ttests/hello/link.ld")
        .args(["b", "-p", "test-hello", "--target", TARGET])
        .status()?;

    if !status.success() {
        Err("build hello binary failed")?;
    }

    let output = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args([
            "run",
            "-p",
            "emulator",
            "--",
            "--rom",
            format!("target/{}/debug/hello", TARGET).as_str(),
        ])
        .output()?;
    if !output.status.success() {
        Err(format!(
            "Emulator failed to run hello binary: {}",
            String::from_utf8(output.stderr.clone())?
        ))?;
    }
    if !String::from_utf8(output.stderr.clone())?.contains("Hello Caliptra") {
        Err(format!(
            "Emulator output did not match expected. Got: '{}' but expected to contain '{}'",
            String::from_utf8(output.stderr)?,
            "Hello Caliptra"
        ))?;
    }

    Ok(())
}
