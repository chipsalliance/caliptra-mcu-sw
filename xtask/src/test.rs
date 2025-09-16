// Licensed under the Apache-2.0 license

use anyhow::{anyhow, bail, Result};
use mcu_builder::{rom_build, PROJECT_ROOT, TARGET};
use std::process::Command;

use crate::emulator_cbinding;

pub(crate) fn test() -> Result<()> {
    test_panic_missing()?;
    e2e_tests()?;
    cargo_test()
}

fn cargo_test() -> Result<()> {
    println!("Running: cargo test");
    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args([
            "test",
            "--workspace",
            "--",
            "--skip",
            "test_mailbox_execute",
        ])
        .status()?;

    if !status.success() {
        bail!("cargo test failed");
    }
    Ok(())
}

fn e2e_tests() -> Result<()> {
    println!("Running: e2e tests");

    test_hello()?;
    test_hello_c_emulator()
}

fn build_hello_binary() -> Result<()> {
    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .env("RUSTFLAGS", "-C link-arg=-Ttests/hello/link.ld")
        .args(["b", "-p", "test-hello", "--target", TARGET])
        .status()?;

    if !status.success() {
        bail!("build hello binary failed");
    }
    Ok(())
}

fn get_emulator_args() -> [String; 10] {
    [
        "--caliptra-rom".to_string(),
        "/dev/null".to_string(),
        "--caliptra-firmware".to_string(),
        "/dev/null".to_string(),
        "--soc-manifest".to_string(),
        "/dev/null".to_string(),
        "--firmware".to_string(),
        "/dev/null".to_string(),
        "--rom".to_string(),
        format!("target/{}/debug/hello", TARGET),
    ]
}

fn check_emulator_output(output: std::process::Output, emulator_name: &str) -> Result<()> {
    if !output.status.success() {
        bail!(
            "{} failed to run hello binary: {}",
            emulator_name,
            String::from_utf8(output.stderr.clone())?
        );
    }
    if !String::from_utf8(output.stderr.clone())?.contains("Hello Caliptra") {
        bail!(
            "{} output did not match expected. Got: '{}' but expected to contain '{}'",
            emulator_name,
            String::from_utf8(output.stderr)?,
            "Hello Caliptra"
        );
    }
    Ok(())
}

fn test_hello() -> Result<()> {
    build_hello_binary()?;

    let args = get_emulator_args();
    let output = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args(["run", "-p", "emulator", "--"])
        .args(&args)
        .output()?;

    check_emulator_output(output, "Emulator")?;
    Ok(())
}

fn test_hello_c_emulator() -> Result<()> {
    // First build the hello test binary (same as test_hello)
    build_hello_binary()?;

    // Build the C emulator binary
    emulator_cbinding::build_emulator(false)?; // false for debug build

    // Path to the C emulator binary
    let c_emulator_path = PROJECT_ROOT
        .join("target")
        .join("debug")
        .join("emulator_cbinding")
        .join("emulator");

    // Get the common emulator arguments
    let args = get_emulator_args();
    println!(
        "Running C emulator: {} {}",
        c_emulator_path.display(),
        args.join(" ")
    );

    // Run the C emulator with the same arguments as the Rust emulator
    let output = Command::new(&c_emulator_path)
        .current_dir(&*PROJECT_ROOT)
        .args(&args)
        .output()?;

    check_emulator_output(output, "C Emulator")?;
    Ok(())
}

pub(crate) fn test_panic_missing() -> Result<()> {
    rom_build(None, "")?;
    let rom_elf = PROJECT_ROOT
        .join("target")
        .join(TARGET)
        .join("release")
        .join("mcu-rom-emulator");
    let rom_elf = std::fs::read(rom_elf)?;
    let symbols = elf_symbols(&rom_elf)?;
    if symbols.iter().any(|s| s.contains("panic_is_possible")) {
        bail!(
            "The MCU ROM contains the panic_is_possible symbol, which is not allowed. \
                Please remove any code that might panic."
        );
    }
    Ok(())
}

pub fn elf_symbols(elf_bytes: &[u8]) -> Result<Vec<String>> {
    let elf = elf::ElfBytes::<elf::endian::LittleEndian>::minimal_parse(elf_bytes)?;
    let Some((symbols, strings)) = elf.symbol_table()? else {
        return Ok(vec![]);
    };
    let mut result = vec![];
    for sym in symbols.iter() {
        let sym_name = strings.get(sym.st_name as usize).map_err(|e| {
            anyhow!(
                "Could not parse symbol string at index {}: {e}",
                sym.st_name
            )
        })?;
        result.push(sym_name.to_string());
    }
    Ok(result)
}
