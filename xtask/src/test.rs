// Licensed under the Apache-2.0 license

use anyhow::{anyhow, bail, Result};
use mcu_builder::{rom_build, PROJECT_ROOT, TARGET};
use std::process::Command;

pub(crate) fn test() -> Result<()> {
    test_panic_missing()?;
    cargo_test()?;
    e2e_tests()
}

fn cargo_test() -> Result<()> {
    println!("Running: cargo test");
    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args(["test", "--workspace"])
        .status()?;

    if !status.success() {
        bail!("cargo test failed");
    }
    Ok(())
}

fn e2e_tests() -> Result<()> {
    println!("Running: e2e tests");

    test_hello()
}

fn test_hello() -> Result<()> {
    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .env("RUSTFLAGS", "-C link-arg=-Ttests/hello/link.ld")
        .args(["b", "-p", "test-hello", "--target", TARGET])
        .status()?;

    if !status.success() {
        bail!("build hello binary failed");
    }

    let output = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args([
            "run",
            "-p",
            "emulator",
            "--",
            "--caliptra-rom",
            "/dev/null",
            "--caliptra-firmware",
            "/dev/null",
            "--soc-manifest",
            "/dev/null",
            "--firmware",
            "/dev/null",
            "--rom",
            format!("target/{}/debug/hello", TARGET).as_str(),
        ])
        .output()?;
    if !output.status.success() {
        bail!(
            "Emulator failed to run hello binary: {}",
            String::from_utf8(output.stderr.clone())?
        );
    }
    if !String::from_utf8(output.stderr.clone())?.contains("Hello Caliptra") {
        bail!(
            "Emulator output did not match expected. Got: '{}' but expected to contain '{}'",
            String::from_utf8(output.stderr)?,
            "Hello Caliptra"
        );
    }

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
