// Licensed under the Apache-2.0 license

use anyhow::{anyhow, bail, Result};
use mcu_builder::{rom_build, PROJECT_ROOT, TARGET};
use std::process::Command;

use crate::emulator_cbinding;

pub(crate) struct TestArgs<'a> {
    pub archive: Option<&'a str>,
    pub shard: Option<&'a str>,
    pub workspace_remap: Option<&'a str>,
    pub firmware_bundle: Option<&'a str>,
    pub emulator_bundle: Option<&'a str>,
}

const EXCLUDED_PACKAGES: &[&str] = &[
    "bare-metal-runtime",
    "mcu-rom-emulator",
    "mcu-rom-fpga",
    "mcu-runtime-emulator",
    "mcu-runtime-fpga",
    "emulator",
    "test-hello",
    "user-app",
    "example-app",
    "libtock_unittest",
    "syscalls_tests",
    // no_std firmware binaries targeting RISC-V; can't be run on the host
    "mcu-test-fw-exception-handler",
    "mcu-test-fw-hitless-update-flow",
    "mcu-test-fw-lc-ctrl",
    "mcu-test-fw-mailbox-responder",
    "mcu-test-fw-otp-blank-check",
    "mcu-test-fw-otp-scramble-check",
    "mcu-test-fw-sw-digest-lock",
];

pub(crate) fn test(args: TestArgs) -> Result<()> {
    if let Some(firmware_bundle) = args.firmware_bundle {
        std::env::set_var("CPTRA_FIRMWARE_BUNDLE", firmware_bundle);
    }
    if let Some(emulator_bundle) = args.emulator_bundle {
        std::env::set_var("CPTRA_EMULATOR_BUNDLE", emulator_bundle);
    }

    cargo_test(args.shard, args.workspace_remap, args.archive)
}

pub(crate) fn test_archive(archive_file: String) -> Result<()> {
    cargo_test_archive(&archive_file)
}

fn cargo_test(
    shard: Option<&str>,
    workspace_remap: Option<&str>,
    archive: Option<&str>,
) -> Result<()> {
    // Run all tests with nextest for proper sequencing, excluding ROM packages that don't have tests
    println!("Running: cargo nextest run");
    let mut args = vec![
        "nextest",
        "run",
        "--test-threads=1",
        "--profile=nightly-emulator",
    ];

    if let Some(archive_path) = archive {
        args.push("--archive-file");
        args.push(archive_path);
    } else {
        // These arguments cannot be used with `--archive-file`
        args.push("--workspace");
        for exclude in EXCLUDED_PACKAGES {
            args.push("--exclude");
            args.push(exclude);
        }
    }

    if let Some(shard) = shard {
        args.push("--partition");
        args.push(shard);
    }

    if let Some(remap) = workspace_remap {
        args.push("--workspace-remap");
        args.push(remap);
    }

    let nextest_status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args(&args)
        .status()?;

    if !nextest_status.success() {
        bail!("Tests with nextest failed");
    }

    Ok(())
}

fn cargo_test_archive(archive_file: &str) -> Result<()> {
    println!(
        "Running: cargo nextest archive --archive-file {}",
        archive_file
    );
    let mut args = vec![
        "nextest",
        "archive",
        "--workspace",
        "--archive-file",
        archive_file,
    ];

    for exclude in EXCLUDED_PACKAGES {
        args.push("--exclude");
        args.push(exclude);
    }

    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args(&args)
        .status()?;

    if !status.success() {
        bail!("cargo nextest archive failed");
    }

    Ok(())
}

pub(crate) fn e2e_tests() -> Result<()> {
    println!("Running: e2e tests");

    test_hello()
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

pub(crate) fn test_hello_c_emulator() -> Result<()> {
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
    let rom_elf_path = PROJECT_ROOT
        .join("target")
        .join(TARGET)
        .join("release")
        .join("mcu-rom-emulator");

    // Check default build
    rom_build(&mcu_builder::CaliptraBuildArgs::default())?;
    check_no_panic(&rom_elf_path, "default")?;

    // Check test-flash-based-boot build
    rom_build(&mcu_builder::CaliptraBuildArgs {
        features: Some("test-flash-based-boot"),
        ..Default::default()
    })?;
    check_no_panic(&rom_elf_path, "test-flash-based-boot")?;

    Ok(())
}

fn check_no_panic(rom_elf_path: &std::path::Path, label: &str) -> Result<()> {
    let rom_elf = std::fs::read(rom_elf_path)?;
    let symbols = elf_symbols(&rom_elf)?;
    if symbols.iter().any(|s| s.contains("panic_is_possible")) {
        bail!(
            "The MCU ROM ({label}) contains the panic_is_possible symbol, which is not allowed. \
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
