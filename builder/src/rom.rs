// Licensed under the Apache-2.0 license

use std::io::Write;
use std::path::PathBuf;

use anyhow::Result;

use crate::utils::manifest_file;
use crate::PROJECT_ROOT;
use caliptra_builder::FwId;
use mcu_firmware_bundler::args::{BuildArgs, Commands, Common, LdArgs};

pub fn rom_build(platform: Option<String>, features: Option<String>) -> Result<PathBuf> {
    let feature_suffix = match &features {
        Some(f) => format!("-{f}"),
        None => String::new(),
    };

    let target_name = format!(
        "mcu-rom-{}",
        platform.clone().unwrap_or_else(|| "emulator".to_string())
    );
    let rom = format!("{target_name}{feature_suffix}");
    let manifest = manifest_file(platform.as_deref(), false)?;
    let common = Common {
        manifest,
        ..Default::default()
    };
    let rom_binary = common.release_dir().map(|t| t.join(format!("{rom}.bin")))?;
    let build_cmd = Commands::Build {
        common,
        ld: LdArgs::default(),
        build: BuildArgs {
            rom_features: features.clone(),
            ..Default::default()
        },
        target: Some(target_name.clone()),
    };

    mcu_firmware_bundler::execute(build_cmd)?;
    std::fs::rename(
        rom_binary.with_file_name(format!("{target_name}.bin")),
        &rom_binary,
    )?;
    assert!(rom_binary.exists(), "{rom_binary:?} does not exist");
    Ok(rom_binary)
}

pub fn test_rom_build(platform: Option<&str>, fwid: &FwId) -> Result<String> {
    let platform = platform.unwrap_or("emulator");

    let template_name = if platform == "fpga" {
        "fpga.toml"
    } else {
        "emulator.toml"
    };
    let template_path = PROJECT_ROOT
        .join("hw/model/test-fw/data")
        .join(template_name);
    let template = std::fs::read_to_string(&template_path)?;
    let manifest_contents = template.replace("{{ROM_NAME}}", fwid.crate_name);

    let mut manifest_file = tempfile::NamedTempFile::new()?;
    manifest_file.write_all(manifest_contents.as_bytes())?;
    manifest_file.flush()?;

    let common = Common {
        manifest: manifest_file.path().to_path_buf(),
        ..Default::default()
    };

    let platform_bin = format!("mcu-test-rom-{}-{}.bin", fwid.crate_name, fwid.bin_name);
    let rom_binary = common.release_dir().map(|t| t.join(&platform_bin))?;

    let mut features = fwid.features.to_vec();
    if !features.contains(&"riscv") {
        features.push("riscv");
    }
    if platform != "emulator" {
        features.push("fpga_realtime");
    }

    let build_cmd = Commands::Build {
        common,
        ld: LdArgs::default(),
        build: BuildArgs {
            rom_features: Some(features.join(",")),
            ..Default::default()
        },
        target: Some(fwid.crate_name.to_string()),
    };

    mcu_firmware_bundler::execute(build_cmd)?;

    // The firmware bundler outputs <crate_name>.bin; rename to our expected convention.
    let bundler_output = rom_binary.with_file_name(format!("{}.bin", fwid.crate_name));
    std::fs::rename(&bundler_output, &rom_binary)?;

    assert!(rom_binary.exists(), "{rom_binary:?} does not exist");
    println!(
        "ROM binary ({}) is at {:?} ({} bytes)",
        platform,
        &rom_binary,
        std::fs::metadata(&rom_binary)?.len()
    );
    Ok(rom_binary.to_string_lossy().to_string())
}
