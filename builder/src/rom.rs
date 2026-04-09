// Licensed under the Apache-2.0 license

use std::io::Write;
use std::path::PathBuf;

use anyhow::Result;

use crate::utils::manifest_file;
use crate::{CaliptraBuildArgs, PROJECT_ROOT};
use caliptra_image_crypto::RustCrypto as Crypto;
use caliptra_image_gen::{from_hw_format, ImageGeneratorCrypto};
use caliptra_mcu_firmware_bundler::args::{BuildArgs, Commands, Common, LdArgs};

pub fn rom_build(args: &CaliptraBuildArgs) -> Result<PathBuf> {
    let platform = args.platform;
    let features = args.features;
    let target_dir = args.target_dir.clone();

    let feature_suffix = match &features {
        Some(f) if !f.is_empty() => format!("-{f}"),
        _ => String::new(),
    };

    let target_name = format!("mcu-rom-{}", platform.unwrap_or("emulator"));
    let rom = format!("{target_name}{feature_suffix}");
    let manifest = manifest_file(platform, false)?;
    let common = Common {
        manifest,
        target_dir,
        ..Default::default()
    };
    let rom_size = rom_size_for_platform(platform.unwrap_or("emulator"));
    let rom_binary = common.release_dir().map(|t| t.join(format!("{rom}.bin")))?;
    let build_cmd = Commands::Build {
        common,
        ld: LdArgs::default(),
        build: BuildArgs {
            rom_features: features.filter(|s| !s.is_empty()).map(|s| s.to_string()),
            ..Default::default()
        },
        target: Some(target_name.clone()),
    };

    caliptra_mcu_firmware_bundler::execute(build_cmd)?;
    let bundler_output = rom_binary.with_file_name(format!("{target_name}.bin"));
    if bundler_output != rom_binary {
        std::fs::rename(bundler_output, &rom_binary)?;
    }
    assert!(rom_binary.exists(), "{rom_binary:?} does not exist");
    append_rom_digest(&rom_binary, rom_size)?;
    Ok(rom_binary)
}

/// Pad the ROM binary to its full size and append a SHA384 digest of its contents to the end.
pub fn append_rom_digest(binary: &PathBuf, rom_size: usize) -> Result<()> {
    let mut data = std::fs::read(binary)?;
    const DIGEST_SIZE: usize = 48;
    let digest_offset = rom_size - DIGEST_SIZE;
    data.resize(rom_size, 0);
    let crypto = Crypto::default();
    let digest = from_hw_format(&crypto.sha384_digest(&data[0..digest_offset])?);
    data[digest_offset..].copy_from_slice(&digest);
    std::fs::write(binary, data)?;
    Ok(())
}

pub fn rom_size_for_platform(platform: &str) -> usize {
    match platform {
        "fpga" => caliptra_mcu_config_fpga::FPGA_MEMORY_MAP.rom_size as usize,
        _ => caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.rom_size as usize,
    }
}

pub fn test_rom_build(args: &CaliptraBuildArgs) -> Result<String> {
    let platform = args.platform.unwrap_or("emulator");
    let fwid = args
        .fwid
        .ok_or_else(|| anyhow::anyhow!("fwid is required for test_rom_build"))?;
    let target_dir = args.target_dir.clone();

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
        target_dir,
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

    caliptra_mcu_firmware_bundler::execute(build_cmd)?;

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
    let rom_size = rom_size_for_platform(platform);
    append_rom_digest(&rom_binary, rom_size)?;
    Ok(rom_binary.to_string_lossy().to_string())
}
