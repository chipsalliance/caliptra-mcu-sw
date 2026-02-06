// Licensed under the Apache-2.0 license

use crate::objcopy;
use crate::{PROJECT_ROOT, TARGET};
use anyhow::{bail, Result};
use std::process::Command;

/// Build the Network Coprocessor ROM.
/// Returns the path to the built binary.
pub fn network_rom_build() -> Result<String> {
    let pkg_name = "network-rom";
    let bin_name = "network-rom.bin";

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&*PROJECT_ROOT).args([
        "build",
        "-p",
        pkg_name,
        "--release",
        "--target",
        TARGET,
    ]);

    let status = cmd.status()?;
    if !status.success() {
        bail!("build Network ROM binary failed");
    }

    let rom_elf = PROJECT_ROOT
        .join("target")
        .join(TARGET)
        .join("release")
        .join(pkg_name);

    let rom_binary = PROJECT_ROOT
        .join("target")
        .join(TARGET)
        .join("release")
        .join(bin_name);

    let objcopy = objcopy()?;
    let objcopy_flags = "--strip-sections --strip-all";
    let mut objcopy_cmd = Command::new(objcopy);
    objcopy_cmd
        .arg("--output-target=binary")
        .args(objcopy_flags.split(' '))
        .arg(&rom_elf)
        .arg(&rom_binary);
    println!("Executing {:?}", &objcopy_cmd);
    if !objcopy_cmd.status()?.success() {
        bail!("objcopy failed to build Network ROM");
    }
    println!(
        "Network ROM binary is at {:?} ({} bytes)",
        &rom_binary,
        std::fs::metadata(&rom_binary)?.len()
    );
    Ok(rom_binary.to_string_lossy().to_string())
}
