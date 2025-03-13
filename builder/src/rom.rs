// Licensed under the Apache-2.0 license

use crate::objcopy;
use crate::{PROJECT_ROOT, TARGET};
use anyhow::{bail, Result};
use std::process::Command;

pub fn rom_build() -> Result<()> {
    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args([
            "build",
            "-p",
            "mcu-rom-emulator",
            "--release",
            "--target",
            TARGET,
        ])
        .status()?;
    if !status.success() {
        bail!("build ROM binary failed");
    }
    let rom_elf = PROJECT_ROOT
        .join("target")
        .join(TARGET)
        .join("release")
        .join("mcu-rom-emulator");

    let rom_binary = PROJECT_ROOT
        .join("target")
        .join(TARGET)
        .join("release")
        .join("rom.bin");

    let objcopy = objcopy()?;
    let objcopy_flags = "--strip-sections --strip-all".to_string();
    let mut cmd = Command::new(objcopy);
    let cmd = cmd
        .arg("--output-target=binary")
        .args(objcopy_flags.split(' '))
        .arg(&rom_elf)
        .arg(&rom_binary);
    println!("Executing {:?}", &cmd);
    if !cmd.status()?.success() {
        bail!("objcopy failed to build ROM");
    }
    println!(
        "ROM binary is at {:?} ({} bytes)",
        &rom_binary,
        std::fs::metadata(&rom_binary)?.len()
    );
    Ok(())
}
