// Licensed under the Apache-2.0 license

use crate::runtime_build::objcopy;
use crate::{DynError, PROJECT_ROOT, TARGET};
use std::process::Command;

pub fn rom_build() -> Result<(), DynError> {
    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args([
            "rustc",
            "-p",
            "rom",
            "--release",
            "--target",
            TARGET,
            "--",
            "-C",
            "link-arg=-Trom/layout.ld",
        ])
        .status()?;
    if !status.success() {
        Err("build ROM binary failed")?;
    }
    let rom_elf = PROJECT_ROOT
        .join("target")
        .join(TARGET)
        .join("release")
        .join("rom");

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
        Err("objcopy failed to build ROM")?;
    }
    println!(
        "ROM binary is at {:?} ({} bytes)",
        &rom_binary,
        std::fs::metadata(&rom_binary)?.len()
    );
    Ok(())
}

pub(crate) fn rom_run(trace: bool) -> Result<(), DynError> {
    rom_build()?;
    let rom_binary = PROJECT_ROOT
        .join("target")
        .join(TARGET)
        .join("release")
        .join("rom.bin");
    let mut cargo_run_args = vec![
        "run",
        "-p",
        "emulator",
        "--release",
        "--",
        "--rom",
        rom_binary.to_str().unwrap(),
    ];
    if trace {
        cargo_run_args.extend(["-t", "-l", PROJECT_ROOT.to_str().unwrap()]);
    }
    Command::new("cargo")
        .args(cargo_run_args)
        .current_dir(&*PROJECT_ROOT)
        .status()?;
    Ok(())
}
