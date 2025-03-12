// Licensed under the Apache-2.0 license

use anyhow::{anyhow, bail, Result};
use mcu_builder::PROJECT_ROOT;
use std::path::Path;
use std::process::Command;

pub fn fpga_install_kernel_modules() -> Result<()> {
    let dir = &PROJECT_ROOT.join("hw").join("fpga").join("kernel-modules");

    // need to wrap it in bash so that the current_dir is propagated to make correctly
    if !Command::new("bash")
        .args(["-c", "make"])
        .current_dir(dir)
        .status()
        .expect("Failed to build modules")
        .success()
    {
        bail!("Failed to build modules");
    }

    if !is_module_loaded("uio")? {
        sudo::escalate_if_needed().map_err(|e| anyhow!("{}", e))?;
        if !Command::new("modprobe")
            .arg("uio")
            .status()
            .expect("Could not load uio kernel module")
            .success()
        {
            bail!("Could not load uio kernel module");
        }
    }

    for module in [
        "io_module",
        "rom_backdoor_class",
        "caliptra_rom_backdoor",
        "mcu_rom_backdoor",
    ] {
        let module_path = dir.join(format!("{}.ko", module));
        if !module_path.exists() {
            bail!("Module {} not found", module_path.display());
        }
        if is_module_loaded(module)? {
            println!("Module {} already loaded", module);
            continue;
        }

        sudo::escalate_if_needed().map_err(|e| anyhow!("{}", e))?;
        if !Command::new("insmod")
            .arg(module_path.to_str().unwrap())
            .status()?
            .success()
        {
            bail!("Failed to insert module {}", module_path.display());
        }
    }

    fix_permissions()?;

    Ok(())
}

fn fix_permissions() -> Result<()> {
    let uio_path = Path::new("/dev/uio0");
    if uio_path.exists() {
        sudo::escalate_if_needed().map_err(|e| anyhow!("{}", e))?;
        if !Command::new("chmod")
            .arg("666")
            .arg(uio_path)
            .status()?
            .success()
        {
            bail!("Failed to change permissions on uio device");
        }
    }
    Ok(())
}

fn is_module_loaded(module: &str) -> Result<bool> {
    let output = Command::new("lsmod").output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .lines()
        .any(|line| line.split_whitespace().next() == Some(module)))
}
