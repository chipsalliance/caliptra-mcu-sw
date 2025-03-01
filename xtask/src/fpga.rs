// Licensed under the Apache-2.0 license

use crate::{DynError, PROJECT_ROOT};
use std::path::Path;
use std::process::Command;

pub fn fpga_install_kernel_modules() -> Result<(), DynError> {
    let dir = &PROJECT_ROOT.join("hw").join("fpga").join("kernel-modules");

    // need to wrap it in bash so that the current_dir is propagated to make correctly
    if !Command::new("bash")
        .args(["-c", "make"])
        .current_dir(dir)
        .status()
        .expect("Failed to build modules")
        .success()
    {
        return Err("Failed to build modules".into());
    }

    if !is_module_loaded("uio")? {
        sudo::escalate_if_needed()?;
        if !Command::new("modprobe")
            .arg("uio")
            .status()
            .expect("Could not load uio kernel module")
            .success()
        {
            return Err("Could not load uio kernel module".into());
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
            return Err(format!("Module {} not found", module_path.display()).into());
        }
        if is_module_loaded(module)? {
            println!("Module {} already loaded", module);
            continue;
        }

        sudo::escalate_if_needed()?;
        if !Command::new("insmod")
            .arg(module_path.to_str().unwrap())
            .status()?
            .success()
        {
            return Err(format!("Failed to insert module {}", module_path.display()).into());
        }
    }

    fix_permissions()?;

    Ok(())
}

fn fix_permissions() -> Result<(), DynError> {
    let uio_path = Path::new("/dev/uio0");
    if uio_path.exists() {
        sudo::escalate_if_needed()?;
        if !Command::new("chmod")
            .arg("666")
            .arg(uio_path)
            .status()?
            .success()
        {
            return Err("Failed to change permissions on uio device".into());
        }
    }
    Ok(())
}

fn is_module_loaded(module: &str) -> Result<bool, DynError> {
    let output = Command::new("lsmod").output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .lines()
        .any(|line| line.split_whitespace().next() == Some(module)))
}
