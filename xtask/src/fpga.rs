// Licensed under the Apache-2.0 license

use anyhow::{anyhow, bail, Result};
use mcu_builder::PROJECT_ROOT;
use mcu_hw_model::McuHwModel;
use mcu_hw_model::{DefaultHwModel, InitParams};
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn fpga_install_kernel_modules() -> Result<()> {
    let dir = &PROJECT_ROOT.join("hw").join("fpga").join("kernel-modules");

    disable_all_cpus_idle()?;

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

fn disable_all_cpus_idle() -> Result<()> {
    println!("Disabling idle on CPUs");
    let mut cpu = 0;
    while disable_cpu_idle(cpu).is_ok() {
        cpu += 1;
    }
    Ok(())
}

fn disable_cpu_idle(cpu: usize) -> Result<()> {
    sudo::escalate_if_needed().map_err(|e| anyhow!("{}", e))?;
    let cpu_sysfs = format!("/sys/devices/system/cpu/cpu{}/cpuidle/state1/disable", cpu);
    let cpu_path = Path::new(&cpu_sysfs);
    if !cpu_path.exists() {
        bail!("cpu[{}] does not exist", cpu);
    }
    std::fs::write(cpu_path, b"1")?;
    println!("    |- cpu[{}]", cpu);

    // verify options were set
    let value = std::fs::read_to_string(&cpu_sysfs)?.trim().to_string();
    if value != "1" {
        bail!("[-] error setting cpu[{}] into idle state", cpu);
    }
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
    let uio_path = Path::new("/dev/uio1");
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

pub(crate) fn fpga_run(mcu_rom: &PathBuf) -> Result<()> {
    if !mcu_rom.exists() {
        bail!("MCU ROM file does not exist: {}", mcu_rom.display());
    }
    let mcu_rom = std::fs::read(mcu_rom)?;
    let blank = [0u8; 256]; // Placeholder for empty firmware
    let mut model = DefaultHwModel::new_unbooted(InitParams {
        caliptra_rom: &blank,
        caliptra_firmware: &blank,
        mcu_rom: &mcu_rom,
        mcu_firmware: &blank,
        soc_manifest: &blank,
        active_mode: true,
        ..Default::default()
    })
    .unwrap();
    for _ in 0..1_000_000 {
        model.step();
    }
    println!("Ending FPGA run");
    Ok(())
}
