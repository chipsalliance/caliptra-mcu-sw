// Licensed under the Apache-2.0 license

use anyhow::{anyhow, bail, Result};
use mcu_builder::PROJECT_ROOT;
use mcu_hw_model::{InitParams, McuHwModel, ModelFpgaRealtime};
use std::io::Read;
use std::path::Path;
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

pub(crate) fn fpga_run(args: crate::Commands) -> Result<()> {
    let crate::Commands::FpgaRun {
        zip,
        mcu_rom,
        caliptra_rom,
        otp,
        save_otp,
        uds,
        steps,
        no_recovery,
    } = args
    else {
        panic!("Must call fpga_run with Commands::FpgaRun");
    };
    let otp_file = otp.as_ref();
    let recovery = !no_recovery;

    if !Path::new("/dev/uio0").exists() {
        fpga_install_kernel_modules()?;
    }
    if mcu_rom.is_none() && zip.is_none() {
        bail!("Must specify either --mcu-rom or --zip");
    }

    let blank = [0u8; 256]; // Placeholder for empty firmware

    let (mcu_rom, mcu_runtime, soc_manifest, caliptra_rom, caliptra_fw) = if zip.is_some() {
        // Load firmware and manifests from ZIP file.
        if mcu_rom.is_some() || caliptra_rom.is_some() {
            bail!("Cannot specify --mcu-rom or --caliptra-rom with --zip");
        }

        let f = std::fs::File::open(zip.unwrap())?;
        let mut z = zip::ZipArchive::new(f)?;
        let mut mcu_rom = vec![];
        let mut mcu_runtime = vec![];
        let mut soc_manifest = vec![];
        let mut caliptra_rom = vec![];
        let mut caliptra_fw = vec![];
        z.by_name("mcu_rom.bin")
            .map_err(|_| anyhow!("mcu_rom.bin not found in ZIP"))?
            .read_to_end(&mut mcu_rom)?;
        z.by_name("mcu_runtime.bin")
            .map_err(|_| anyhow!("mcu_runtime.bin not found in ZIP"))?
            .read_to_end(&mut mcu_runtime)?;
        z.by_name("soc_manifest.bin")
            .map_err(|_| anyhow!("soc_manifest.bin not found in ZIP"))?
            .read_to_end(&mut soc_manifest)?;
        z.by_name("caliptra_rom.bin")
            .map_err(|_| anyhow!("caliptra_rom.bin not found in ZIP"))?
            .read_to_end(&mut caliptra_rom)?;
        z.by_name("caliptra_fw.bin")
            .map_err(|_| anyhow!("caliptra_fw.bin not found in ZIP"))?
            .read_to_end(&mut caliptra_fw)?;
        (
            mcu_rom,
            mcu_runtime,
            soc_manifest,
            caliptra_rom,
            caliptra_fw,
        )
    } else {
        let mcu_rom = std::fs::read(mcu_rom.unwrap())?;
        let caliptra_rom = if let Some(caliptra_rom) = caliptra_rom {
            std::fs::read(caliptra_rom)?
        } else {
            blank.to_vec()
        };

        (
            mcu_rom,
            blank.to_vec(),
            blank.to_vec(),
            caliptra_rom,
            blank.to_vec(),
        )
    };
    let otp_memory = if otp_file.is_some() && otp_file.unwrap().exists() {
        mcu_hw_model::read_otp_vmem_data(&std::fs::read(otp_file.unwrap())?)?
    } else {
        vec![]
    };

    // If we're doing UDS provisioning, we need to set the bootfsm breakpoint
    // so we can use JTAG/TAP.
    let bootfsm_break = uds;
    let mut model = ModelFpgaRealtime::new_unbooted(InitParams {
        caliptra_rom: &caliptra_rom,
        caliptra_firmware: &caliptra_fw,
        mcu_rom: &mcu_rom,
        mcu_firmware: &mcu_runtime,
        soc_manifest: &soc_manifest,
        active_mode: true,
        otp_memory: Some(&otp_memory),
        uds_program_req: uds,
        bootfsm_break,
        ..Default::default()
    })
    .unwrap();

    let mut uds_requested = false;
    let mut xi3c_configured = false;
    let start_cycle_count = model.cycle_count();
    for _ in 0..steps {
        if uds && model.cycle_count() - start_cycle_count > 20_000_000 && !uds_requested {
            println!("Opening openocd connection to Caliptra");
            model.open_openocd(4444)?;
            println!("Setting Caliptra UDS programming request");
            model.set_uds_req()?;
            println!("Setting Caliptra bootfsm go");
            model.set_bootfsm_go()?;
            uds_requested = true;
        } else if recovery && !xi3c_configured && model.i3c_target_configured() {
            xi3c_configured = true;
            println!("I3C target configured");
            model.configure_i3c_controller();
            println!("Starting recovery flow (BMC)");
            model.start_recovery_bmc();
        }
        model.step();
    }
    println!("Ending FPGA run");
    if save_otp {
        println!(
            "Saving OTP memory to file {}",
            otp_file.as_ref().unwrap().display()
        );
        model.save_otp_memory(otp_file.as_ref().unwrap())?;
    }
    Ok(())
}
