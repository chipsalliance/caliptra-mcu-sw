// Licensed under the Apache-2.0 license

use anyhow::{anyhow, bail, Result};
use caliptra_hw_model::BootParams;
use caliptra_image_gen::to_hw_format;
use caliptra_image_types::FwVerificationPqcKeyType;
use clap::Subcommand;
use mcu_builder::{FirmwareBinaries, PROJECT_ROOT};
use mcu_hw_model::{InitParams, McuHwModel, ModelFpgaRealtime};
use mcu_rom_common::LifecycleControllerState;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;

#[derive(Subcommand)]
pub(crate) enum Fpga {
    /// Bootstraps an FPGA. This command should be run after each boot
    Bootstrap {
        #[arg(long)]
        target_host: Option<String>,
    },
    /// Run firmware on Fpga
    /// NOTE: THIS COMMAND HAS NOT YET BEEN TESTED
    // TODO(clundin): Refactor this command to run over ssh.
    Run {
        /// ZIP with all images.
        #[arg(long)]
        zip: Option<PathBuf>,

        /// Where to load the MCU ROM from.
        #[arg(long)]
        mcu_rom: Option<PathBuf>,

        /// Where to load the Caliptra ROM from.
        #[arg(long)]
        caliptra_rom: Option<PathBuf>,

        /// Where to load and save OTP memory.
        #[arg(long)]
        otp: Option<PathBuf>,

        /// Save OTP memory to a file after running.
        #[arg(long, default_value_t = false)]
        save_otp: bool,

        /// Run UDS provisioning flow
        #[arg(long, default_value_t = false)]
        uds: bool,

        /// Number of "steps" to run the FPGA before stopping
        #[arg(long, default_value_t = 1_000_000)]
        steps: u64,

        /// Whether to disable the recovery interface and I3C
        #[arg(long, default_value_t = false)]
        no_recovery: bool,

        /// Lifecycle controller state to set (raw, test_unlocked0, manufacturing, prod, etc.).
        #[arg(long)]
        lifecycle: Option<String>,
    },
    /// Build FPGA firmware
    Build {
        /// When set copy firmware to `target_host`
        #[arg(long)]
        target_host: Option<String>,
    },
    /// Build FPGA test binaries
    BuildTest {
        /// When copy test binaries to `target_host`
        #[arg(long)]
        target_host: Option<String>,
    },
    /// Run FPGA tests
    Test {
        /// When set run commands over ssh to `target_host`
        #[arg(long)]
        target_host: Option<String>,
        /// A specific test filter to apply.
        #[arg(long)]
        test_filter: Option<String>,
    },
}

// Copies a file to FPGA over rsync to the FPGA home folder.
fn rsync_file(target_host: &str, file: &str, from_fpga: bool) -> Result<()> {
    // TODO(clundin): We assume are files are dropped in the root / home folder. May want to find a
    // put things in their own directory.
    let copy = if from_fpga {
        format!("{target_host}:{file}")
    } else {
        format!("{target_host}:.")
    };
    let args = if from_fpga {
        ["-avxz", &copy, file]
    } else {
        ["-avxz", file, &copy]
    };
    let status = Command::new("rsync")
        .current_dir(&*PROJECT_ROOT)
        .args(args)
        .status()?;
    if !status.success() {
        bail!("failed rsync file: {file} to {target_host}");
    }
    Ok(())
}

/// Runs a command over SSH if `target_host` is `Some`. Otherwise runs command on current machine.
fn run_command_with_output(
    target_host: Option<&str>,
    command: &str,
) -> Result<std::process::Output> {
    // TODO(clundin): Refactor to share code with `run_command`
    if let Some(target_host) = target_host {
        Ok(Command::new("ssh")
            .current_dir(&*PROJECT_ROOT)
            .args([target_host, "-t", command])
            .output()?)
    } else {
        Ok(Command::new("sh")
            .current_dir(&*PROJECT_ROOT)
            .args(["-c", command])
            .output()?)
    }
}

/// Runs a command over SSH if `target_host` is `Some`. Otherwise runs command on current machine.
fn run_command(target_host: Option<&str>, command: &str) -> Result<()> {
    if let Some(target_host) = target_host {
        println!("[FPGA HOST] Running command: {command}");
        let status = Command::new("ssh")
            .current_dir(&*PROJECT_ROOT)
            .args([target_host, "-t", command])
            .stdin(Stdio::inherit())
            .status()?;
        if !status.success() {
            bail!("\"{command}\" failed to run on FPGA over ssh");
        }
    } else {
        println!("Running command: {command}");
        let status = Command::new("sh")
            .current_dir(&*PROJECT_ROOT)
            .args(["-c", command])
            .stdin(Stdio::inherit())
            .status()?;
        if !status.success() {
            bail!("Failed to run command");
        }
    }

    Ok(())
}

pub fn fpga_install_kernel_modules(target_host: Option<&str>) -> Result<()> {
    disable_all_cpus_idle(target_host)?;

    // Make file assumes we are in the same directory.
    // TODO(clundin): Need to test this, the Ubuntu FPGA is in a bad state and seems to not be able
    // to build kernel modules.
    run_command(
        target_host,
        "(cd caliptra-mcu-sw/hw/fpga/kernel-modules && make)",
    )?;

    // TODO(clundin): Need to test this, the Ubuntu FPGA is in a bad state and seems to not be able
    // to build kernel modules.
    run_command(
        target_host,
        "sudo insmod caliptra-mcu-sw/hw/fpga/kernel-modules/io_module.ko",
    )?;

    fix_permissions(target_host)?;

    Ok(())
}

fn disable_all_cpus_idle(target_host: Option<&str>) -> Result<()> {
    println!("Disabling idle on CPUs");
    for i in 0..2 {
        disable_cpu_idle(i, target_host)?;
    }
    Ok(())
}

fn disable_cpu_idle(cpu: usize, target_host: Option<&str>) -> Result<()> {
    // Need to use bash -c to avoid misinterpreting this line...
    run_command(
        target_host,
        &format!(
            "sudo bash -c \"echo 1 > /sys/devices/system/cpu/cpu{cpu}/cpuidle/state1/disable\""
        ),
    )?;
    let state = run_command_with_output(
        target_host,
        &format!("cat /sys/devices/system/cpu/cpu{cpu}/cpuidle/state1/disable"),
    )?;
    let state = String::from_utf8(state.stdout)?;
    if state.trim_end() != "1" {
        bail!("[-] error setting cpu[{cpu}] into idle state");
    }
    Ok(())
}

fn fix_permissions(target_host: Option<&str>) -> Result<()> {
    run_command(target_host, "sudo chmod 666 /dev/uio0")?;
    run_command(target_host, "sudo chmod 666 /dev/uio1")?;
    Ok(())
}

fn is_module_loaded(module: &str, target_host: Option<&str>) -> Result<bool> {
    let stdout = String::from_utf8(run_command_with_output(target_host, "lsmod")?.stdout)?;
    Ok(stdout
        .lines()
        .any(|line| line.split_whitespace().next() == Some(module)))
}

pub(crate) fn fpga_entry(args: &Fpga) -> Result<()> {
    match args {
        Fpga::Build { target_host } => {
            println!("Building FPGA firmware");
            // TODO(clundin): Modify `mcu_builder::all_build` to return the zip instead of writing it?
            // TODO(clundin): Place FPGA xtask artifacts in a specific folder?
            mcu_builder::all_build(Some("all-fw.zip"), Some("fpga"), false, None, None)?;

            // We want to copy the zip to the FPGA if `target_host` is specified.
            if let Some(target_host) = target_host {
                rsync_file(&target_host, "all-fw.zip", false)?;
            }
        }
        Fpga::BuildTest { target_host } => {
            println!("Building FPGA test");
            // Build test binaries in a docker container
            let home = std::env::var("HOME").unwrap();
            let project_root = PROJECT_ROOT.clone();
            let project_root = project_root.display();

            // TODO(clundin): Clean this docker command up.
            Command::new("docker")
                .current_dir(&*PROJECT_ROOT)
                .args(["run", "--rm", &format!("-v{project_root}:/work-dir"), "-w/work-dir", &format!("-v{home}/.cargo/registry:/root/.cargo/registry"), &format!("-v{home}/.cargo/git:/root/.cargo/git"), "ghcr.io/chipsalliance/caliptra-build-image:latest", "/bin/bash", "-c", "(cd /work-dir && echo 'Cross compiling tests' && CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc cargo nextest archive --features=fpga_realtime --target=aarch64-unknown-linux-gnu --archive-file=caliptra-test-binaries.tar.zst --target-dir cross-target/ )"])
                .status()?;

            if let Some(target_host) = target_host {
                rsync_file(target_host, "caliptra-test-binaries.tar.zst", false)?;
            }
        }
        Fpga::Bootstrap { target_host } => {
            println!("Bootstrapping FPGA");
            let hostname = run_command_with_output(target_host.as_deref(), "hostname")?;
            let hostname = String::from_utf8(hostname.stdout).expect("Failed to parse hostname");

            // skip this step for CI images. Kernel modules are already installed.
            if hostname.trim_end() != "caliptra-fpga" {
                fpga_install_kernel_modules(target_host.as_deref())?;
            }

            // Need to clone caliptra-mcu-sw to run tests.
            run_command(target_host.as_deref(), "[ -d caliptra-mcu-sw ] || git clone https://github.com/chipsalliance/caliptra-mcu-sw --branch=main --depth=1").expect("failed to clone caliptra-mcu-sw repo");
        }
        Fpga::Test {
            target_host,
            test_filter,
        } => {
            println!("Running test suite on FPGA");
            is_module_loaded("io_module", target_host.as_deref())?;
            // Clear old test logs
            run_command(target_host.as_deref(), "(sudo rm /tmp/junit.xml || true)")?;
            // Run caliptra-mcu-sw test suite.
            // Ignore error so we still copy the logs.
            let tf = if let Some(tf) = test_filter {
                // Specific test filter to apply.
                tf
            } else {
                // Default test suite to run.
                "package(mcu-hw-model) - test(model_emulated::test::test_new_unbooted)"
            };
            let test_command = format!(
                "(cd caliptra-mcu-sw && \
                sudo CPTRA_FIRMWARE_BUNDLE=$HOME/all-fw.zip \
                cargo-nextest nextest run \
                --workspace-remap=. --archive-file $HOME/caliptra-test-binaries.tar.zst \
                --test-threads=1 --no-fail-fast --profile=nightly \
                -E \"{}\")",
                tf
            );
            let _ = run_command(target_host.as_deref(), test_command.as_str());

            if let Some(target_host) = target_host {
                println!("Copying test log from FPGA to junit.xml");
                rsync_file(target_host, "/tmp/junit.xml", true)?;
            }
        }
        _ => todo!("implement this command"),
    }

    Ok(())
}

// TODO(clundin): Refactor to match rest of module
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
        lifecycle,
    } = args
    else {
        panic!("Must call fpga_run with Commands::FpgaRun");
    };
    let otp_file = otp.as_ref();
    let recovery = !no_recovery;

    if !Path::new("/dev/uio0").exists() {
        fpga_install_kernel_modules(None)?;
    }
    if mcu_rom.is_none() && zip.is_none() {
        bail!("Must specify either --mcu-rom or --zip");
    }

    let lifecycle_controller_state = match lifecycle {
        Some(s) => Some(
            LifecycleControllerState::from_str(&s.to_lowercase())
                .map_err(|_| anyhow!("Invalid lifecycle controller state: {}", s))?,
        ),
        None => None,
    };

    let blank = [0u8; 256]; // Placeholder for empty firmware

    let binaries = if zip.is_some() {
        // Load firmware and manifests from ZIP file.
        if mcu_rom.is_some() || caliptra_rom.is_some() {
            bail!("Cannot specify --mcu-rom or --caliptra-rom with --zip");
        }

        FirmwareBinaries::read_from_zip(zip.as_ref().unwrap())?
    } else {
        let mcu_rom = std::fs::read(mcu_rom.unwrap())?;
        let caliptra_rom = if let Some(caliptra_rom) = caliptra_rom {
            std::fs::read(caliptra_rom)?
        } else {
            blank.to_vec()
        };

        FirmwareBinaries {
            mcu_rom,
            mcu_runtime: blank.to_vec(),
            caliptra_rom,
            caliptra_fw: blank.to_vec(),
            soc_manifest: blank.to_vec(),
        }
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
        caliptra_rom: &binaries.caliptra_rom,
        caliptra_firmware: &binaries.caliptra_fw,
        mcu_rom: &binaries.mcu_rom,
        mcu_firmware: &binaries.mcu_runtime,
        soc_manifest: &binaries.soc_manifest,
        active_mode: true,
        otp_memory: Some(&otp_memory),
        uds_program_req: uds,
        bootfsm_break,
        lifecycle_controller_state,
        vendor_pk_hash: binaries.vendor_pk_hash(),
        ..Default::default()
    })
    .unwrap();
    model.boot(BootParams {
        fuses: caliptra_api_types::Fuses {
            vendor_pk_hash: binaries
                .vendor_pk_hash()
                .map(|h| to_hw_format(&h))
                .unwrap_or([0u32; 12]),
            fuse_pqc_key_type: u8::from(FwVerificationPqcKeyType::LMS).into(),
            ..Default::default()
        },
        fw_image: Some(binaries.caliptra_fw.as_slice()),
        soc_manifest: Some(binaries.soc_manifest.as_slice()),
        mcu_fw_image: Some(binaries.mcu_runtime.as_slice()),
        ..Default::default()
    })?;

    let mut uds_requested = false;
    let mut xi3c_configured = false;
    let start_cycle_count = model.cycle_count();
    let mut i3c_sent = true; // set to false to test I3C interrupt
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

        if !i3c_sent && model.cycle_count() - start_cycle_count > 400_000_000 {
            i3c_sent = true;
            println!("Host: sending I3C");
            model.send_i3c_write(&[1, 2, 3, 4]);
        }
        model.step();
    }
    println!("Ending FPGA run");
    println!("MCI flow status: {:x}", model.mci_flow_status());
    if save_otp {
        println!(
            "Saving OTP memory to file {}",
            otp_file.as_ref().unwrap().display()
        );
        model.save_otp_memory(otp_file.as_ref().unwrap())?;
    }
    Ok(())
}
