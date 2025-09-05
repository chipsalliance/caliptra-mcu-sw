// Licensed under the Apache-2.0 license

use anyhow::{anyhow, bail, Result};
use caliptra_hw_model::BootParams;
use caliptra_image_gen::to_hw_format;
use caliptra_image_types::FwVerificationPqcKeyType;
use clap::{Subcommand, ValueEnum};
use mcu_builder::{AllBuildArgs, FirmwareBinaries, PROJECT_ROOT};
use mcu_hw_model::{InitParams, McuHwModel, ModelFpgaRealtime};
use mcu_rom_common::LifecycleControllerState;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;

/// The FPGA configuration mode
#[derive(Clone, ValueEnum, Debug)]
pub enum Configuration {
    /// Testing FPGA in Subsystem mode. For example running tests in caliptra-mcu-sw.
    Subsystem,
    /// Running Core tests on a subsystem FPGA. The tests are sourced from caliptra-sw.
    CoreOnSubsystem,
}

impl<'a> Configuration {
    fn cache(&'a self, cache_function: impl FnOnce(&'a str) -> Result<()>) -> Result<()> {
        match self {
            Self::Subsystem => cache_function("subsystem")?,
            Self::CoreOnSubsystem => cache_function("core-on-subsystem")?,
        }

        Ok(())
    }

    fn from_cache(cache_contents: &'a str) -> Result<Self> {
        match cache_contents {
            "core-on-subsystem" => Ok(Configuration::CoreOnSubsystem),
            _ => Ok(Configuration::Subsystem),
        }
    }

    fn from_cmd(target_host: Option<&str>) -> Result<Self> {
        let cache_contents = run_command_with_output(target_host, "cat /tmp/fpga-config")?;
        let cache_contents = cache_contents.trim_end();
        Self::from_cache(&cache_contents)
    }
}

#[derive(Subcommand)]
pub(crate) enum Fpga {
    /// Bootstraps an FPGA. This command should be run after each boot
    Bootstrap {
        #[arg(long)]
        target_host: Option<String>,
        #[arg(long, default_value_t = Configuration::Subsystem, value_enum)]
        configuration: Configuration,
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

        /// Local caliptra-sw path. Used in conjunction with the Cargo.toml change.
        #[arg(long)]
        caliptra_sw: Option<PathBuf>,
    },
    /// Build FPGA test binaries
    BuildTest {
        /// When copy test binaries to `target_host`
        #[arg(long)]
        target_host: Option<String>,
        /// Local caliptra-sw path. Used in conjunction with the Cargo.toml change.
        #[arg(long)]
        caliptra_sw: Option<PathBuf>,
    },
    /// Run FPGA tests
    Test {
        /// When set run commands over ssh to `target_host`
        #[arg(long)]
        target_host: Option<String>,
        /// A specific test filter to apply.
        #[arg(long)]
        test_filter: Option<String>,
        /// Print test output during execution.
        #[arg(long, default_value_t = false)]
        test_output: bool,
    },
}

// Copies a file to FPGA over rsync to the FPGA home folder.
fn rsync_file(target_host: &str, file: &str, dest_file: &str, from_fpga: bool) -> Result<()> {
    // TODO(clundin): We assume are files are dropped in the root / home folder. May want to find a
    // put things in their own directory.
    let copy = if from_fpga {
        format!("{target_host}:{file}")
    } else {
        format!("{target_host}:{dest_file}")
    };
    let args = if from_fpga {
        ["-avxz", &copy, "."]
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
fn run_command_with_output(target_host: Option<&str>, command: &str) -> Result<String> {
    // TODO(clundin): Refactor to share code with `run_command`

    let output = {
        if let Some(target_host) = target_host {
            Command::new("ssh")
                .current_dir(&*PROJECT_ROOT)
                .args([target_host, "-t", command])
                .output()
        } else {
            Command::new("sh")
                .current_dir(&*PROJECT_ROOT)
                .args(["-c", command])
                .output()
        }
    }?;

    Ok(String::from_utf8(output.stdout)?)
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
    let stdout = run_command_with_output(target_host, "lsmod")?;
    Ok(stdout
        .lines()
        .any(|line| line.split_whitespace().next() == Some(module)))
}

pub(crate) fn fpga_entry(args: &Fpga) -> Result<()> {
    match args {
        Fpga::Build {
            target_host,
            caliptra_sw,
        } => {
            println!("Building FPGA firmware");
            let config = Configuration::from_cmd(target_host.as_deref())?;
            // TODO(clundin): Maybe use a trait instead of a bunch of match statements.
            match config {
                Configuration::Subsystem => {
                    // TODO(clundin): Modify `mcu_builder::all_build` to return the zip instead of writing it?
                    // TODO(clundin): Place FPGA xtask artifacts in a specific folder?
                    let args = AllBuildArgs {
                        output: Some("all-fw.zip"),
                        platform: Some("fpga"),
                        ..Default::default()
                    };
                    mcu_builder::all_build(args)?;

                    // We want to copy the zip to the FPGA if `target_host` is specified.
                    if let Some(target_host) = target_host {
                        rsync_file(&target_host, "all-fw.zip", ".", false)?;
                    }
                }
                Configuration::CoreOnSubsystem => {
                    run_command(
                        None,
                        "mkdir -p /tmp/caliptra-test-firmware/caliptra-test-firmware",
                    )?;
                    let caliptra_sw = caliptra_sw
                        .as_deref()
                        .expect("need to set `caliptra-sw` when in core-on-subsystem mode");
                    run_command(
                        None,
                        &format!("(cd {} && cargo run --release -p caliptra-builder -- --all_elfs /tmp/caliptra-test-firmware)", caliptra_sw.display())
                    )?;
                    let rom_path = mcu_builder::rom_build(Some("fpga"), "core_test")?;
                    if let Some(target_host) = target_host {
                        rsync_file(
                            target_host,
                            "/tmp/caliptra-test-firmware",
                            "/tmp/caliptra-test-firmware",
                            false,
                        )?;
                        rsync_file(target_host, &rom_path, "mcu-rom-fpga.bin", false)?;
                    }
                }
            }
        }
        Fpga::BuildTest {
            target_host,
            caliptra_sw,
        } => {
            println!("Building FPGA test");
            // Build test binaries in a docker container
            let home = std::env::var("HOME").unwrap();
            let project_root = PROJECT_ROOT.clone();
            let project_root = project_root.display();

            // TODO(clundin): Clean this docker command up.
            let mut cmd = Command::new("docker");
            cmd.current_dir(&*PROJECT_ROOT).args([
                "run",
                "--rm",
                &format!("-v{project_root}:/work-dir"),
                "-w/work-dir",
                &format!("-v{home}/.cargo/registry:/root/.cargo/registry"),
                &format!("-v{home}/.cargo/git:/root/.cargo/git"),
            ]);

            // Add optional path to the caliptra-sw directory
            if let Some(caliptra_sw) = caliptra_sw {
                let basename = caliptra_sw.file_name().unwrap().to_str().unwrap();
                let caliptra_sw = std::fs::canonicalize(&caliptra_sw)?;
                cmd.arg(&format!("-v{}:/{basename}", caliptra_sw.display()));
            }

            let config = Configuration::from_cmd(target_host.as_deref())?;

            cmd.arg("ghcr.io/chipsalliance/caliptra-build-image:latest")
                .arg("/bin/bash")
                .arg("-c");

            // Assumes you are using `../caliptra-sw` as your crate path in Cargo.toml
            // TODO(clundin): Clean this up...
            let (features, work_dir) = match config {
                Configuration::Subsystem => ("fpga_realtime", "/work-dir"),
                Configuration::CoreOnSubsystem => {
                    if caliptra_sw.is_none() {
                        bail!("have to set `caliptra-sw` flag when using core-on-subsystem");
                    }
                    ("fpga_subsystem,itrng", "/caliptra-sw")
                }
            };

            cmd.arg(format!("(cd /{work_dir} && echo 'Cross compiling tests' && CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc cargo nextest archive --features={features} --target=aarch64-unknown-linux-gnu --archive-file=/work-dir/caliptra-test-binaries.tar.zst --target-dir cross-target/ )"));
            cmd.status()?;

            if let Some(target_host) = target_host {
                rsync_file(target_host, "caliptra-test-binaries.tar.zst", ".", false)?;
            }
        }
        Fpga::Bootstrap {
            target_host,
            configuration,
        } => {
            println!("Bootstrapping FPGA");
            println!("configuration: {:?}", configuration);
            let hostname = run_command_with_output(target_host.as_deref(), "hostname")?;

            // skip this step for CI images. Kernel modules are already installed.
            if hostname.trim_end() != "caliptra-fpga" {
                fpga_install_kernel_modules(target_host.as_deref())?;
            }

            let cache_function = |config_marker| {
                run_command(
                    target_host.as_deref(),
                    &format!("echo \"{config_marker}\" > /tmp/fpga-config"),
                )
            };

            // Need to clone repo to run tests.
            match configuration {
                Configuration::Subsystem => run_command(target_host.as_deref(), "[ -d caliptra-mcu-sw ] || git clone https://github.com/chipsalliance/caliptra-mcu-sw --branch=main --depth=1").expect("failed to clone caliptra-mcu-sw repo"),
                Configuration::CoreOnSubsystem => run_command(target_host.as_deref(), "[ -d caliptra-sw ] || git clone https://github.com/chipsalliance/caliptra-sw --branch=main-2.x --depth=1").expect("failed to clone caliptra-mcu-sw repo"),
            }

            configuration
                .cache(cache_function)
                .expect("failed to cache fpga configuration");
        }
        Fpga::Test {
            target_host,
            test_filter,
            test_output,
        } => {
            println!("Running test suite on FPGA");
            is_module_loaded("io_module", target_host.as_deref())?;
            // Clear old test logs
            run_command(target_host.as_deref(), "(sudo rm /tmp/junit.xml || true)")?;
            let config = Configuration::from_cmd(target_host.as_deref())?;
            let tf = match (test_filter, &config) {
                (Some(tf), _) => tf,
                (_, Configuration::Subsystem) => {
                    "package(mcu-hw-model) - test(model_emulated::test::test_new_unbooted)"
                }
                (_, Configuration::CoreOnSubsystem) => "package(caliptra-drivers)",
            };

            let to = if *test_output {
                "--success-output=immediate"
            } else {
                ""
            };

            let (prelude, test_dir) = match config {
                Configuration::Subsystem => ("CPTRA_FIRMWARE_BUNDLE=$HOME/all-fw.zip", "caliptra-mcu-sw"),
                Configuration::CoreOnSubsystem => {
                    ("CPTRA_MCU_ROM=/home/runner/mcu-rom-fpga.bin CPTRA_UIO_NUM=0 CALIPTRA_PREBUILT_FW_DIR=/tmp/caliptra-test-firmware/caliptra-test-firmware CALIPTRA_IMAGE_NO_GIT_REVISION=1", "caliptra-sw")
                }
            };

            let test_command = format!(
                "(cd {test_dir} && \
                sudo {prelude} \
                cargo-nextest nextest run \
                --workspace-remap=. --archive-file $HOME/caliptra-test-binaries.tar.zst \
                --test-threads=1 --no-fail-fast --profile=nightly {} \
                -E \"{}\")",
                to, tf
            );

            // Run test suite.
            // Ignore error so we still copy the logs.
            let _ = run_command(target_host.as_deref(), test_command.as_str());

            if let Some(target_host) = target_host {
                println!("Copying test log from FPGA to junit.xml");
                rsync_file(target_host, "/tmp/junit.xml", ".", true)?;
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
