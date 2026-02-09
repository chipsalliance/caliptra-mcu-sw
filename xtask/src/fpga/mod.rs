// Licensed under the Apache-2.0 license

use anyhow::{anyhow, bail, Result};
use caliptra_image_gen::to_hw_format;
use caliptra_image_types::FwVerificationPqcKeyType;
use clap::Subcommand;
use configurations::Configuration;
use mcu_builder::flash_image::build_flash_image_bytes;
use mcu_builder::FirmwareBinaries;
use mcu_hw_model::{InitParams, McuHwModel, ModelFpgaRealtime};
use romtime::LifecycleControllerState;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use utils::{
    check_fpga_dependencies, check_host_dependencies, check_ssh_access, run_command,
    run_command_with_output,
};

mod configurations;

mod utils;

struct BuildArgs<'a> {
    mcu: bool,
    fw_id: &'a Option<String>,
}

struct BuildTestArgs<'a> {
    package_filter: &'a Option<String>,
}
struct TestArgs<'a> {
    test_filter: &'a Option<String>,
    test_output: &'a bool,
    default_test_profile: &'a str,
}
trait ActionHandler<'a> {
    fn bootstrap(&self) -> Result<()>;
    fn build(&self, args: &'a BuildArgs<'a>) -> Result<()>;
    fn build_test(&self, args: &'a BuildTestArgs<'a>) -> Result<()>;
    fn test(&self, args: &'a TestArgs) -> Result<()>;
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

        /// Only Build MCU binaries
        #[arg(long, default_value_t = false)]
        mcu: bool,

        /// Only build the specified Caliptra Firmware
        /// By default all Caliptra firmware binaries are built
        #[arg(long)]
        fw_id: Option<String>,
    },
    /// Build FPGA test binaries
    BuildTest {
        /// When set copy test binaries to `target_host`
        #[arg(long)]
        target_host: Option<String>,
        /// Filter packages for the test archive. This can be used to reduce the total archive
        /// size and speed up `build-test` commands.
        ///
        /// Uses a `cargo-nextest` package filter-set, e.g. `package(caliptra-rom)`.
        #[arg(long)]
        package_filter: Option<String>,
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
    check_host_dependencies()?;
    match args {
        Fpga::Build {
            target_host,
            mcu,
            fw_id: calitpra_fw_id,
        } => {
            println!("Building FPGA firmware");
            let config = Configuration::from_cmd(target_host.as_deref())?;
            config
                .executor()
                .set_target_host(target_host.as_deref())
                .build(&BuildArgs {
                    mcu: *mcu,
                    fw_id: calitpra_fw_id,
                })?;
        }
        Fpga::BuildTest {
            target_host,
            package_filter,
        } => {
            println!("Building FPGA tests");
            let config = Configuration::from_cmd(target_host.as_deref())?;
            config
                .executor()
                .set_target_host(target_host.as_deref())
                .build_test(&BuildTestArgs { package_filter })?;
        }
        Fpga::Bootstrap {
            target_host,
            configuration,
        } => {
            println!("Bootstrapping FPGA");
            println!("configuration: {:?}", configuration);

            let target_host = target_host.as_deref();
            check_ssh_access(target_host)?;
            check_fpga_dependencies(target_host)?;

            let hostname = run_command_with_output(target_host, "hostname")?;

            // skip this step for CI images. Kernel modules are already installed.
            let caliptra_fpga = hostname.trim_end() == "caliptra-fpga";
            if !caliptra_fpga {
                fpga_install_kernel_modules(target_host)?;
            }

            let cache_function = |config_marker| {
                // Cache FPGA configuration in RAM. We need to re-bootstrap on power cycles.
                run_command(
                    target_host,
                    &format!("echo \"{config_marker}\" > /dev/shm/fpga-config"),
                )
            };

            configuration.cache(cache_function)?;
            configuration
                .executor()
                .set_target_host(target_host)
                .set_caliptra_fpga(caliptra_fpga)
                .bootstrap()?;
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
            config
                .executor()
                .set_target_host(target_host.as_deref())
                .test(&TestArgs {
                    test_filter,
                    test_output,
                    default_test_profile: config.default_test_profile(),
                })?;
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
            network_rom: vec![],
            test_roms: vec![],
            caliptra_test_roms: vec![],
            test_runtimes: vec![],
            test_soc_manifests: vec![],
            test_pldm_fw_pkgs: vec![],
            test_flash_images: vec![],
            test_update_flash_images: vec![],
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

    // Build flash image from firmware binaries
    let flash_image = build_flash_image_bytes(
        Some(binaries.caliptra_fw.as_slice()),
        Some(binaries.soc_manifest.as_slice()),
        Some(binaries.mcu_runtime.as_slice()),
    );

    let mut model = ModelFpgaRealtime::new_unbooted(InitParams {
        fuses: caliptra_api_types::Fuses {
            vendor_pk_hash: binaries
                .vendor_pk_hash()
                .map(|h| to_hw_format(&h))
                .unwrap_or([0u32; 12]),
            fuse_pqc_key_type: u8::from(FwVerificationPqcKeyType::LMS).into(),
            ..Default::default()
        },
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
        enable_mcu_uart_log: true,
        primary_flash_initial_contents: Some(flash_image),
        ..Default::default()
    })
    .unwrap();
    model.boot()?;

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
            model.start_i3c_controller();
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
