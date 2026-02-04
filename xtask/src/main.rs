// Licensed under the Apache-2.0 license

use caliptra_api_types::DeviceLifecycle;
use clap::{Parser, Subcommand};
use clap_num::maybe_hex;
use core::panic;
use mcu_builder::ImageCfg;
use mcu_firmware_bundler::args::Commands as BundleCommands;
use std::path::PathBuf;

mod auth_manifest;
mod cargo_lock;
mod clippy;
mod deps;
mod docs;
mod emulator_cbinding;
mod format;
#[cfg(feature = "fpga_realtime")]
mod fpga;
mod fuses;
mod header;
mod pldm_fw_pkg;
mod precheckin;
mod registers;
mod rom;
mod runtime;
mod test;

#[cfg(feature = "fpga_realtime")]
use fpga::Fpga;

use auth_manifest::AuthManifestCommands;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Xtask {
    #[command(subcommand)]
    xtask: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build and Run Runtime image
    Runtime {
        /// HW revision in semver format (e.g., "2.0.0")
        #[arg(long, value_parser = semver::Version::parse, default_value = "2.0.0")]
        hw_revision: semver::Version,

        /// Run with tracing options
        #[arg(short, long, default_value_t = false)]
        trace: bool,

        /// TCP port to listen on for communication I3C socket
        #[arg(long)]
        i3c_port: Option<u16>,

        /// Features to build runtime with
        #[arg(long)]
        features: Vec<String>,

        #[arg(long, default_value_t = false)]
        no_stdin: bool,

        #[arg(long)]
        caliptra_rom: Option<PathBuf>,

        #[arg(long)]
        caliptra_firmware: Option<PathBuf>,

        #[arg(
            long,
            value_parser = maybe_hex::<u32>,
            default_value_t = DeviceLifecycle::Production as u32
        )]
        device_security_state: u32,

        #[arg(long)]
        soc_manifest: Option<PathBuf>,

        #[arg(long)]
        vendor_pk_hash: Option<String>,

        /// Path to the PLDM Firmware package to be used in streaming boot
        #[arg(long)]
        streaming_boot: Option<PathBuf>,

        /// List of SoC images with format: <path>,<load_addr>,<staging_addr>,<image_id>,<exec_bit>,<component_id>,<feature>
        /// Example: --soc_image image1.bin,0x80000000,0x60000000,2,2,2,test-flash-based-boot
        #[arg(long = "soc_image", value_name = "SOC_IMAGE", num_args = 1.., required = false)]
        soc_images: Option<Vec<ImageCfg>>,

        /// Path to the Flash image to be used in streaming boot
        #[arg(long)]
        flash_image: Option<PathBuf>,

        #[arg(long, default_value_t = false)]
        use_dccm_for_stack: bool,

        #[arg(long, value_parser=maybe_hex::<u32>)]
        dccm_offset: Option<u32>,

        #[arg(long, value_parser=maybe_hex::<u32>)]
        dccm_size: Option<u32>,
    },
    /// Build Runtime image
    RuntimeBuild {
        /// Features to build runtime with
        #[arg(long)]
        features: Vec<String>,

        #[arg(long)]
        output: Option<String>,

        /// Platform to build for. Default: emulator
        #[arg(long)]
        platform: Option<String>,

        #[arg(long, default_value_t = false)]
        use_dccm_for_stack: bool,

        #[arg(long, value_parser=maybe_hex::<u32>)]
        dccm_offset: Option<u32>,

        #[arg(long, value_parser=maybe_hex::<u32>)]
        dccm_size: Option<u32>,
    },
    /// Build ROM
    RomBuild {
        /// Platform to build for. Default: emulator
        #[arg(long)]
        platform: Option<String>,

        /// Features to build ROM with.
        #[arg(long)]
        features: Option<String>,
    },
    /// Build Network Coprocessor ROM
    NetworkRomBuild,
    /// Build and Run ROM image
    Rom {
        /// Run with tracing options
        #[arg(short, long, default_value_t = false)]
        trace: bool,
    },
    /// Build emulator binaries for test features and package them in emulators.zip
    EmulatorBuild {
        #[arg(long)]
        output: Option<String>,

        /// Comma-separated list of features to build emulators for
        #[arg(long)]
        features: Option<String>,
    },
    /// Build Caliptra ROM, firmware bundle, MCU ROM, runtime, and SoC manifest and package them together
    AllBuild {
        #[arg(long)]
        output: Option<String>,

        /// Platform to build for. Default: emulator
        #[arg(long)]
        platform: Option<String>,

        #[arg(long, default_value_t = false)]
        use_dccm_for_stack: bool,

        #[arg(long, value_parser=maybe_hex::<u32>)]
        dccm_offset: Option<u32>,

        #[arg(long, value_parser=maybe_hex::<u32>)]
        dccm_size: Option<u32>,

        #[arg(long)]
        rom_features: Option<String>,

        #[arg(long)]
        runtime_features: Option<String>,

        #[arg(long, default_value_t = false)]
        separate_runtimes: bool,

        /// List of SoC images with format: <path>,<load_addr>,<staging_addr>,<image_id>,<exec_bit>,<component_id>,<feature>
        /// Example: --soc_image image1.bin,0x80000000,0x60000000,2,2,2,test-flash-based-boot
        #[arg(long = "soc_image", value_name = "SOC_IMAGE", num_args = 1.., required = false)]
        soc_images: Option<Vec<ImageCfg>>,

        // MCU configuration to include in the SoC manifest
        // format: mcu,<load_addr>,<staging_addr>,<image_id>,<exec_bit>,<feature>
        // Example: --mcu_cfg mcu,0x10000000,0x10000000,1,1,test-dma
        #[arg(
            long = "mcu_cfg",
            value_name = "MCU_CFG",
            num_args = 1..,
            required = false
        )]
        mcu_cfgs: Option<Vec<ImageCfg>>,

        /// Path to the PLDM manifest TOML file
        #[arg(short, long, value_name = "MANIFEST", required = false)]
        pldm_manifest: Option<String>,
    },
    /// Commands related to flash images
    FlashImage {
        #[command(subcommand)]
        subcommand: FlashImageCommands,
    },
    /// Run clippy on all targets
    Clippy,
    /// Build docs
    Docs,
    /// Check that all files are formatted
    Format,
    /// Run pre-check-in checks
    Precheckin,
    /// Check cargo lock
    CargoLock,
    /// Check files for Apache license header
    HeaderCheck,
    /// Add Apache license header to files where it is missing
    HeaderFix,
    /// Run tests
    Test,
    /// Autogenerate register files and emulator bus from RDL
    RegistersAutogen {
        /// Check output only
        #[arg(short, long, default_value_t = false)]
        check: bool,

        /// Extra RDL files to parse
        #[arg(short, long)]
        files: Vec<PathBuf>,

        /// Extra addrmap entries to add
        /// Must be in the format of "type@addr"
        #[arg(short, long)]
        addrmap: Vec<String>,

        /// Path to fuses.hjson file. Default: hw/fuses.hjson
        #[arg(long)]
        fuses_hjson: Option<PathBuf>,

        /// Path to otp_ctrl_mmap.hjson file. Default: hw/caliptra-ss/src/fuse_ctrl/data/otp_ctrl_mmap.hjson
        #[arg(long)]
        otp_mmap_hjson: Option<PathBuf>,
    },
    /// Check dependencies
    Deps,
    /// Manage FPGA Life cycle
    #[cfg(feature = "fpga_realtime")]
    Fpga {
        #[command(subcommand)]
        subcommand: Fpga,
    },
    // TODO(clundin): Refactor into FPGA module.
    /// Run firmware on the FPGA
    #[cfg(feature = "fpga_realtime")]
    FpgaRun {
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
    /// Utility to create and parse PLDM firmware packages
    PldmFirmware {
        #[command(subcommand)]
        subcommand: PldmFirmwareCommands,
    },
    /// Emulator C binding utilities
    EmulatorCbinding {
        #[command(subcommand)]
        subcommand: EmulatorCbindingCommands,
    },
    /// Auth Manifest generation and parsing
    AuthManifest {
        #[command(subcommand)]
        subcommand: AuthManifestCommands,
    },
    /// A collection of experimental composition commands.  These are not intended for production
    /// use, but can be used to test the functionality of the composition functionality.
    Experimental {
        #[command(subcommand)]
        cmd: BundleCommands,
    },
}

#[derive(Subcommand)]
enum FlashImageCommands {
    /// Create a new flash image
    Create {
        /// Path to the Caliptra firmware file
        #[arg(long, value_name = "CALIPTRA_FW", required = true)]
        caliptra_fw: Option<String>,

        /// Path to the SoC manifest file
        #[arg(long, value_name = "SOC_MANIFEST", required = true)]
        soc_manifest: Option<String>,

        /// Path to the MCU runtime file
        #[arg(long, value_name = "MCU_RUNTIME", required = true)]
        mcu_runtime: Option<String>,

        /// List of SoC images
        /// Example: --soc-images /tmp/a.bin --soc-images /tmp/b.bin
        #[arg(long, value_name = "SOC_IMAGE", num_args=1.., required = false)]
        soc_images: Option<Vec<String>>,

        /// Paths to the output image file
        #[arg(long, value_name = "OUTPUT", required = true)]
        output: String,
    },
    /// Verify an existing flash image
    Verify {
        /// Path to the flash image file
        #[arg(value_name = "FILE")]
        file: String,

        /// Offset of the flash image in the file
        #[arg(long, value_name = "OFFSET", default_value_t = 0)]
        offset: u32,
    },
}

#[derive(Subcommand)]
enum PldmFirmwareCommands {
    /// Encode a manifest TOML file to a firmware package
    Create {
        /// Path to the manifest TOML file
        #[arg(short, long, value_name = "MANIFEST", required = true)]
        manifest: String,

        /// Output file for the firmware package
        #[arg(short, long, value_name = "FILE", required = true)]
        file: String,
    },
    /// Decode a firmware package to a manifest and components
    Decode {
        /// Path to the firmware package file
        #[arg(short, long, value_name = "PACKAGE", required = true)]
        package: String,

        /// Output directory for manifest and components
        #[arg(short, long, value_name = "DIRECTORY", required = true)]
        dir: String,
    },
}

#[derive(Subcommand)]
enum EmulatorCbindingCommands {
    /// Build all emulator C binding components (library, header, and binary)
    Build {
        /// Build in release mode (optimized)
        #[arg(long, default_value_t = false)]
        release: bool,
    },
    /// Build only the Rust static library and generate C header
    BuildLib {
        /// Build in release mode (optimized)
        #[arg(long, default_value_t = false)]
        release: bool,
    },
    /// Build only the C emulator binary
    BuildEmulator {
        /// Build in release mode (optimized)
        #[arg(long, default_value_t = false)]
        release: bool,
    },
    /// Clean all build artifacts
    Clean {
        /// Clean release mode artifacts (otherwise cleans debug artifacts)
        #[arg(long, default_value_t = false)]
        release: bool,
    },
}

fn main() {
    let cli = Xtask::parse();
    let result = match &cli.xtask {
        Commands::AllBuild {
            output,
            platform,
            use_dccm_for_stack,
            dccm_offset,
            dccm_size,
            rom_features,
            runtime_features,
            separate_runtimes,
            soc_images,
            mcu_cfgs,
            pldm_manifest,
        } => mcu_builder::all_build(mcu_builder::AllBuildArgs {
            output: output.as_deref(),
            platform: platform.as_deref(),
            use_dccm_for_stack: *use_dccm_for_stack,
            dccm_offset: *dccm_offset,
            dccm_size: *dccm_size,
            rom_features: rom_features.as_deref(),
            runtime_features: runtime_features.as_deref(),
            separate_runtimes: *separate_runtimes,
            soc_images: soc_images.clone(),
            mcu_cfgs: mcu_cfgs.clone(),
            pldm_manifest: pldm_manifest.as_deref(),
        }),
        Commands::EmulatorBuild { output, features } => {
            mcu_builder::emulator_build(mcu_builder::EmulatorBuildArgs {
                output: output.as_deref(),
                features: features.as_deref(),
            })
        }
        Commands::Runtime { .. } => runtime::runtime_run(cli.xtask),
        Commands::RuntimeBuild {
            features,
            output,
            platform,
            use_dccm_for_stack,
            dccm_offset,
            dccm_size,
        } => {
            let features: Vec<&str> = features.iter().map(|x| x.as_str()).collect();
            mcu_builder::runtime_build_with_apps(
                &features,
                output.clone(),
                false,
                platform.as_deref(),
                match platform.as_deref() {
                    None | Some("emulator") => Some(&mcu_config_emulator::EMULATOR_MEMORY_MAP),
                    Some("fpga") => Some(&mcu_config_fpga::FPGA_MEMORY_MAP),
                    _ => panic!("Unsupported platform"),
                },
                *use_dccm_for_stack,
                *dccm_offset,
                *dccm_size,
                match platform.as_deref() {
                    None | Some("emulator") => {
                        Some(&mcu_config_emulator::flash::LOGGING_FLASH_CONFIG)
                    }
                    Some("fpga") => None,
                    _ => panic!("Unsupported platform"),
                },
                None,
            )
            .map(|_| ())
        }
        Commands::Rom { trace } => rom::rom_run(*trace),
        Commands::RomBuild { platform, features } => {
            mcu_builder::rom_build(platform.as_deref(), features.as_deref().unwrap_or(""))
                .map(|_| ())
        }
        Commands::NetworkRomBuild => mcu_builder::network_rom_build().map(|_| ()),
        Commands::FlashImage { subcommand } => match subcommand {
            FlashImageCommands::Create {
                caliptra_fw,
                soc_manifest,
                mcu_runtime,
                soc_images,
                output,
            } => mcu_builder::flash_image::flash_image_create(
                caliptra_fw,
                soc_manifest,
                mcu_runtime,
                soc_images,
                0,
                output,
            ),
            FlashImageCommands::Verify { file, offset } => {
                mcu_builder::flash_image::flash_image_verify(file, *offset)
            }
        },
        Commands::Clippy => clippy::clippy(),
        Commands::Docs => docs::docs(),
        Commands::Precheckin => precheckin::precheckin(),
        Commands::Format => format::format(),
        Commands::CargoLock => cargo_lock::cargo_lock(),
        Commands::HeaderFix => header::fix(),
        Commands::HeaderCheck => header::check(),
        Commands::Test => test::test(),
        Commands::RegistersAutogen {
            check,
            files,
            addrmap,
            fuses_hjson,
            otp_mmap_hjson,
        } => registers::autogen(
            *check,
            files,
            addrmap,
            fuses_hjson.as_deref(),
            otp_mmap_hjson.as_deref(),
        ),
        Commands::Deps => deps::check(),
        #[cfg(feature = "fpga_realtime")]
        Commands::Fpga { subcommand } => fpga::fpga_entry(subcommand),
        // TODO(clundin): Refactor into FPGA module.
        #[cfg(feature = "fpga_realtime")]
        Commands::FpgaRun { .. } => fpga::fpga_run(cli.xtask),
        Commands::PldmFirmware { subcommand } => match subcommand {
            PldmFirmwareCommands::Create { manifest, file } => pldm_fw_pkg::create(manifest, file),
            PldmFirmwareCommands::Decode { package, dir } => pldm_fw_pkg::decode(package, dir),
        },
        Commands::EmulatorCbinding { subcommand } => match subcommand {
            EmulatorCbindingCommands::Build { release } => emulator_cbinding::build_all(*release),
            EmulatorCbindingCommands::BuildLib { release } => {
                emulator_cbinding::build_lib(*release)
            }
            EmulatorCbindingCommands::BuildEmulator { release } => {
                emulator_cbinding::build_emulator(*release)
            }
            EmulatorCbindingCommands::Clean { release } => emulator_cbinding::clean(*release),
        },
        Commands::AuthManifest { subcommand } => match subcommand {
            AuthManifestCommands::Create {
                images,
                mcu_image,
                output,
            } => auth_manifest::create(images, mcu_image, output),
            AuthManifestCommands::Parse { file } => auth_manifest::parse(file),
        },
        Commands::Experimental { cmd } => mcu_firmware_bundler::execute(cmd.clone()),
    };
    result.unwrap_or_else(|e| {
        eprintln!("Error: {:?}", e);
        std::process::exit(1);
    });
}
