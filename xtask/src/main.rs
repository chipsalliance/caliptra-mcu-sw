// Licensed under the Apache-2.0 license

use std::{
    path::{Path, PathBuf},
    sync::LazyLock,
};

use clap::{Parser, Subcommand};

mod apps_build;
mod cargo_lock;
mod clippy;
mod docs;
mod flash_image;
mod format;
mod header;
mod precheckin;
mod registers;
mod rom;
mod runtime;
mod runtime_build;
mod tbf;
mod test;

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
        /// Run with tracing options
        #[arg(short, long, default_value_t = false)]
        trace: bool,
    },
    /// Build Runtime image
    RuntimeBuild,
    /// Build ROM
    RomBuild,
    /// Build and Run ROM image
    Rom {
        /// Run with tracing options
        #[arg(short, long, default_value_t = false)]
        trace: bool,
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
    },
}

#[derive(Subcommand)]
enum FlashImageCommands {
    /// Create a new flash image
    Create {
        /// Path to the Caliptra firmware file
        #[arg(long, value_name = "CALIPTRA_FW", required = true)]
        caliptra_fw: String,

        /// Path to the SoC manifest file
        #[arg(long, value_name = "SOC_MANIFEST", required = true)]
        soc_manifest: String,

        /// Path to the MCU runtime file
        #[arg(long, value_name = "MCU_RUNTIME", required = true)]
        mcu_runtime: String,

        /// Paths to optional SoC images
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
    },
}

pub type DynError = Box<dyn std::error::Error>;
pub const TARGET: &str = "riscv32imc-unknown-none-elf";

static PROJECT_ROOT: LazyLock<PathBuf> = LazyLock::new(|| {
    Path::new(&env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
});

fn convert_option_vec(input: &Option<Vec<String>>) -> Option<Vec<&str>> {
    // Convert a series of String arguments into &str
    input
        .as_ref()
        .map(|vec| vec.iter().map(|s| s.as_str()).collect())
}

fn main() {
    let cli = Xtask::parse();
    let result = match &cli.xtask {
        Commands::Runtime { trace } => runtime::runtime_run(*trace),
        Commands::RuntimeBuild => runtime_build::runtime_build_with_apps(),
        Commands::Rom { trace } => rom::rom_run(*trace),
        Commands::RomBuild => rom::rom_build(),
        Commands::FlashImage { subcommand } => match subcommand {
            FlashImageCommands::Create {
                caliptra_fw,
                soc_manifest,
                mcu_runtime,
                soc_images,
                output,
            } => flash_image::flash_image_create(
                caliptra_fw,
                soc_manifest,
                mcu_runtime,
                &convert_option_vec(soc_images),
                output,
            ),
            FlashImageCommands::Verify { file } => flash_image::flash_image_verify(file),
        },
        Commands::Clippy => clippy::clippy(),
        Commands::Docs => docs::docs(),
        Commands::Precheckin => precheckin::precheckin(),
        Commands::Format => format::format(),
        Commands::CargoLock => cargo_lock::cargo_lock(),
        Commands::HeaderFix => header::fix(),
        Commands::HeaderCheck => header::check(),
        Commands::Test => test::test(),
        Commands::RegistersAutogen { check } => registers::autogen(*check),
    };
    result.unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    });
}
