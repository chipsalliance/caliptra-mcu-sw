// Licensed under the Apache-2.0 license

//! A collection of functionalities which intend to provide simple support for bundling a
//! caliptra subsystem into a collection of distribution binaries.
//!
//! As a general principle the firmware-bundler is responsible for 2 binaries.
//!     1. ROM - A binary to be burnt into the chip as the first executable code
//!     2. Runtime - A binary to be loaded by the ROM, which contains the functionality of the
//!                  device.
//!
//! For both of these applications the firmware-bundler is responsible for generating appropriate
//! linker scripts and utilizing them during the compilation process.  This allows the compiled
//! binaries to be easily used on systems without virtual addressing, and respecting the
//! configuration which tock expects.
//!
//! For the runtime application, the firmware-bundler will be responsible for concatenating the
//! compiled binaries into a single `.bin` file which can be loaded into ITCM memory space.
//!
//! This package is designed to be easily integrated into the xtask infrastructure within a vendor's
//! repository.  This will provide a number of benefits including simpler integration with `cargo b`
//! commands.  However, a binary application will also be made available if the vendor wishes to
//! only include the distribution composition support, without the build system integration.

pub mod args;
pub mod build;
pub mod bundle;
pub mod ld;
pub mod manifest;
pub mod tbf;
pub(crate) mod utils;

use anyhow::Result;

use crate::args::Commands;

pub fn execute(cmd: Commands) -> Result<()> {
    match cmd {
        Commands::Build { common, ld, build } => {
            let manifest = &common.manifest()?;
            let build_definition = ld::generate(manifest, &common, &ld)?;
            let _ = build::build(&common.manifest()?, &build_definition, &common, &build)?;
            Ok(())
        }
        Commands::Bundle { common, ld, build } => {
            let manifest = common.manifest()?;
            let build_definition = ld::generate(&manifest, &common, &ld)?;
            let output = build::build(&manifest, &build_definition, &common, &build)?;
            bundle::bundle(&manifest, &output, &common)?;
            Ok(())
        }
        Commands::Generate { common, ld } => {
            let definition = ld::generate(&common.manifest()?, &common, &ld)?;
            println!("Build definition: {definition:?}");
            Ok(())
        }
    }
}
