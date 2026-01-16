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
pub mod ld;
pub mod manifest;
pub(crate) mod utils;

use std::path::Path;

use anyhow::Result;
use manifest::Manifest;

use crate::args::Commands;

pub fn execute(cmd: Commands) -> Result<()> {
    match cmd {
        Commands::Generate { manifest, common } => {
            let definition = ld::generate(manifest_from_file(&manifest)?, common)?;
            println!("Build definition: {definition:?}");
            Ok(())
        }
    }
}

fn manifest_from_file(path: &Path) -> Result<Manifest> {
    let contents = std::fs::read_to_string(path)?;
    let manifest: Manifest = toml::from_str(&contents)?;
    manifest.validate()?;
    Ok(manifest)
}
