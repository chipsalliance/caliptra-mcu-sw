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
pub mod size;
pub mod tbf;
pub(crate) mod utils;

use anyhow::{bail, Result};
use args::{BuildArgs, Common, LdArgs};
use build::BuildOutput;
use manifest::{AllocationRequest, Manifest};

use crate::args::Commands;

pub fn execute(cmd: Commands) -> Result<()> {
    match cmd {
        Commands::Build { common, ld, build } => build_step(&common, &ld, &build).map(|_| ()),
        Commands::Bundle { common, ld, build } => {
            let (manifest, output) = build_step(&common, &ld, &build)?;
            bundle::bundle(&manifest, &output, &common)?;
            Ok(())
        }
    }
}

/// A utility function to run the logic for a build step.
fn build_step(common: &Common, ld: &LdArgs, build: &BuildArgs) -> Result<(Manifest, BuildOutput)> {
    let mut manifest = common.manifest()?;

    if manifest.platform.dynamic_sizing() {
        dynamically_size(&mut manifest, common, ld, build)?;
    }

    let build_definition = ld::generate(&manifest, common, ld)?;
    let build_output = build::build(&manifest, &build_definition, common, build)?;
    Ok((manifest, build_output))
}

/// Execute a dynamic sizing pass.  This will build each runtime application with a maximal linker
/// script, and then determine the size of each applications instruction and data memory.  It will
/// then update the manifest file to match the minimal size of each applications memory requirement
/// with alignment to the Tock required 4Kb.
fn dynamically_size(
    manifest: &mut Manifest,
    common: &Common,
    ld: &LdArgs,
    build: &BuildArgs,
) -> Result<()> {
    // This alignment is derived from Tocks' requirements within the linker script.
    const ALIGNMENT: u64 = 4096;

    // Generate the maximal linker file, build with it, and then get the size out of the resulting
    // binary.
    //
    // Note: We cannot just build without a linker script, since the application assumes some of
    // the symbols stated in the linker exist, and won't compile without them.
    let maximal_build_definition = ld::generate_maximal_link_scripts(manifest, common, ld)?;
    let maximal_output = build::build(manifest, &maximal_build_definition, common, build)?;
    let sizes = size::sizes(&maximal_output)?;

    // Update the kernels memory requirments.
    manifest.kernel.exec_mem = Some(AllocationRequest {
        size: sizes.kernel.instructions.next_multiple_of(ALIGNMENT),
        alignment: None,
    });
    manifest.kernel.data_mem = Some(AllocationRequest {
        size: sizes.kernel.data.next_multiple_of(ALIGNMENT),
        alignment: None,
    });

    // Update the requirements for each application.
    manifest
        .apps
        .iter_mut()
        .zip(sizes.apps)
        .try_for_each(|(manifest_app, size_app)| {
            // As a sanity test ensure we are talking about the same binary.  Each round iterates
            // through the apps in the same order, so this should always succeed.
            if manifest_app.name != size_app.name {
                bail!(
                    "Manifest and size application are not aligned ({}, {})",
                    manifest_app.name,
                    size_app.name
                );
            }

            manifest_app.exec_mem = Some(AllocationRequest {
                size: size_app.instructions.next_multiple_of(ALIGNMENT),
                alignment: None,
            });

            manifest_app.data_mem = Some(AllocationRequest {
                size: size_app.data.next_multiple_of(ALIGNMENT),
                alignment: None,
            });

            Ok(())
        })?;

    Ok(())
}
