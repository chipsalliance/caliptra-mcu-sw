// Licensed under the Apache-2.0 license

//! A module to combine the outputs of the build process into a single binary which can be loaded
//! into an embedded execution environment.

use std::cmp::Ordering;

use anyhow::{bail, Result};

use crate::{args::Common, build::BuildOutput, manifest::Manifest, tbf::generate_tbf_header};

/// Take a collection of binaries and output a single binary which can be loaded into a memory
/// block.
///
/// This could fail if the binaries aren't able to fit into the blob, or if a hard drive operation
/// fails.
pub fn bundle(manifest: &Manifest, output: &BuildOutput, common: &Common) -> Result<()> {
    // Determine the release directory which elf files will be placed by `rustc` and where we
    // wish to place binaries.
    let binary_dir = match &common.workspace_dir {
        Some(oc) => oc.to_path_buf(),
        None => common.workspace_dir()?,
    }
    .join(&manifest.platform.tuple)
    .join("release");

    // Note: The ROM is a single application, so we don't have to do any bundling.  As such skip it.

    // Build the binary into a byte vector.  The size of the embedded application at most in the
    // Megabytes so this isn't too expensive and will save multiple disk operations.
    let mut runtime = std::fs::read(&output.kernel.0.binary)?;

    let base_addr = output.kernel.1.offset;
    for app in output.apps.clone().into_iter() {
        // Find the location the the binary should occupy in the blob.  There could be padding
        // between the end of one application and the beginning of the next.
        let app_start: usize = (app.instruction_block.offset - base_addr).try_into()?;
        match runtime.len().cmp(&app_start) {
            Ordering::Less => runtime.resize(app_start, 0),
            Ordering::Greater => bail!(
                "Error in bundling, binary already exceeds app {} start offset",
                &app.binary.name
            ),
            Ordering::Equal => { /* no op */ }
        };

        let elf = app.binary.binary.with_extension("");
        let header_bytes = generate_tbf_header(
            app.header,
            app.instruction_block,
            elf,
            app.binary.binary.clone(),
        )?;
        runtime.extend(header_bytes.into_iter());

        let app = std::fs::read(&app.binary.binary)?;
        runtime.extend(app.into_iter());
    }

    let runtime_file = binary_dir.join(format!("runtime-{}.bin", &manifest.platform.name));
    std::fs::write(runtime_file, runtime).map_err(|e| e.into())
}
