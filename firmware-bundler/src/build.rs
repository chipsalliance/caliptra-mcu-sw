// Licensed under the Apache-2.0 license

//! A module for handling the build step of firmware binaries for the bundler.  This will take as
//! an input the name of the package to build, and the previously generated linker files and utilze
//! the standard rust buld system to generate appropriate binaries.  It will rely on the
//! `.cargo/config.toml` associated with the workspace the package is in to determine any features
//! or compilation flags to include.

use std::{path::PathBuf, process::Command};

use anyhow::{anyhow, bail, Result};

use crate::{
    args::{BuildArgs, Common},
    ld::{AppLinkerScript, BuildDefinition},
    manifest::Manifest,
    utils::objcopy,
};

// The OBJCOPY flags to produce smaller binaries when translating to binary format.
const ROM_OBJCOPY_FLAGS: &str = "--strip-sections --strip-all";
const KERNEL_OBJCOPY_FLAGS: &str =
    "--strip-sections --strip-all --remove-section .apps --remove-section .attributes";
const APP_OBJCOPY_FLAGS: &str = "--strip-sections --strip-all";

/// A pairing of application name to the linker script it should be built with.
#[derive(Debug, Clone)]
// TODO: Remove when used by the bundle phase
#[allow(dead_code)]
pub struct BuiltBinary {
    name: String,
    binary: PathBuf,
}

/// The build definition for a collection of applications.  The ROM and Runtime are both fully
/// specified with their linker files.  This is the output of the generation step.
#[derive(Debug, Clone)]
// TODO: Remove when used by the bundle phase
#[allow(dead_code)]
pub struct BuildOutput {
    rom: Option<BuiltBinary>,
    kernel: BuiltBinary,
    apps: Vec<BuiltBinary>,
}

/// Execute the `rustc` compiler against the specified packages with the associated linker files.
/// If successful the elf files and binaries will exist in the `<workspace>/target/<tuple>/release`
/// directory on the hard drive.  The BuildOutput will include the package name, along with the
/// path to the binary to eventually be bundled.
///
/// This could fail if the package is unable to be compiled for any reason, including exceeding
/// the memory restrictions placed on the binary by the generated ld file.  It could also fail if
/// a hard drive operation errors.
pub fn build(
    manifest: &Manifest,
    build_definition: &BuildDefinition,
    common: &Common,
    build: &BuildArgs,
) -> Result<BuildOutput> {
    BuildPass::new(manifest, build_definition, common, build)?.run()
}

/// A helper struct containing the context required to do a build run.
struct BuildPass<'a> {
    manifest: &'a Manifest,
    build_definition: &'a BuildDefinition,
    binary_dir: PathBuf,
}

impl<'a> BuildPass<'a> {
    /// Create a new `BuildPass`.
    fn new(
        manifest: &'a Manifest,
        build_definition: &'a BuildDefinition,
        common: &Common,
        build: &BuildArgs,
    ) -> Result<Self> {
        // Determine the release directory which elf files will be placed by `rustc` and where we
        // wish to place binaries.
        let binary_dir = match &build.objcopy {
            Some(oc) => oc.to_path_buf(),
            None => common.workspace_dir()?,
        }
        .join(&manifest.platform.tuple)
        .join("release");

        Ok(Self {
            manifest,
            build_definition,
            binary_dir,
        })
    }

    /// Execute a BuildPass run.  This will include both building the elf with the specified linker
    /// file via `rustc` and then using `objcopy` to produce a binary file from that elf.
    fn run(&self) -> Result<BuildOutput> {
        let rom = self
            .build_definition
            .rom
            .as_ref()
            .map(|r| self.build_binary(r, ROM_OBJCOPY_FLAGS))
            .transpose()?;

        let kernel = self.build_binary(&self.build_definition.kernel, KERNEL_OBJCOPY_FLAGS)?;

        let apps = self
            .build_definition
            .apps
            .iter()
            .map(|a| self.build_binary(a, APP_OBJCOPY_FLAGS))
            .collect::<Result<_>>()?;

        Ok(BuildOutput { rom, kernel, apps })
    }

    /// Execute the build step for a single binary.
    fn build_binary(&self, app: &AppLinkerScript, objcopy_flags: &str) -> Result<BuiltBinary> {
        // Setup the linker args based on the associated path provided by the linker generation
        // phase.
        let linker_args = format!(
            "-C link-arg=-T{} -C link-arg=-L{}",
            &app.linker_script.display(),
            app.linker_script
                .parent()
                .ok_or_else(|| anyhow!("Invalid linker script {}", app.linker_script.display()))?
                .display()
        );

        // Instantiate the rustc command
        let mut cmd = Command::new("cargo");
        cmd.arg("rustc")
            .arg("--package")
            .arg(&app.name)
            .arg("--target")
            .arg(&self.manifest.platform.tuple)
            .arg("--release")
            .arg("--")
            .args(linker_args.split(' '));

        if !cmd.status()?.success() {
            bail!("cargo failed to build binary (cmd: {cmd:?})");
        }

        // Finally use objcopy to produce a binary from the output elf.
        let elf = self.binary_dir.join(&app.name);
        let binary = elf.with_extension("bin");
        let mut objcopy_cmd = Command::new(objcopy()?);
        objcopy_cmd
            .arg("--output-target=binary")
            .args(objcopy_flags.split(' '))
            .arg(&elf)
            .arg(&binary);

        if let Err(e) = objcopy_cmd.status() {
            bail!("objcopy cmd {objcopy_cmd:?} failed with {e:?}");
        }

        Ok(BuiltBinary {
            name: app.name.clone(),
            binary,
        })
    }
}
