// Licensed under the Apache-2.0 license

//! A module for handling the build step of firmware binaries for the bundler.  This will take as
//! an input the name of the package to build, and the previously generated linker files and utilze
//! the standard rust buld system to generate appropriate binaries.  It will rely on the
//! `.cargo/config.toml` associated with the workspace the package is in to determine any features
//! or compilation flags to include.

use std::{path::PathBuf, process::Command};

use anyhow::{anyhow, bail, Result};
use tbf_header::TbfHeader;

use crate::{
    args::{BuildArgs, Common},
    ld::{BuildDefinition, LinkerScript},
    manifest::{Manifest, Memory},
    utils::objcopy,
};

// The OBJCOPY flags to produce smaller binaries when translating to binary format.
const ROM_OBJCOPY_FLAGS: &str = "--strip-sections --strip-all";
const KERNEL_OBJCOPY_FLAGS: &str =
    "--strip-sections --strip-all --remove-section .apps --remove-section .attributes";
const APP_OBJCOPY_FLAGS: &str = "--strip-sections --strip-all";

/// A pairing of application name to the linker script it should be built with.
#[derive(Debug, Clone)]
pub struct BuiltBinary {
    pub name: String,
    pub elf: PathBuf,
    pub binary: PathBuf,
}

/// A built TockOS application.
#[derive(Debug, Clone)]
pub struct BuiltApp {
    pub binary: BuiltBinary,
    pub header: TbfHeader,
    pub instruction_block: Memory,
}

/// The build definition for a collection of applications.  The ROM and Runtime are both fully
/// specified with their linker files.  This is the output of the generation step.
#[derive(Debug, Clone)]
pub struct BuildOutput {
    pub rom: Option<BuiltBinary>,
    pub kernel: (BuiltBinary, Memory),
    pub apps: Vec<BuiltApp>,
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

/// Execute the `rustc` compiler against the specified target package within the manifest.  If
/// successful the elf file and binary will exist in the `<workspace>/target/<tuple>/release`
/// directory on the hard drive.
///
/// This could fail if the package is unable to compile for any reason, including exceeding the
/// memory restrictions placed on the binary by the generated ld file.  It could also fail if a hard
/// drive operation errors.  An error will also occur if the target is not defined in the manifest
/// file.
pub fn build_single_target(
    manifest: &Manifest,
    build_definition: &BuildDefinition,
    common: &Common,
    build: &BuildArgs,
    target: &str,
) -> Result<()> {
    // Put together a list of all the packages specified by this manifest, along with their objcopy
    // flags.
    let mut binaries = build_definition
        .apps
        .iter()
        .map(|a| (a.linker.clone(), &build.runtime_features, APP_OBJCOPY_FLAGS))
        .collect::<Vec<_>>();
    binaries.push((
        build_definition.kernel.0.clone(),
        &build.runtime_features,
        KERNEL_OBJCOPY_FLAGS,
    ));
    if let Some(rom) = &build_definition.rom {
        binaries.push((rom.clone(), &build.rom_features, ROM_OBJCOPY_FLAGS));
    }

    // Find the package to build, if none of the binaries matches the specified target error out.
    let (target_to_build, features, objcopy_flags) = binaries
        .into_iter()
        .find(|(b, _, _)| b.name == target)
        .ok_or_else(|| anyhow!("Binary target {target} not found in manifest file."))?;

    let pass = BuildPass::new(manifest, build_definition, common, build)?;
    pass.build_binary(&target_to_build, features, objcopy_flags)
        .map(|_| ())
}

/// A helper struct containing the context required to do a build run.
struct BuildPass<'a> {
    manifest: &'a Manifest,
    build_definition: &'a BuildDefinition,
    build_args: &'a BuildArgs,
    binary_dir: PathBuf,
    objcopy: PathBuf,
}

impl<'a> BuildPass<'a> {
    /// Create a new `BuildPass`.
    fn new(
        manifest: &'a Manifest,
        build_definition: &'a BuildDefinition,
        common: &Common,
        build_args: &'a BuildArgs,
    ) -> Result<Self> {
        // Determine the release directory which elf files will be placed by `rustc` and where we
        // wish to place binaries.
        let binary_dir = common.release_dir()?;

        let objcopy = match &build_args.objcopy {
            Some(o) => o.clone(),
            None => objcopy()?,
        };

        Ok(Self {
            manifest,
            build_definition,
            build_args,
            binary_dir,
            objcopy,
        })
    }

    /// Execute a BuildPass run.  This will include both building the elf with the specified linker
    /// file via `rustc` and then using `objcopy` to produce a binary file from that elf.
    fn run(&self) -> Result<BuildOutput> {
        let rom = self
            .build_definition
            .rom
            .as_ref()
            .map(|r| self.build_binary(r, &self.build_args.rom_features, ROM_OBJCOPY_FLAGS))
            .transpose()?;

        let (kernal_linker, kernel_instructions) = &self.build_definition.kernel;
        let kernel = (
            self.build_binary(
                kernal_linker,
                &self.build_args.runtime_features,
                KERNEL_OBJCOPY_FLAGS,
            )?,
            kernel_instructions.clone(),
        );

        let apps = self
            .build_definition
            .apps
            .iter()
            .map(|a| {
                Ok(BuiltApp {
                    binary: self.build_binary(
                        &a.linker,
                        &self.build_args.runtime_features,
                        APP_OBJCOPY_FLAGS,
                    )?,
                    header: a.header.clone(),
                    instruction_block: a.instruction_block.clone(),
                })
            })
            .collect::<Result<_>>()?;

        Ok(BuildOutput { rom, kernel, apps })
    }

    /// Execute the build step for a single binary.
    fn build_binary(
        &self,
        app: &LinkerScript,
        features: &Option<String>,
        objcopy_flags: &str,
    ) -> Result<BuiltBinary> {
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
            .arg("--release");

        if let Some(f) = features {
            cmd.arg("--features").arg(f);
        }

        cmd.arg("--").args(linker_args.split(' '));

        if !cmd.status()?.success() {
            bail!("cargo failed to build binary (cmd: {cmd:?})");
        }

        // Finally use objcopy to produce a binary from the output elf.
        let elf = self.binary_dir.join(&app.name);
        let binary = elf.with_extension("bin");
        let mut objcopy_cmd = Command::new(&self.objcopy);
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
            elf,
            binary,
        })
    }
}
