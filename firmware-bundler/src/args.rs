// Licensed under the Apache-2.0 license

//! The arguments for the various operations which the firmware-bundler supports.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::{manifest::Manifest, utils};

/// Arguments common among all subcommands.
#[derive(Args, Default, Debug, Clone)]
pub struct Common {
    /// The manifest file describing the platform to be deployed to, and which binaries to
    /// deploy to it.
    pub manifest: PathBuf,

    /// The location of the workspace Cargo.toml file for the set of applications being built.
    /// If not specified the tool will attempt to find the workspace directory by finding the
    /// directory highest in the stack with a `Cargo.toml` specified.
    #[arg(long)]
    pub workspace_dir: Option<PathBuf>,
}

impl Common {
    /// Retrieve a validated Manifest instance based on the manifest path passed on the command
    /// line.
    pub fn manifest(&self) -> Result<Manifest> {
        let contents = std::fs::read_to_string(&self.manifest)?;
        let manifest: Manifest = toml::from_str(&contents)?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Retrieve the workspace directory, either from the command line specification or
    /// algorithmically based on the current execution directory.
    pub fn workspace_dir(&self) -> Result<PathBuf> {
        match &self.workspace_dir {
            Some(wd) => Ok(wd.join("target")),
            None => utils::find_target_directory(),
        }
    }

    /// Create a new Common struct for testing purposes.
    #[cfg(test)]
    pub fn new_for_test(workspace_dir: PathBuf) -> Self {
        Common {
            manifest: workspace_dir.join("manifest.toml"),
            workspace_dir: Some(workspace_dir),
        }
    }
}

/// Arguments required for commands which execute the LD step of the build process.
#[derive(Args, Default, Debug, Clone)]
pub struct LdArgs {
    /// The base ROM linker layout.  This will be customized via individual applications ROM, and
    /// RAM memory usages.  If not specified a generally applicable default file will be utilized.
    #[arg(long)]
    pub rom_ld_base: Option<PathBuf>,

    /// The base kernel linker layout.  This will be customized via individaul ITCM and RAM memory
    /// usage.  If not specified the default tockOS kernel layout file will be used.
    #[arg(long)]
    pub kernel_ld_base: Option<PathBuf>,

    /// The base app linker layout.  This will be customized via individaul ITCM and RAM memory
    /// usage.  If not specified the default tockOS app layout file will be used.
    #[arg(long)]
    pub app_ld_base: Option<PathBuf>,
}

/// Arguments required for commands which execute the build step of the bundle process.
#[derive(Args, Default, Debug, Clone)]
pub struct BuildArgs {
    /// If specified the objcopy binary to use.  If not specified the bundler will attempt to use
    /// `llvm-objcopy` from the rustc compiler.
    #[arg(long, env = "OBJCOPY")]
    pub objcopy: Option<PathBuf>,

    /// If specified the features to enable for the binaries being compiled.  Multiple features can
    /// be specified as follows: `feature_a,feature_b,etc...`.
    #[arg(long)]
    pub features: Option<String>,
}

/// Arguments required for commands which execute the bundle step of the bundle process.
#[derive(Args, Default, Debug, Clone)]
pub struct BundleArgs {
    /// The name to give the bundled runtime binary output by the bundle step.  A file with the
    /// given name will be placed in the `<workspace>/target/<target-tuple>/release` directory.
    #[arg(long)]
    pub bundle_name: Option<String>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Build the collection of binaries associated with a firmware bundle.  This will not bundle
    /// them, only build them.  These will be published to
    /// `<workspace>/target/<target-tuple>/release`.
    Build {
        #[command(flatten)]
        common: Common,

        #[command(flatten)]
        ld: LdArgs,

        #[command(flatten)]
        build: BuildArgs,

        /// If specified, build only the module specified by the given name.
        ///
        /// Note: If `dynamic_sizing` is enabled, other applications may be built during the sizing
        /// operation to determine the memory region available to the given application.
        target: Option<String>,
    },

    /// Build and bundle the collection of binaries required for a deployment.  The bundles will
    /// be published to `<workspace>/target/<target-tuple>/release`.
    Bundle {
        #[command(flatten)]
        common: Common,

        #[command(flatten)]
        ld: LdArgs,

        #[command(flatten)]
        build: BuildArgs,

        #[command(flatten)]
        bundle: BundleArgs,
    },
}
