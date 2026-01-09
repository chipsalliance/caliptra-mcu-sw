// Licensed under the Apache-2.0 license

//! The arguments for the various operations which the firmware-bundler supports.

use std::path::PathBuf;

use clap::{Args, Subcommand};

/// Arguments common among all subcommands.
#[derive(Args, Debug, Clone)]
pub struct Common {
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

    /// The location of the workspace Cargo.toml file for the set of applications being built.
    /// If not specified the tool will attempt to find the workspace directory by finding the
    /// directory highest in the stack with a `Cargo.toml` specified.
    #[arg(long)]
    pub workspace_dir: Option<PathBuf>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Generate the linker files required for a firmware bundled build.  These will be published
    /// to `<workspace>/target/<target-tuple>/linker-scripts`
    Generate {
        /// The manifest file describing the platform to be deployed to, and which binaries to
        /// deploy to it.
        manifest: PathBuf,

        #[command(flatten)]
        common: Common,
    },
}
