// Licensed under the Apache-2.0 license

mod artifacts;
mod binaries;
mod bundle;
mod context;
mod emulator;
mod feature_resources;
mod flash;
mod pldm;
mod soc_images;
mod test_roms;

use std::path::Path;

use anyhow::Result;

pub use binaries::{EmulatorBinaries, FirmwareBinaries};
pub use context::AllBuildArgs;
pub use emulator::{emulator_build, EmulatorBuildArgs};

use artifacts::BaseArtifacts;
use bundle::create_firmware_bundle;
use context::AllBuildContext;
use feature_resources::build_feature_resources;
use test_roms::{build_all_test_roms, build_feature_roms};

/// Build Caliptra ROM and firmware bundle, MCU ROM and runtime, and SoC manifest,
/// and package them all together in a ZIP file.
///
/// This is the main entry point for the all-in-one firmware build process.
///
/// # Arguments
///
/// - `args`: Build arguments containing configuration options.
///
/// # Returns
///
/// - `Ok(())`: If the build completed successfully.
/// - `Err(anyhow::Error)`: If any build step fails.
///
/// # Build Steps
///
/// 1. Parse arguments and create build context
/// 2. Build all test ROMs (MCU + Caliptra)
/// 3. Build base artifacts (MCU ROM, runtime, Caliptra ROM/FW, SoC manifest, flash image, PLDM package)
/// 4. Build feature-specific ROMs
/// 5. Build feature-specific resources (runtime, manifest, flash image, PLDM package per feature)
/// 6. Package everything into a ZIP archive
pub fn all_build(args: AllBuildArgs) -> Result<()> {
    let ctx = AllBuildContext::new(args);
    let mut test_roms = build_all_test_roms(&ctx.platform)?;
    let base = BaseArtifacts::build(&ctx)?;
    let separate_features: Vec<&str> = ctx.separate_features.iter().map(|s| s.as_str()).collect();

    let feature_roms = build_feature_roms(&ctx.platform, &separate_features)?;
    test_roms.extend(feature_roms);

    let feature_resources = build_feature_resources(&ctx, &base)?;
    let default_path = crate::target_dir().join("all-fw.zip");

    let output_path = ctx
        .output
        .as_ref()
        .map(|s| Path::new(s.as_str()))
        .unwrap_or(&default_path);

    create_firmware_bundle(output_path, &base, &test_roms, &feature_resources)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_build_args_default() {
        let args = AllBuildArgs::default();
        assert!(args.output.is_none());
        assert!(args.platform.is_none());
        assert!(!args.separate_runtimes);
    }

    #[test]
    fn test_context_creation() {
        let args = AllBuildArgs {
            platform: Some("emulator".to_string()),
            separate_runtimes: false,
            ..Default::default()
        };
        let ctx = AllBuildContext::new(args);
        assert_eq!(ctx.platform, "emulator");
        assert!(!ctx.runtime_type);
    }

    #[test]
    fn test_context_fpga() {
        let args = AllBuildArgs {
            platform: Some("fpga".to_string()),
            ..Default::default()
        };
        let ctx = AllBuildContext::new(args);
        assert_eq!(ctx.platform, "fpga");
        assert!(ctx.runtime_type);
    }
}
