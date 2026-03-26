// Licensed under the Apache-2.0 license

//! Build context for the all-in-one firmware build process.
//!
//! This module provides the `AllBuildContext` struct which encapsulates
//! the configuration and state needed throughout the build process.

use crate::ImageCfg;

#[derive(Default)]
pub struct AllBuildArgs {
    pub output: Option<String>,
    pub platform: Option<String>,
    pub rom_features: Option<String>,
    /// Feature flags for runtime build (comma-separated).
    pub runtime_features: Option<String>,
    /// Build separate runtimes for each feature flag.
    pub separate_runtimes: bool,
    pub soc_images: Option<Vec<ImageCfg>>,
    pub mcu_cfgs: Option<Vec<ImageCfg>>,
    pub pldm_manifest: Option<String>,
}

/// Build context holding shared configuration for the build process.
///
/// This struct encapsulates all the configuration needed throughout
/// the firmware build process, avoiding the need to thread parameters
/// through multiple function calls.
pub struct AllBuildContext {
    pub platform: String,
    /// Whether building for FPGA (vs emulator).
    pub fpga: bool,
    /// Feature flags for ROM build.
    pub rom_features: String,
    /// SoC images configuration.
    pub soc_images: Option<Vec<ImageCfg>>,
    /// MCU configuration images.
    pub mcu_cfgs: Option<Vec<ImageCfg>>,
    /// Path to custom PLDM manifest.
    pub pldm_manifest: Option<String>,
    /// Output path for the firmware bundle.
    pub output: Option<String>,
    /// Base runtime features (used when not building separate runtimes).
    pub base_runtime_features: Vec<String>,
    /// Separate features (each gets its own runtime).
    pub separate_features: Vec<String>,
}

impl AllBuildContext {
    /// Create a new build context from build arguments.
    ///
    /// # Arguments
    ///
    /// - `args`: Build arguments containing configuration options.
    ///
    /// # Returns
    ///
    /// - `AllBuildContext`: Initialized build context.
    pub fn new(args: AllBuildArgs) -> Self {
        let platform = args.platform.unwrap_or_else(|| "emulator".to_string());
        let fpga = platform == "fpga";
        let rom_features = args.rom_features.unwrap_or_default();

        // Determine runtime features
        let runtime_features: Vec<String> = match args.runtime_features {
            Some(r) if !r.is_empty() => r.split(',').map(|s| s.to_string()).collect(),
            _ => {
                if args.separate_runtimes {
                    if fpga {
                        crate::features::FPGA_RUNTIME_TEST_FEATURES
                            .iter()
                            .map(|s| s.to_string())
                            .collect()
                    } else {
                        crate::features::EMULATOR_RUNTIME_TEST_FEATURES
                            .iter()
                            .map(|s| s.to_string())
                            .collect()
                    }
                } else {
                    vec![]
                }
            }
        };

        let (base_runtime_features, separate_features) = if args.separate_runtimes {
            // Build a separate runtime for each feature flag
            (vec![], runtime_features)
        } else {
            // Build one runtime with all feature flags
            (runtime_features, vec![])
        };

        Self {
            platform,
            fpga,
            rom_features,
            soc_images: args.soc_images,
            mcu_cfgs: args.mcu_cfgs,
            pldm_manifest: args.pldm_manifest,
            output: args.output,
            base_runtime_features,
            separate_features,
        }
    }

    /// Get the image configuration for a specific feature.
    ///
    /// # Arguments
    ///
    /// - `feature`: Feature name to look up.
    ///
    /// # Returns
    ///
    /// - `Option<ImageCfg>`: The matching image configuration, if found.
    pub fn get_image_cfg_for_feature(&self, feature: &str) -> Option<ImageCfg> {
        self.mcu_cfgs
            .as_ref()
            .and_then(|cfgs| cfgs.iter().find(|img| img.feature == feature).cloned())
    }

    /// Get SoC image paths from the configuration.
    ///
    /// # Returns
    ///
    /// - `Vec<std::path::PathBuf>`: Paths to all configured SoC images.
    pub fn get_soc_image_paths(&self) -> Vec<std::path::PathBuf> {
        self.soc_images
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|img| img.path.clone())
            .collect()
    }
}
