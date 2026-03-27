// Licensed under the Apache-2.0 license

//! Size history tracking for MCU firmware binaries.
//!
//! This module implements the `ArtifactBuilder` trait from the size-history library
//! to track the sizes of MCU ROM and runtime binaries across git history.

use std::{env, error::Error, path::Path};

use size_history::{
    ArtifactBuilder, Cache, FsCache, GitHubStepSummary, GithubActionCache, HtmlTableReport,
    OutputDestination, SizeHistory, Stdout,
};

/// Cache format version - increment when the build process changes
/// in a way that would invalidate cached sizes.
const CACHE_FORMAT_VERSION: &str = "mcu-v1";

pub fn run() -> Result<(), Box<dyn Error>> {
    let cache = create_cache()?;
    let reporter = HtmlTableReport::new("https://github.com/chipsalliance/caliptra-mcu-sw");
    let output: Box<dyn OutputDestination> = if env::var("GITHUB_STEP_SUMMARY").is_ok() {
        Box::new(GitHubStepSummary)
    } else {
        Box::new(Stdout)
    };

    SizeHistory::new(reporter, output, cache)
        .worktree_path("/tmp/mcu-size-history-wt")
        .cache_version(CACHE_FORMAT_VERSION)
        .with_pr_squashing(true)
        // MCU ROM
        .add_builder(Box::new(
            McuRomBuilder::new("MCU ROM (emulator)").platform("emulator"),
        ))
        .add_builder(Box::new(
            McuRomBuilder::new("MCU ROM (fpga)")
                .platform("fpga")
                .features("fpga_realtime"),
        ))
        // MCU Runtime
        .add_builder(Box::new(
            McuRuntimeBuilder::new("MCU Runtime (emulator)").platform("emulator"),
        ))
        .add_builder(Box::new(
            McuRuntimeBuilder::new("MCU Runtime (fpga)")
                .platform("fpga")
                .feature("fpga_realtime"),
        ))
        .run()?;

    Ok(())
}

fn create_cache() -> Result<Box<dyn Cache>, Box<dyn Error>> {
    Ok(GithubActionCache::new().map(box_cache).or_else(|e| {
        let fs_cache_path = "/tmp/mcu-size-cache";
        println!(
            "Unable to create github action cache: {e}; using fs-cache instead at {fs_cache_path}"
        );
        FsCache::new(fs_cache_path.into()).map(box_cache)
    })?)
}

fn box_cache(val: impl Cache + 'static) -> Box<dyn Cache> {
    Box::new(val)
}

/// Builds MCU ROM firmware and measures the binary size.
///
/// # Example
///
/// ```ignore
/// McuRomBuilder::new("MCU ROM (emulator)")
///     .platform("emulator")
///     .features("feature1,feature2")
/// ```
pub struct McuRomBuilder {
    name: String,
    platform: Option<String>,
    features: Option<String>,
}

impl McuRomBuilder {
    /// Create a new ROM builder with the given display name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            platform: None,
            features: None,
        }
    }

    /// Set the target platform (e.g., "emulator", "fpga").
    pub fn platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = Some(platform.into());
        self
    }

    /// Set build features (comma-separated, e.g., "feature1,feature2").
    pub fn features(mut self, features: impl Into<String>) -> Self {
        self.features = Some(features.into());
        self
    }
}

impl ArtifactBuilder for McuRomBuilder {
    fn name(&self) -> &str {
        &self.name
    }

    fn build_and_measure(&self, _workspace: &Path) -> Option<u64> {
        // Note: mcu_builder uses PROJECT_ROOT internally, not the workspace parameter
        match mcu_builder::rom_build(self.platform.clone(), self.features.clone(), None) {
            Ok(bin_path) => match std::fs::metadata(&bin_path) {
                Ok(metadata) => {
                    let size = metadata.len();
                    println!("Built {}: {} bytes", self.name, size);
                    Some(size)
                }
                Err(e) => {
                    println!("Error reading {} binary metadata: {}", self.name, e);
                    None
                }
            },
            Err(e) => {
                println!("Error building {}: {}", self.name, e);
                None
            }
        }
    }
}

/// Builds MCU Runtime firmware and measures the binary size.
///
/// # Example
///
/// ```ignore
/// McuRuntimeBuilder::new("MCU Runtime (emulator)")
///     .platform("emulator")
///     .feature("feature1")
///     .feature("feature2")
///     .example_app(false)
///     .svn(1)
/// ```
pub struct McuRuntimeBuilder {
    name: String,
    platform: Option<String>,
    features: Vec<String>,
    example_app: bool,
    svn: Option<u16>,
}

impl McuRuntimeBuilder {
    /// Create a new runtime builder with the given display name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            platform: None,
            features: Vec::new(),
            example_app: false,
            svn: None,
        }
    }

    /// Set the target platform (e.g., "emulator", "fpga").
    pub fn platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = Some(platform.into());
        self
    }

    /// Add a single build feature.
    pub fn feature(mut self, feature: impl Into<String>) -> Self {
        self.features.push(feature.into());
        self
    }

    /// Set whether to include the example app in the build.
    #[allow(dead_code)]
    pub fn example_app(mut self, include: bool) -> Self {
        self.example_app = include;
        self
    }

    /// Set the security version number (SVN).
    #[allow(dead_code)]
    pub fn svn(mut self, svn: u16) -> Self {
        self.svn = Some(svn);
        self
    }
}

impl ArtifactBuilder for McuRuntimeBuilder {
    fn name(&self) -> &str {
        &self.name
    }

    fn build_and_measure(&self, _workspace: &Path) -> Option<u64> {
        // Note: mcu_builder uses PROJECT_ROOT internally, not the workspace parameter
        let features: Vec<&str> = self.features.iter().map(|s| s.as_str()).collect();
        match mcu_builder::runtime_build_with_apps(
            &features,
            None, // output_name - use default
            self.example_app,
            self.platform.as_deref(),
            self.svn,
            None, // target_dir - use default
        ) {
            Ok(bin_path) => match std::fs::metadata(&bin_path) {
                Ok(metadata) => {
                    let size = metadata.len();
                    println!("Built {}: {} bytes", self.name, size);
                    Some(size)
                }
                Err(e) => {
                    println!("Error reading {} binary metadata: {}", self.name, e);
                    None
                }
            },
            Err(e) => {
                println!("Error building {}: {}", self.name, e);
                None
            }
        }
    }
}
