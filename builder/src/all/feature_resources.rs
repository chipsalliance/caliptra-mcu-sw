// Licensed under the Apache-2.0 license

//! Feature-specific test resources.
//!
//! This module provides functionality for building feature-specific firmware
//! variants used in integration tests.

use anyhow::Result;
use std::path::PathBuf;
use tempfile::NamedTempFile;

use super::artifacts::BaseArtifacts;
use super::context::AllBuildContext;
use super::flash::create_flash_image;
use super::pldm::{generate_pldm_package, load_or_create_pldm_manifest};
use super::soc_images::create_default_soc_images;
use crate::{CaliptraBuilder, ImageCfg};

cfg_if::cfg_if! {
    if #[cfg(feature = "parallel-build")] {
        use rayon::prelude::*;
        fn maybe_par_iter<T: Sync>(slice: &[T]) -> impl ParallelIterator<Item = &T> { slice.par_iter() }
    } else {
        fn maybe_par_iter<T>(slice: &[T]) -> impl Iterator<Item = &T> { slice.iter() }
    }
}

/// Features that require the example app to be included.
/// Determined by which tests use `run_test!(test_name, example_app)` in tests/integration/src/lib.rs
pub const FEATURES_WITH_EXAMPLE_APP: &[&str] = &[
    "test-caliptra-certs",
    "test-caliptra-crypto",
    "test-caliptra-mailbox",
    "test-dma",
    "test-doe-discovery",
    "test-doe-transport-loopback",
    "test-doe-user-loopback",
    "test-flash-usermode",
    "test-fpga-flash-ctrl",
    "test-get-device-state",
    "test-log-flash-usermode",
    "test-mbox-sram",
    "test-mci",
    "test-mcu-mbox-soc-requester-loopback",
    "test-mcu-mbox-usermode",
    "test-warm-reset",
];

/// Features that require SoC images to be included in the flash image.
pub const FEATURES_REQUIRING_SOC_IMAGES: &[&str] = &[
    "test-flash-based-boot",
    "test-pldm-streaming-boot",
    "test-firmware-update-flash",
    "test-firmware-update-streaming",
];

/// Features that require flash-based boot (partition table at offset 0).
pub const FEATURES_REQUIRING_FLASH_BOOT: &[&str] =
    &["test-flash-based-boot", "test-firmware-update-flash"];

/// Features that require firmware update support.
const FIRMWARE_UPDATE_FEATURES: &[&str] = &[
    "test-firmware-update-flash",
    "test-firmware-update-streaming",
];

/// Resources built for a specific test feature.
///
/// Each feature gets its own runtime, SoC manifest, flash image, and PLDM package.
pub struct FeatureTestResource {
    /// Feature name this resource was built for.
    pub feature: String,
    /// Temp file containing the runtime binary.
    pub runtime_file: NamedTempFile,
    /// Temp file containing the SoC manifest.
    pub soc_manifest_file: NamedTempFile,
    /// Path to the flash image.
    pub flash_image: PathBuf,
    /// Temp file containing the PLDM firmware package.
    pub pldm_fw_pkg: NamedTempFile,
    /// Optional update flash image (without partition table) for firmware update tests.
    pub update_flash_image: Option<PathBuf>,
}

/// Build all feature-specific test resources.
///
/// For each feature in the separate_features list, builds a complete set of
/// firmware artifacts including runtime, SoC manifest, flash image, and PLDM package.
///
/// # Arguments
///
/// - `ctx`: Build context with configuration.
/// - `base`: Base artifacts to build upon.
///
/// # Returns
///
/// - `Ok(Vec<FeatureTestResource>)`: List of built feature resources.
/// - `Err(anyhow::Error)`: If any feature build fails.
pub fn build_feature_resources(
    ctx: &AllBuildContext,
    base: &BaseArtifacts,
) -> Result<Vec<FeatureTestResource>> {
    let test_runtimes: Result<Vec<FeatureTestResource>> = maybe_par_iter(&ctx.separate_features)
        .map(|feature| build_single_feature_resource(ctx, base, feature))
        .collect();

    test_runtimes
}

/// Build resources for a single feature.
///
/// # Arguments
///
/// - `ctx`: Build context with configuration.
/// - `base`: Base artifacts to build upon.
/// - `feature`: Feature name to build for.
///
/// # Returns
///
/// - `Ok(FeatureTestResource)`: Built feature resource.
/// - `Err(anyhow::Error)`: If the build fails.
fn build_single_feature_resource(
    ctx: &AllBuildContext,
    base: &BaseArtifacts,
    feature: &str,
) -> Result<FeatureTestResource> {
    // Build feature-specific runtime
    let (runtime_file, runtime_path) = build_feature_runtime(ctx, feature)?;

    // Get feature-specific MCU image config
    let mcu_image_cfg = ctx.get_image_cfg_for_feature(feature);

    // Get SoC images (create defaults if needed for features that require them)
    let (feature_soc_images, feature_soc_images_paths) = get_feature_soc_images(ctx, feature)?;

    // Build Caliptra artifacts with feature-specific runtime
    let mut caliptra_builder = CaliptraBuilder::new(
        ctx.fpga,
        Some(base.caliptra_rom.clone()),
        Some(base.caliptra_fw.clone()),
        None,
        Some(base.vendor_pk_hash.clone()),
        Some(runtime_path.clone()),
        feature_soc_images,
        mcu_image_cfg,
        None,
        None,
        None,
    );

    // Generate feature-specific SoC manifest
    let soc_manifest_file = NamedTempFile::new()?;
    caliptra_builder.get_soc_manifest(soc_manifest_file.path().to_str())?;

    // Create flash image (with partition table for flash-boot features)
    let is_flash_based_boot = FEATURES_REQUIRING_FLASH_BOOT.contains(&feature);
    let feature_flash_image = create_flash_image(
        Some(base.caliptra_fw.clone()),
        Some(soc_manifest_file.path().to_path_buf()),
        Some(runtime_path.clone()),
        feature_soc_images_paths.clone(),
        is_flash_based_boot,
    )?;

    // Create update flash image (without partition table) for firmware update features
    let update_flash_image = if FIRMWARE_UPDATE_FEATURES.contains(&feature) {
        Some(create_flash_image(
            Some(base.caliptra_fw.clone()),
            Some(soc_manifest_file.path().to_path_buf()),
            Some(runtime_path),
            feature_soc_images_paths,
            false, // No partition table for update image
        )?)
    } else {
        None
    };

    // Create PLDM package (use update image if available)
    let pldm_fw_pkg = create_feature_pldm_package(
        ctx,
        update_flash_image.as_ref().unwrap_or(&feature_flash_image),
    )?;

    Ok(FeatureTestResource {
        feature: feature.to_string(),
        runtime_file,
        soc_manifest_file,
        flash_image: feature_flash_image,
        pldm_fw_pkg,
        update_flash_image,
    })
}

/// Build a feature-specific runtime.
///
/// # Arguments
///
/// - `ctx`: Build context with configuration.
/// - `feature`: Feature name to build for.
///
/// # Returns
///
/// - `Ok((NamedTempFile, PathBuf))`: Temp file and path to the built runtime.
/// - `Err(anyhow::Error)`: If the build fails.
fn build_feature_runtime(ctx: &AllBuildContext, feature: &str) -> Result<(NamedTempFile, PathBuf)> {
    let target_dir = if cfg!(feature = "parallel-build") {
        Some(crate::target_dir().join(format!("target-runtime-{}", feature)))
    } else {
        None
    };

    let runtime_file = NamedTempFile::new()?;
    let runtime_path_str = runtime_file.path().to_str().unwrap().to_string();
    let include_example_app = FEATURES_WITH_EXAMPLE_APP.contains(&feature);

    crate::runtime_build_with_apps(
        &[feature],
        Some(runtime_path_str),
        include_example_app,
        Some(&ctx.platform),
        None,
        target_dir,
    )?;

    let runtime_path = runtime_file.path().to_path_buf();
    Ok((runtime_file, runtime_path))
}

/// Get SoC images for a feature, creating defaults if needed.
///
/// # Arguments
///
/// - `ctx`: Build context with configuration.
/// - `feature`: Feature name.
///
/// # Returns
///
/// - `Ok((Option<Vec<ImageCfg>>, Vec<PathBuf>))`: SoC images config and paths.
/// - `Err(anyhow::Error)`: If image creation fails.
fn get_feature_soc_images(
    ctx: &AllBuildContext,
    feature: &str,
) -> Result<(Option<Vec<ImageCfg>>, Vec<PathBuf>)> {
    if FEATURES_REQUIRING_SOC_IMAGES.contains(&feature) && ctx.soc_images.is_none() {
        let (images, paths) = create_default_soc_images();
        Ok((Some(images), paths))
    } else {
        Ok((ctx.soc_images.clone(), ctx.get_soc_image_paths()))
    }
}

/// Create a PLDM package for a feature's flash image.
///
/// # Arguments
///
/// - `ctx`: Build context with configuration.
/// - `flash_image_path`: Path to the flash image to package.
///
/// # Returns
///
/// - `Ok(NamedTempFile)`: Temp file containing the PLDM package.
/// - `Err(anyhow::Error)`: If package creation fails.
fn create_feature_pldm_package(
    ctx: &AllBuildContext,
    flash_image_path: &PathBuf,
) -> Result<NamedTempFile> {
    let flash_image_data = std::fs::read(flash_image_path)?;
    let pldm_manifest =
        load_or_create_pldm_manifest(ctx.pldm_manifest.as_deref(), &flash_image_data)?;

    let pldm_fw_pkg = NamedTempFile::new()?;
    generate_pldm_package(&pldm_manifest, pldm_fw_pkg.path())?;

    Ok(pldm_fw_pkg)
}
