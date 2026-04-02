// Licensed under the Apache-2.0 license

//! Firmware bundle creation (ZIP packaging).
//!
//! This module provides functionality for packaging firmware artifacts
//! into a ZIP file for distribution.

use anyhow::Result;
use std::io::Write;
use std::path::{Path, PathBuf};
use zip::{
    write::{FileOptions, SimpleFileOptions},
    ZipWriter,
};

use super::artifacts::BaseArtifacts;
use super::binaries::FirmwareBinaries;
use super::feature_resources::FeatureTestResource;

/// Add a file to a ZIP archive.
///
/// # Arguments
///
/// - `input_file`: Path to the file to add.
/// - `name`: Name to use in the archive.
/// - `zip`: ZIP writer to add the file to.
/// - `options`: File options for compression settings.
///
/// # Returns
///
/// - `Ok(())`: If the file was added successfully.
/// - `Err(anyhow::Error)`: If reading or writing fails.
fn add_to_zip(
    input_file: &PathBuf,
    name: &str,
    zip: &mut ZipWriter<std::fs::File>,
    options: FileOptions<'_, ()>,
) -> Result<()> {
    let data = std::fs::read(input_file)?;
    println!("Adding {}: {} bytes", name, data.len());
    zip.start_file(name, options)?;
    zip.write_all(&data)?;
    Ok(())
}

/// Create a firmware bundle ZIP file.
///
/// Packages all base artifacts, test ROMs, and feature-specific resources
/// into a single ZIP file.
///
/// # Arguments
///
/// - `output_path`: Path for the output ZIP file.
/// - `base`: Base firmware artifacts.
/// - `test_roms`: List of (path, filename) pairs for test ROMs.
/// - `feature_resources`: List of feature-specific test resources.
///
/// # Returns
///
/// - `Ok(())`: If the bundle was created successfully.
/// - `Err(anyhow::Error)`: If any packaging step fails.
pub fn create_firmware_bundle(
    output_path: &Path,
    base: &BaseArtifacts,
    test_roms: &[(PathBuf, String)],
    feature_resources: &[FeatureTestResource],
) -> Result<()> {
    println!("Creating ZIP file: {}", output_path.display());
    let file = std::fs::File::create(output_path)?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o644)
        .last_modified_time(zip::DateTime::try_from(chrono::Local::now().naive_local())?);

    // Add base artifacts
    add_base_artifacts(&mut zip, base, options)?;

    // Add test ROMs
    for (test_rom, name) in test_roms {
        add_to_zip(test_rom, name, &mut zip, options)?;
    }

    // Add feature-specific resources
    for resource in feature_resources {
        add_feature_resource(&mut zip, resource, options)?;
    }

    zip.finish()?;
    Ok(())
}

/// Add base artifacts to the ZIP archive.
///
/// # Arguments
///
/// - `zip`: ZIP writer.
/// - `base`: Base firmware artifacts.
/// - `options`: File options for compression.
///
/// # Returns
///
/// - `Ok(())`: If all artifacts were added successfully.
/// - `Err(anyhow::Error)`: If any addition fails.
fn add_base_artifacts(
    zip: &mut ZipWriter<std::fs::File>,
    base: &BaseArtifacts,
    options: FileOptions<'_, ()>,
) -> Result<()> {
    add_to_zip(
        &base.caliptra_rom,
        FirmwareBinaries::CALIPTRA_ROM_NAME,
        zip,
        options,
    )?;
    add_to_zip(
        &base.caliptra_fw,
        FirmwareBinaries::CALIPTRA_FW_NAME,
        zip,
        options,
    )?;
    add_to_zip(&base.mcu_rom, FirmwareBinaries::MCU_ROM_NAME, zip, options)?;
    add_to_zip(
        &base.mcu_runtime,
        FirmwareBinaries::MCU_RUNTIME_NAME,
        zip,
        options,
    )?;
    add_to_zip(
        &base.soc_manifest,
        FirmwareBinaries::SOC_MANIFEST_NAME,
        zip,
        options,
    )?;
    add_to_zip(
        &base.flash_image,
        FirmwareBinaries::FLASH_IMAGE_NAME,
        zip,
        options,
    )?;
    add_to_zip(
        &base.pldm_fw_pkg,
        FirmwareBinaries::PLDM_FW_PKG_NAME,
        zip,
        options,
    )?;

    Ok(())
}

/// Add a feature resource to the ZIP archive.
///
/// # Arguments
///
/// - `zip`: ZIP writer.
/// - `resource`: Feature test resource to add.
/// - `options`: File options for compression.
///
/// # Returns
///
/// - `Ok(())`: If all files were added successfully.
/// - `Err(anyhow::Error)`: If any addition fails.
fn add_feature_resource(
    zip: &mut ZipWriter<std::fs::File>,
    resource: &FeatureTestResource,
    options: FileOptions<'_, ()>,
) -> Result<()> {
    let feature = &resource.feature;

    let runtime_name = format!("mcu-test-runtime-{}.bin", feature);
    println!(
        "Adding {} -> {}",
        resource.runtime_file.path().display(),
        runtime_name
    );
    add_to_zip(
        &resource.runtime_file.path().to_path_buf(),
        &runtime_name,
        zip,
        options,
    )?;

    let soc_manifest_name = format!("mcu-test-soc-manifest-{}.bin", feature);
    println!(
        "Adding {} -> {}",
        resource.soc_manifest_file.path().display(),
        soc_manifest_name
    );
    add_to_zip(
        &resource.soc_manifest_file.path().to_path_buf(),
        &soc_manifest_name,
        zip,
        options,
    )?;

    let flash_image_name = format!("mcu-test-flash-image-{}.bin", feature);
    println!(
        "Adding {} -> {}",
        resource.flash_image.display(),
        flash_image_name
    );
    add_to_zip(&resource.flash_image, &flash_image_name, zip, options)?;

    if let Some(ref update_flash) = resource.update_flash_image {
        let update_flash_name = format!("mcu-test-update-flash-image-{}.bin", feature);
        println!("Adding {} -> {}", update_flash.display(), update_flash_name);
        add_to_zip(update_flash, &update_flash_name, zip, options)?;
    }

    let pldm_fw_pkg_name = format!("mcu-test-pldm-fw-pkg-{}.bin", feature);
    println!(
        "Adding {} -> {}",
        resource.pldm_fw_pkg.path().display(),
        pldm_fw_pkg_name
    );
    add_to_zip(
        &resource.pldm_fw_pkg.path().to_path_buf(),
        &pldm_fw_pkg_name,
        zip,
        options,
    )?;

    Ok(())
}
