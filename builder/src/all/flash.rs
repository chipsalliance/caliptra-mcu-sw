// Licensed under the Apache-2.0 license

//! Flash image creation utilities.
//!
//! This module provides functions for creating flash images with optional
//! partition tables for different boot modes.

use anyhow::Result;
use mcu_config::boot::{PartitionId, PartitionStatus, RollbackEnable};
use mcu_config_emulator::flash::{PartitionTable, StandAloneChecksumCalculator, IMAGE_A_PARTITION};
use std::path::{Path, PathBuf};

/// Create a flash image from firmware components.
///
/// # Arguments
///
/// - `caliptra_fw_path`: Optional path to the Caliptra firmware bundle.
/// - `soc_manifest_path`: Optional path to the SoC manifest.
/// - `mcu_runtime_path`: Optional path to the MCU runtime binary.
/// - `soc_images_paths`: Paths to additional SoC images to include.
/// - `is_flash_based_boot`: If true, creates a partition table at offset 0.
///
/// # Returns
///
/// - `Ok(PathBuf)`: Path to the created flash image (temporary file).
/// - `Err(anyhow::Error)`: If flash image creation fails.
pub fn create_flash_image(
    caliptra_fw_path: Option<PathBuf>,
    soc_manifest_path: Option<PathBuf>,
    mcu_runtime_path: Option<PathBuf>,
    soc_images_paths: Vec<PathBuf>,
    is_flash_based_boot: bool,
) -> Result<PathBuf> {
    let flash_image_path = tempfile::NamedTempFile::new()
        .expect("Failed to create flash image file")
        .path()
        .to_path_buf();

    // For flash-based boot, we need to:
    // 1. Write flash content at the partition offset (not 0)
    // 2. Write a valid partition table at offset 0
    let flash_offset = if is_flash_based_boot {
        IMAGE_A_PARTITION.offset
    } else {
        0
    };

    crate::flash_image::flash_image_create(
        &caliptra_fw_path.map(|p| p.to_string_lossy().to_string()),
        &soc_manifest_path.map(|p| p.to_string_lossy().to_string()),
        &mcu_runtime_path.map(|p| p.to_string_lossy().to_string()),
        &Some(
            soc_images_paths
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect(),
        ),
        flash_offset,
        flash_image_path.to_str().unwrap(),
    )?;

    // For flash-based boot, write a valid partition table at offset 0
    if is_flash_based_boot {
        write_partition_table(&flash_image_path)?;
    }

    Ok(flash_image_path)
}

/// Write a partition table to a flash image at offset 0.
///
/// # Arguments
///
/// - `flash_image_path`: Path to the flash image file.
///
/// # Returns
///
/// - `Ok(())`: If the partition table was written successfully.
/// - `Err(anyhow::Error)`: If writing fails.
fn write_partition_table(flash_image_path: &Path) -> Result<()> {
    let mut partition_table = PartitionTable {
        active_partition: PartitionId::A as u32,
        partition_a_status: PartitionStatus::Valid as u16,
        partition_b_status: PartitionStatus::Invalid as u16,
        rollback_enable: RollbackEnable::Enabled as u32,
        ..Default::default()
    };
    let checksum_calculator = StandAloneChecksumCalculator::new();
    partition_table.populate_checksum(&checksum_calculator);

    crate::flash_image::write_partition_table(
        &partition_table,
        0,
        flash_image_path.to_str().unwrap(),
    )?;

    Ok(())
}
