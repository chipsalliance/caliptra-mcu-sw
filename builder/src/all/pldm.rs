// Licensed under the Apache-2.0 license

//! PLDM firmware manifest helpers.
//!
//! This module provides utilities for creating and decoding PLDM firmware
//! manifests used in firmware update packages.

use anyhow::Result;
use chrono::{TimeZone, Utc};
use pldm_fw_pkg::{
    manifest::{
        ComponentImageInformation, Descriptor, DescriptorType, FirmwareDeviceIdRecord,
        PackageHeaderInformation, StringType,
    },
    FirmwareManifest,
};
use std::io::Read;
use std::path::Path;

/// Device UUID for PLDM firmware packages.
/// This is an arbitrary UUID that should match the one used in the device's ID record.
const DEVICE_UUID: [u8; 16] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
];

/// Get the device UUID used for PLDM firmware packages.
///
/// # Returns
///
/// - `[u8; 16]`: The device UUID bytes.
pub fn get_device_uuid() -> [u8; 16] {
    DEVICE_UUID
}

/// Create a default PLDM firmware manifest for the given image data.
///
/// The identifier and classification should match the device's component image information.
///
/// # Arguments
///
/// - `dev_uuid`: Device UUID bytes.
/// - `image`: Firmware image data to include in the manifest.
///
/// # Returns
///
/// - `FirmwareManifest`: The constructed firmware manifest.
pub fn get_default_pldm_fw_manifest(dev_uuid: &[u8], image: &[u8]) -> FirmwareManifest {
    FirmwareManifest {
        package_header_information: PackageHeaderInformation {
            package_header_identifier: uuid::Uuid::parse_str("7B291C996DB64208801B02026E463C78")
                .unwrap(),
            package_header_format_revision: 1,
            package_release_date_time: Utc.with_ymd_and_hms(2025, 3, 1, 0, 0, 0).unwrap(),
            package_version_string_type: StringType::Utf8,
            package_version_string: Some("0.0.0-release".to_string()),
            package_header_size: 0, // This will be computed during encoding
        },

        firmware_device_id_records: vec![FirmwareDeviceIdRecord {
            firmware_device_package_data: None,
            device_update_option_flags: 0x0,
            component_image_set_version_string_type: StringType::Utf8,
            component_image_set_version_string: Some("1.2.0".to_string()),
            applicable_components: Some(vec![0]),
            // The descriptor should match the device's ID record found in runtime/apps/pldm/pldm-lib/src/config.rs
            initial_descriptor: Descriptor {
                descriptor_type: DescriptorType::Uuid,
                descriptor_data: dev_uuid.to_vec(),
            },
            additional_descriptors: None,
            reference_manifest_data: None,
        }],
        downstream_device_id_records: None,
        component_image_information: vec![ComponentImageInformation {
            // Classification and identifier should match the device's component image information found in runtime/apps/pldm/pldm-lib/src/config.rs
            classification: 0x000A, // Firmware
            identifier: 0xffff,

            // Comparison stamp should be greater than the device's comparison stamp
            comparison_stamp: Some(0xffffffff),
            options: 0x0,
            requested_activation_method: 0x0002,
            version_string_type: StringType::Utf8,
            version_string: Some("soc-fw-1.2".to_string()),

            size: image.len() as u32,
            image_data: Some(image.to_vec()),
            ..Default::default()
        }],
    }
}

/// Load or create a PLDM firmware manifest.
///
/// If a manifest path is provided, decode it from the file. Otherwise, create
/// a default manifest using the provided flash image data.
///
/// # Arguments
///
/// - `pldm_manifest_path`: Optional path to an existing PLDM manifest file.
/// - `flash_image_data`: Flash image data to use if creating a default manifest.
///
/// # Returns
///
/// - `Ok(FirmwareManifest)`: The loaded or created manifest.
/// - `Err(anyhow::Error)`: If loading or decoding fails.
pub fn load_or_create_pldm_manifest(
    pldm_manifest_path: Option<&str>,
    flash_image_data: &[u8],
) -> Result<FirmwareManifest> {
    match pldm_manifest_path {
        Some(path) => {
            let mut file = std::fs::File::open(path)?;
            let mut _data = Vec::new();
            file.read_to_end(&mut _data)?;
            Ok(FirmwareManifest::decode_firmware_package(
                &path.to_string(),
                None,
            )?)
        }
        None => {
            let dev_uuid = get_device_uuid();
            Ok(get_default_pldm_fw_manifest(&dev_uuid, flash_image_data))
        }
    }
}

/// Generate a PLDM firmware package file from a manifest.
///
/// # Arguments
///
/// - `manifest`: The firmware manifest to encode.
/// - `output_path`: Path where the package file will be written.
///
/// # Returns
///
/// - `Ok(())`: If the package was generated successfully.
/// - `Err(anyhow::Error)`: If generation fails.
pub fn generate_pldm_package(manifest: &FirmwareManifest, output_path: &Path) -> Result<()> {
    let path_str = output_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid path"))?
        .to_string();
    manifest.generate_firmware_package(&path_str)?;
    Ok(())
}
