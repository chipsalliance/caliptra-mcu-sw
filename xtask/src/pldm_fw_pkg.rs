// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use caliptra_mcu_pldm_fw_pkg::manifest::*;

pub(crate) fn create(manifest_path: &str, output_path: &str) -> Result<()> {
    let firmware_manifest = FirmwareManifest::parse_manifest_file(&manifest_path.to_string())
        .map_err(|_| anyhow::anyhow!("Failed to parse manifest file: {}", manifest_path))?;
    if let Err(err) = firmware_manifest.generate_firmware_package(&output_path.to_string()) {
        bail!("Failed to generate firmware package: {}", err);
    }
    println!("Encoded FirmwarePackage to binary file: {}", output_path);
    Ok(())
}

pub(crate) fn decode(pldm_package_path: &str, output_path: &str) -> Result<()> {
    let firmware_manifest = FirmwareManifest::decode_firmware_package(
        &pldm_package_path.to_string(),
        Some(&output_path.to_string()),
    );
    if firmware_manifest.is_err() {
        bail!("Failed to parse PLDM package file: {}", pldm_package_path);
    }
    println!("Decoded FirmwarePackage to binary file: {}", output_path);
    Ok(())
}
