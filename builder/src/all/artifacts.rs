// Licensed under the Apache-2.0 license

//! Base firmware artifacts.
//!
//! This module defines the `BaseArtifacts` struct which holds all the
//! core firmware components built during the all-in-one build process.

use anyhow::Result;
use std::path::PathBuf;
use tempfile::NamedTempFile;

use super::context::AllBuildContext;
use super::flash::create_flash_image;
use super::pldm::{generate_pldm_package, load_or_create_pldm_manifest};
use crate::CaliptraBuilder;

/// Base firmware artifacts produced by the build process.
///
/// This struct holds paths to all the core firmware components that are
/// built once and potentially reused when building feature-specific variants.
pub struct BaseArtifacts {
    /// Path to the Caliptra ROM binary.
    pub caliptra_rom: PathBuf,
    /// Path to the Caliptra firmware bundle.
    pub caliptra_fw: PathBuf,
    /// Vendor public key hash (hex string).
    pub vendor_pk_hash: String,
    /// Path to the MCU ROM binary.
    pub mcu_rom: PathBuf,
    /// Path to the MCU runtime binary.
    pub mcu_runtime: PathBuf,
    /// Temp file holding the MCU runtime (to keep it alive).
    pub _mcu_runtime_file: NamedTempFile,
    /// Path to the SoC manifest.
    pub soc_manifest: PathBuf,
    /// Path to the flash image.
    pub flash_image: PathBuf,
    /// Path to the PLDM firmware package.
    pub pldm_fw_pkg: PathBuf,
    /// Temp file holding the PLDM package (to keep it alive).
    pub _pldm_fw_pkg_file: NamedTempFile,
}

impl BaseArtifacts {
    /// Build all base artifacts from the given context.
    ///
    /// # Arguments
    ///
    /// - `ctx`: Build context with configuration.
    ///
    /// # Returns
    ///
    /// - `Ok(BaseArtifacts)`: All built artifacts.
    /// - `Err(anyhow::Error)`: If any build step fails.
    pub fn build(ctx: &AllBuildContext) -> Result<Self> {
        // Build MCU ROM
        let mcu_rom = crate::rom_build(
            Some(ctx.platform.clone()),
            Some(ctx.rom_features.clone()),
            None,
        )?;

        // Build base MCU runtime
        let runtime_file = NamedTempFile::new()?;
        let runtime_path = runtime_file.path().to_str().unwrap().to_string();

        // Convert Vec<String> to Vec<&str> for the API
        let base_features: Vec<&str> = ctx
            .base_runtime_features
            .iter()
            .map(|s| s.as_str())
            .collect();

        let mcu_runtime_str = crate::runtime_build_with_apps(
            &base_features,
            Some(runtime_path),
            false,
            Some(&ctx.platform),
            None,
            None,
        )?;
        let mcu_runtime = PathBuf::from(&mcu_runtime_str);

        // Build Caliptra artifacts
        let mcu_image_cfg = ctx.get_image_cfg_for_feature("none");
        let mut caliptra_builder = CaliptraBuilder::new(
            ctx.runtime_type,
            None,
            None,
            None,
            None,
            Some(mcu_runtime.clone()),
            ctx.soc_images.clone(),
            mcu_image_cfg,
            None,
            None,
            None,
        );

        let caliptra_rom = caliptra_builder.get_caliptra_rom()?;
        let caliptra_fw = caliptra_builder.get_caliptra_fw()?;
        let vendor_pk_hash = caliptra_builder.get_vendor_pk_hash()?.to_string();
        println!("Vendor PK hash: {:x?}", vendor_pk_hash);

        let soc_manifest = caliptra_builder.get_soc_manifest(None)?;

        // Create flash image (not for flash-based boot)
        let flash_image = create_flash_image(
            Some(caliptra_fw.clone()),
            Some(soc_manifest.clone()),
            Some(mcu_runtime.clone()),
            ctx.get_soc_image_paths(),
            false,
        )?;

        // Create PLDM firmware package
        let flash_image_data = std::fs::read(&flash_image)?;
        let pldm_manifest =
            load_or_create_pldm_manifest(ctx.pldm_manifest.as_deref(), &flash_image_data)?;

        let pldm_fw_pkg_file = NamedTempFile::new()?;
        generate_pldm_package(&pldm_manifest, pldm_fw_pkg_file.path())?;

        Ok(Self {
            caliptra_rom,
            caliptra_fw,
            vendor_pk_hash,
            mcu_rom,
            mcu_runtime,
            _mcu_runtime_file: runtime_file,
            soc_manifest,
            flash_image,
            pldm_fw_pkg: pldm_fw_pkg_file.path().to_path_buf(),
            _pldm_fw_pkg_file: pldm_fw_pkg_file,
        })
    }
}
