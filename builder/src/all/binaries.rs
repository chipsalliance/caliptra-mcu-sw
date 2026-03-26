// Licensed under the Apache-2.0 license

//! Firmware and emulator binary management.
//!
//! This module provides structs for reading and managing prebuilt firmware
//! and emulator binaries from ZIP archives.

use anyhow::Result;
use caliptra_builder::FwId;
use caliptra_image_types::ImageManifest;
use std::env::var;
use std::io::Read;
use std::path::PathBuf;
use std::sync::OnceLock;
use zerocopy::FromBytes;

use crate::CaliptraBuilder;

/// Prebuilt firmware binaries stored in a ZIP archive.
#[derive(Default)]
pub struct FirmwareBinaries {
    /// Caliptra ROM binary.
    pub caliptra_rom: Vec<u8>,
    /// Caliptra firmware bundle.
    pub caliptra_fw: Vec<u8>,
    /// MCU ROM binary.
    pub mcu_rom: Vec<u8>,
    /// MCU runtime binary.
    pub mcu_runtime: Vec<u8>,
    /// SoC manifest binary.
    pub soc_manifest: Vec<u8>,
    /// MCU test ROMs: (filename, data).
    pub test_roms: Vec<(String, Vec<u8>)>,
    /// Caliptra test ROMs: (filename, data).
    pub caliptra_test_roms: Vec<(String, Vec<u8>)>,
    /// Test SoC manifests: (filename, data).
    pub test_soc_manifests: Vec<(String, Vec<u8>)>,
    /// Test runtimes: (filename, data).
    pub test_runtimes: Vec<(String, Vec<u8>)>,
    /// Test PLDM firmware packages: (filename, data).
    pub test_pldm_fw_pkgs: Vec<(String, Vec<u8>)>,
    /// Test flash images: (filename, data).
    pub test_flash_images: Vec<(String, Vec<u8>)>,
    /// Update flash images without partition table (for PLDM update packages).
    pub test_update_flash_images: Vec<(String, Vec<u8>)>,
}

impl FirmwareBinaries {
    /// Standard file names used in the firmware bundle.
    pub const CALIPTRA_ROM_NAME: &'static str = "caliptra_rom.bin";
    pub const CALIPTRA_FW_NAME: &'static str = "caliptra_fw.bin";
    pub const MCU_ROM_NAME: &'static str = "mcu_rom.bin";
    pub const MCU_RUNTIME_NAME: &'static str = "mcu_runtime.bin";
    pub const SOC_MANIFEST_NAME: &'static str = "soc_manifest.bin";
    pub const FLASH_IMAGE_NAME: &'static str = "flash_image.bin";
    pub const PLDM_FW_PKG_NAME: &'static str = "pldm_fw_pkg.bin";

    /// Reads the environment variable `CPTRA_FIRMWARE_BUNDLE`.
    ///
    /// Returns `FirmwareBinaries` if `CPTRA_FIRMWARE_BUNDLE` points to a valid zip file.
    ///
    /// This function is safe to call multiple times. The returned `FirmwareBinaries` is cached
    /// after the first invocation to avoid multiple decompressions.
    ///
    /// # Returns
    ///
    /// - `Ok(&'static FirmwareBinaries)`: Cached firmware binaries.
    /// - `Err(anyhow::Error)`: If the environment variable is not set or the file cannot be read.
    pub fn from_env() -> Result<&'static Self> {
        let bundle_path = var("CPTRA_FIRMWARE_BUNDLE")
            .map_err(|_| anyhow::anyhow!("Set the environment variable CPTRA_FIRMWARE_BUNDLE"))?;

        static BINARIES: OnceLock<FirmwareBinaries> = OnceLock::new();
        let binaries = BINARIES.get_or_init(|| {
            Self::read_from_zip(&bundle_path.clone().into()).expect("failed to unzip archive")
        });

        Ok(binaries)
    }

    /// Read firmware binaries from a ZIP archive file.
    ///
    /// # Arguments
    ///
    /// - `path`: Path to the ZIP archive containing firmware binaries.
    ///
    /// # Returns
    ///
    /// - `Ok(FirmwareBinaries)`: Populated firmware binaries structure.
    /// - `Err(anyhow::Error)`: If the file cannot be opened or parsed.
    pub fn read_from_zip(path: &PathBuf) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        let mut zip = zip::ZipArchive::new(file)?;
        let mut binaries = FirmwareBinaries::default();

        for i in 0..zip.len() {
            let mut file = zip.by_index(i)?;
            let name = file.name().to_string();
            let mut data = Vec::new();
            file.read_to_end(&mut data)?;

            match name.as_str() {
                Self::CALIPTRA_ROM_NAME => binaries.caliptra_rom = data,
                Self::CALIPTRA_FW_NAME => binaries.caliptra_fw = data,
                Self::MCU_ROM_NAME => binaries.mcu_rom = data,
                Self::MCU_RUNTIME_NAME => binaries.mcu_runtime = data,
                Self::SOC_MANIFEST_NAME => binaries.soc_manifest = data,
                name if name.contains("mcu-test-soc-manifest") => {
                    binaries.test_soc_manifests.push((name.to_string(), data));
                }
                name if name.contains("mcu-test-runtime") => {
                    binaries.test_runtimes.push((name.to_string(), data));
                }
                name if name.contains("mcu-test-rom") => {
                    binaries.test_roms.push((name.to_string(), data));
                }
                name if name.contains("cptra-test-rom") => {
                    binaries.caliptra_test_roms.push((name.to_string(), data));
                }
                name if name.contains("mcu-test-pldm-fw-pkg") => {
                    binaries.test_pldm_fw_pkgs.push((name.to_string(), data));
                }
                name if name.contains("mcu-test-update-flash-image") => {
                    binaries
                        .test_update_flash_images
                        .push((name.to_string(), data));
                }
                name if name.contains("mcu-test-flash-image") => {
                    binaries.test_flash_images.push((name.to_string(), data));
                }
                _ => continue,
            }
        }

        Ok(binaries)
    }

    /// Extract the vendor public key hash from the Caliptra firmware bundle.
    ///
    /// # Returns
    ///
    /// - `Some([u8; 48])`: Vendor public key hash if successfully extracted.
    /// - `None`: If the firmware manifest could not be parsed.
    pub fn vendor_pk_hash(&self) -> Option<[u8; 48]> {
        if let Ok((manifest, _)) = ImageManifest::ref_from_prefix(&self.caliptra_fw) {
            CaliptraBuilder::vendor_pk_hash(manifest).ok()
        } else {
            None
        }
    }

    /// Extract the owner public key hash from the Caliptra firmware bundle.
    ///
    /// # Returns
    ///
    /// - `Some([u8; 48])`: Owner public key hash if successfully extracted.
    /// - `None`: If the firmware manifest could not be parsed.
    pub fn owner_pk_hash(&self) -> Option<[u8; 48]> {
        if let Ok((manifest, _)) = ImageManifest::ref_from_prefix(&self.caliptra_fw) {
            CaliptraBuilder::owner_pk_hash(manifest).ok()
        } else {
            None
        }
    }

    /// Try to get the file `mcu-test-rom-{crate_name}-{bin_name}.bin` from self.
    /// `crate_name` and `bin_name` are derived from `fwid`.
    ///
    /// # Arguments
    ///
    /// - `fwid`: [FwId] identifying the mcu test rom binary.
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<u8>)`: Firmware binary data
    /// - `Err(anyhow::Error)`: No firmware binary associated to `fwid` found.
    pub fn test_rom(&self, fwid: &FwId) -> Result<Vec<u8>> {
        let expected_name = format!("mcu-test-rom-{}-{}.bin", fwid.crate_name, fwid.bin_name);
        for (name, data) in self.test_roms.iter() {
            if &expected_name == name {
                return Ok(data.clone());
            }
        }
        Err(anyhow::anyhow!(
            "FwId not found. File name: {expected_name}, FwId: {:?}",
            fwid
        ))
    }

    /// Try to get the file `cptra-test-rom-{crate_name}-{bin_name}.bin` from self.
    /// `crate_name` and `bin_name` are derived from `fwid`.
    ///
    /// # Arguments
    ///
    /// - `fwid`: [FwId] identifying the Caliptra test ROM binary.
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<u8>)`: Firmware binary data
    /// - `Err(anyhow::Error)`: No firmware binary associated to `fwid` found.
    pub fn caliptra_test_rom(&self, fwid: &FwId) -> Result<Vec<u8>> {
        let expected_name = format!("cptra-test-rom-{}-{}.bin", fwid.crate_name, fwid.bin_name);
        println!("expected name: {expected_name}");
        for (name, data) in self.caliptra_test_roms.iter() {
            println!("checking: {name}");
            if &expected_name == name {
                return Ok(data.clone());
            }
        }
        Err(anyhow::anyhow!(
            "FwId not found. File name: {expected_name}, FwId: {:?}",
            fwid
        ))
    }

    /// Try to get the file `mcu-test-soc-manifest-{feature}.bin` from self.
    ///
    /// # Arguments
    ///
    /// - `feature`: Feature name identifying the SoC manifest variant.
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<u8>)`: SoC manifest binary data
    /// - `Err(anyhow::Error)`: No SoC manifest associated to `feature` found.
    pub fn test_soc_manifest(&self, feature: &str) -> Result<Vec<u8>> {
        let expected_name = format!("mcu-test-soc-manifest-{}.bin", feature);
        for (name, data) in self.test_soc_manifests.iter() {
            if &expected_name == name {
                return Ok(data.clone());
            }
        }
        Err(anyhow::anyhow!(
            "SoC Manifest not found. File name: {expected_name}, feature: {feature}"
        ))
    }

    /// Try to get the file `mcu-test-runtime-{feature}.bin` from self.
    ///
    /// # Arguments
    ///
    /// - `feature`: Feature name identifying the runtime variant.
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<u8>)`: Runtime binary data
    /// - `Err(anyhow::Error)`: No runtime associated to `feature` found.
    pub fn test_runtime(&self, feature: &str) -> Result<Vec<u8>> {
        let expected_name = format!("mcu-test-runtime-{}.bin", feature);
        for (name, data) in self.test_runtimes.iter() {
            if &expected_name == name {
                return Ok(data.clone());
            }
        }
        Err(anyhow::anyhow!(
            "Runtime not found. File name: {expected_name}, feature: {feature}"
        ))
    }

    /// Try to get the file `mcu-test-pldm-fw-pkg-{feature}.bin` from self.
    ///
    /// # Arguments
    ///
    /// - `feature`: Feature name identifying the PLDM firmware package variant.
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<u8>)`: PLDM firmware package binary data
    /// - `Err(anyhow::Error)`: No PLDM firmware package associated to `feature` found.
    pub fn test_pldm_fw_pkg(&self, feature: &str) -> Result<Vec<u8>> {
        let expected_name = format!("mcu-test-pldm-fw-pkg-{}.bin", feature);
        for (name, data) in self.test_pldm_fw_pkgs.iter() {
            if &expected_name == name {
                return Ok(data.clone());
            }
        }
        Err(anyhow::anyhow!(
            "PLDM FW Package not found. File name: {expected_name}, feature: {feature}"
        ))
    }

    /// Try to get the file `mcu-test-flash-image-{feature}.bin` from self.
    ///
    /// # Arguments
    ///
    /// - `feature`: Feature name identifying the flash image variant.
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<u8>)`: Flash image binary data
    /// - `Err(anyhow::Error)`: No flash image associated to `feature` found.
    pub fn test_flash_image(&self, feature: &str) -> Result<Vec<u8>> {
        let expected_name = format!("mcu-test-flash-image-{}.bin", feature);
        for (name, data) in self.test_flash_images.iter() {
            if &expected_name == name {
                return Ok(data.clone());
            }
        }
        Err(anyhow::anyhow!(
            "Flash image not found. File name: {expected_name}, feature: {feature}"
        ))
    }

    /// Try to get the file `mcu-test-update-flash-image-{feature}.bin` from self.
    /// This is the flash image without partition table, used for PLDM update packages
    /// in firmware update tests.
    ///
    /// # Arguments
    ///
    /// - `feature`: Feature name identifying the update flash image variant.
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<u8>)`: Update flash image binary data
    /// - `Err(anyhow::Error)`: No update flash image associated to `feature` found.
    pub fn test_update_flash_image(&self, feature: &str) -> Result<Vec<u8>> {
        let expected_name = format!("mcu-test-update-flash-image-{}.bin", feature);
        for (name, data) in self.test_update_flash_images.iter() {
            if &expected_name == name {
                return Ok(data.clone());
            }
        }
        Err(anyhow::anyhow!(
            "Update flash image not found. File name: {expected_name}, feature: {feature}"
        ))
    }

    /// Try to get the file `mcu-test-rom-feature-{feature}.bin` from self.
    /// Falls back to the generic MCU ROM if no feature-specific ROM was built.
    ///
    /// # Arguments
    ///
    /// - `feature`: Feature name identifying the MCU ROM variant.
    ///
    /// # Returns
    ///
    /// - `Vec<u8>`: Feature-specific MCU ROM binary data, or generic MCU ROM as fallback.
    pub fn test_feature_rom(&self, feature: &str) -> Vec<u8> {
        let expected_name = format!("mcu-test-rom-feature-{}.bin", feature);
        for (name, data) in self.test_roms.iter() {
            if &expected_name == name {
                return data.clone();
            }
        }
        self.mcu_rom.clone()
    }
}

/// Prebuilt emulator binaries stored in a separate ZIP file (emulators.zip).
/// This is kept separate from FirmwareBinaries to avoid bloating the firmware bundle.
#[derive(Default)]
pub struct EmulatorBinaries {
    /// Prebuilt emulator binaries for each test feature: (feature_name, binary_data)
    pub emulators: Vec<(String, Vec<u8>)>,
}

impl EmulatorBinaries {
    /// Reads the environment variable `CPTRA_EMULATOR_BUNDLE`.
    ///
    /// Returns `EmulatorBinaries` if `CPTRA_EMULATOR_BUNDLE` points to a valid zip file.
    ///
    /// This function is safe to call multiple times. The returned `EmulatorBinaries` is cached
    /// after the first invocation to avoid multiple decompressions.
    ///
    /// # Returns
    ///
    /// - `Ok(&'static EmulatorBinaries)`: Cached emulator binaries.
    /// - `Err(anyhow::Error)`: If the environment variable is not set or the file cannot be read.
    pub fn from_env() -> Result<&'static Self> {
        let bundle_path = var("CPTRA_EMULATOR_BUNDLE")
            .map_err(|_| anyhow::anyhow!("Set the environment variable CPTRA_EMULATOR_BUNDLE"))?;

        static BINARIES: OnceLock<EmulatorBinaries> = OnceLock::new();
        let binaries = BINARIES.get_or_init(|| {
            Self::read_from_zip(&bundle_path.clone().into())
                .expect("failed to unzip emulator archive")
        });

        Ok(binaries)
    }

    /// Read emulator binaries from a ZIP archive file.
    ///
    /// # Arguments
    ///
    /// - `path`: Path to the ZIP archive containing emulator binaries.
    ///
    /// # Returns
    ///
    /// - `Ok(EmulatorBinaries)`: Populated emulator binaries structure.
    /// - `Err(anyhow::Error)`: If the file cannot be opened or parsed.
    pub fn read_from_zip(path: &PathBuf) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        let mut zip = zip::ZipArchive::new(file)?;
        let mut binaries = EmulatorBinaries::default();

        for i in 0..zip.len() {
            let mut file = zip.by_index(i)?;
            let name = file.name().to_string();
            let mut data = Vec::new();
            file.read_to_end(&mut data)?;

            if name == "emulator" {
                binaries.emulators.push((name, data));
            }
        }

        Ok(binaries)
    }

    /// Get the prebuilt emulator binary from the bundle.
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<u8>)`: Emulator binary data.
    /// - `Err(anyhow::Error)`: If the emulator binary is not found in the bundle.
    pub fn emulator(&self) -> Result<Vec<u8>> {
        for (name, data) in self.emulators.iter() {
            if name == "emulator" {
                return Ok(data.clone());
            }
        }

        Err(anyhow::anyhow!("Emulator binary not found in bundle"))
    }
}
