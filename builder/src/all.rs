// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use caliptra_builder::FwId;
use caliptra_image_types::ImageManifest;
use chrono::{TimeZone, Utc};
use mcu_config::boot::{PartitionId, PartitionStatus, RollbackEnable};
use mcu_config_emulator::flash::{PartitionTable, StandAloneChecksumCalculator, IMAGE_A_PARTITION};
use pldm_fw_pkg::{
    manifest::{
        ComponentImageInformation, Descriptor, DescriptorType, FirmwareDeviceIdRecord,
        PackageHeaderInformation, StringType,
    },
    FirmwareManifest,
};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zerocopy::FromBytes;
use zip::{
    write::{FileOptions, SimpleFileOptions},
    ZipWriter,
};

use crate::CaliptraBuilder;
use crate::PROJECT_ROOT;
use crate::TARGET;
use crate::{firmware, ImageCfg};

use std::{env::var, sync::OnceLock};

/// Features that require the example app to be included
/// These are determined by which tests use `run_test!(test_name, example_app)` in tests/integration/src/lib.rs
const FEATURES_WITH_EXAMPLE_APP: &[&str] = &[
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

/// Features that require SoC images to be included in the flash image
const FEATURES_REQUIRING_SOC_IMAGES: &[&str] = &[
    "test-flash-based-boot",
    "test-pldm-streaming-boot",
    "test-firmware-update-flash",
    "test-firmware-update-streaming",
];

/// Features that require flash-based boot (partition table at offset 0)
const FEATURES_REQUIRING_FLASH_BOOT: &[&str] =
    &["test-flash-based-boot", "test-firmware-update-flash"];

/// MCI base address for SoC image load addresses.
/// Uses FPGA memory map since the emulator's AXI simulation uses FPGA-like addresses.
const MCI_BASE_AXI_ADDRESS: u64 = mcu_config_fpga::FPGA_MEMORY_MAP.mci_offset as u64;

/// Build the emulator with a specific feature flag.
/// Returns the path to the built emulator binary, or None if the feature is not supported by the emulator.
pub fn build_emulator_with_feature(feature: &str) -> Result<Option<PathBuf>> {
    use std::process::Command;

    println!("Building emulator with feature: {}", feature);

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&*PROJECT_ROOT).args([
        "build",
        "-p",
        "emulator",
        "--profile",
        "test",
        "--features",
        feature,
    ]);

    let output = cmd.output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Check if the error is due to missing feature
        if stderr.contains("does not contain this feature") {
            println!(
                "Skipping emulator build for feature '{}' (feature not supported by emulator)",
                feature
            );
            return Ok(None);
        }
        bail!(
            "Failed to build emulator with feature {}: {}",
            feature,
            stderr
        );
    }

    // The emulator binary is at target/debug/emulator (profile "test" uses the debug directory)
    let emulator_path = PROJECT_ROOT.join("target").join("debug").join("emulator");

    if !emulator_path.exists() {
        bail!("Emulator binary not found at {:?}", emulator_path);
    }

    Ok(Some(emulator_path))
}

/// MCU MBOX SRAM1 offset from MCI base.
/// Matches mcu_mbox_driver::MCU_MBOX1_SRAM_OFFSET (0x80_0000).
const MCU_MBOX_SRAM1_OFFSET: u64 = 0x80_0000;

/// Creates default SoC images for tests that require them.
/// Returns (soc_images_config, soc_images_paths).
fn create_default_soc_images() -> (Vec<ImageCfg>, Vec<PathBuf>) {
    let soc_image_fw_1 = vec![0x55u8; 512];
    let soc_image_fw_2 = vec![0xAAu8; 256];

    let soc_image_path_1 = std::env::temp_dir().join("default-soc-image-1.bin");
    let soc_image_path_2 = std::env::temp_dir().join("default-soc-image-2.bin");

    std::fs::write(&soc_image_path_1, &soc_image_fw_1).expect("Failed to write SoC image 1");
    std::fs::write(&soc_image_path_2, &soc_image_fw_2).expect("Failed to write SoC image 2");

    let soc_images = vec![
        ImageCfg {
            path: soc_image_path_1.clone(),
            load_addr: MCI_BASE_AXI_ADDRESS + MCU_MBOX_SRAM1_OFFSET,
            image_id: 4096,
            component_id: 4096,
            exec_bit: 5,
            ..Default::default()
        },
        ImageCfg {
            path: soc_image_path_2.clone(),
            load_addr: MCI_BASE_AXI_ADDRESS + MCU_MBOX_SRAM1_OFFSET + soc_image_fw_1.len() as u64,
            image_id: 4097,
            component_id: 4097,
            exec_bit: 6,
            ..Default::default()
        },
    ];

    let soc_images_paths = vec![soc_image_path_1, soc_image_path_2];

    (soc_images, soc_images_paths)
}

#[derive(Default)]
pub struct FirmwareBinaries {
    pub caliptra_rom: Vec<u8>,
    pub caliptra_fw: Vec<u8>,
    pub mcu_rom: Vec<u8>,
    pub mcu_runtime: Vec<u8>,
    pub network_rom: Vec<u8>,
    pub soc_manifest: Vec<u8>,
    pub test_roms: Vec<(String, Vec<u8>)>,
    pub test_network_roms: Vec<(String, Vec<u8>)>,
    pub caliptra_test_roms: Vec<(String, Vec<u8>)>,
    pub test_soc_manifests: Vec<(String, Vec<u8>)>,
    pub test_runtimes: Vec<(String, Vec<u8>)>,
    pub test_pldm_fw_pkgs: Vec<(String, Vec<u8>)>,
    pub test_flash_images: Vec<(String, Vec<u8>)>,
    /// Update flash images without partition table (for PLDM update packages)
    pub test_update_flash_images: Vec<(String, Vec<u8>)>,
}

impl FirmwareBinaries {
    const CALIPTRA_ROM_NAME: &'static str = "caliptra_rom.bin";
    const CALIPTRA_FW_NAME: &'static str = "caliptra_fw.bin";
    const MCU_ROM_NAME: &'static str = "mcu_rom.bin";
    const MCU_RUNTIME_NAME: &'static str = "mcu_runtime.bin";
    const NETWORK_ROM_NAME: &'static str = "network_rom.bin";
    const SOC_MANIFEST_NAME: &'static str = "soc_manifest.bin";
    const FLASH_IMAGE_NAME: &'static str = "flash_image.bin";
    const PLDM_FW_PKG_NAME: &'static str = "pldm_fw_pkg.bin";

    /// Reads the environment variable `CPTRA_FIRMWARE_BUNDLE`.
    ///
    /// returns `FirmwareBinaries` if `CPTRA_FIRMWARE_BUNDLE` points to a valid zip file.
    ///
    /// This function is safe to call multiple times. The returned `FirmwareBinaries` is cached
    /// after the first invocation to avoid multiple decompressions.
    pub fn from_env() -> Result<&'static Self> {
        // TODO: Consider falling back to building the firmware if CPTRA_FIRMWARE_BUNDLE is unset.
        let bundle_path = var("CPTRA_FIRMWARE_BUNDLE")
            .map_err(|_| anyhow::anyhow!("Set the environment variable CPTRA_FIRMWARE_BUNDLE"))?;

        static BINARIES: OnceLock<FirmwareBinaries> = OnceLock::new();
        let binaries = BINARIES.get_or_init(|| {
            Self::read_from_zip(&bundle_path.clone().into()).expect("failed to unzip archive")
        });

        Ok(binaries)
    }

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
                Self::NETWORK_ROM_NAME => binaries.network_rom = data,
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
                name if name.contains("network-rom-feature-") => {
                    binaries.test_network_roms.push((name.to_string(), data));
                }
                _ => continue,
            }
        }

        Ok(binaries)
    }

    pub fn vendor_pk_hash(&self) -> Option<[u8; 48]> {
        if let Ok((manifest, _)) = ImageManifest::ref_from_prefix(&self.caliptra_fw) {
            CaliptraBuilder::vendor_pk_hash(manifest).ok()
        } else {
            None
        }
    }

    /// Returns the owner public key hash from the Caliptra firmware bundle.
    pub fn owner_pk_hash(&self) -> Option<[u8; 48]> {
        if let Ok((manifest, _)) = ImageManifest::ref_from_prefix(&self.caliptra_fw) {
            CaliptraBuilder::owner_pk_hash(manifest).ok()
        } else {
            None
        }
    }

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

    /// Get the update flash image (without partition table) for a test feature.
    /// This is used for PLDM update packages in firmware update tests.
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

    /// Get a feature-specific MCU ROM. Falls back to the generic MCU ROM
    /// if no feature-specific ROM was built.
    pub fn test_feature_rom(&self, feature: &str) -> Vec<u8> {
        let expected_name = format!("mcu-test-rom-feature-{}.bin", feature);
        for (name, data) in self.test_roms.iter() {
            if &expected_name == name {
                return data.clone();
            }
        }
        self.mcu_rom.clone()
    }

    /// Get a feature-specific Network ROM. Falls back to the generic Network ROM
    /// if no feature-specific ROM was built.
    pub fn test_feature_network_rom(&self, feature: &str) -> Vec<u8> {
        let expected_name = format!("network-rom-feature-{}.bin", feature);
        for (name, data) in self.test_network_roms.iter() {
            if &expected_name == name {
                return data.clone();
            }
        }
        self.network_rom.clone()
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

    pub fn read_from_zip(path: &PathBuf) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        let mut zip = zip::ZipArchive::new(file)?;
        let mut binaries = EmulatorBinaries::default();

        for i in 0..zip.len() {
            let mut file = zip.by_index(i)?;
            let name = file.name().to_string();
            let mut data = Vec::new();
            file.read_to_end(&mut data)?;

            if name.starts_with("emulator-") {
                binaries.emulators.push((name, data));
            }
        }

        Ok(binaries)
    }

    /// Get the prebuilt emulator binary for a specific test feature.
    pub fn emulator(&self, feature: &str) -> Result<Vec<u8>> {
        let expected_name = format!("emulator-{}", feature);
        for (name, data) in self.emulators.iter() {
            if &expected_name == name {
                return Ok(data.clone());
            }
        }
        Err(anyhow::anyhow!(
            "Emulator not found. File name: {expected_name}, feature: {feature}"
        ))
    }
}

#[derive(Default)]
pub struct AllBuildArgs<'a> {
    pub output: Option<&'a str>,
    pub platform: Option<&'a str>,
    pub rom_features: Option<&'a str>,
    pub network_rom_features: Option<&'a str>,
    pub runtime_features: Option<&'a str>,
    pub separate_runtimes: bool,
    pub soc_images: Option<Vec<ImageCfg>>,
    pub mcu_cfgs: Option<Vec<ImageCfg>>,
    pub pldm_manifest: Option<&'a str>,
}

/// Build Caliptra ROM and firmware bundle, MCU ROM and runtime, and SoC manifest, and package them all together in a ZIP file.
pub fn all_build(args: AllBuildArgs) -> Result<()> {
    let AllBuildArgs {
        output,
        platform,
        rom_features,
        network_rom_features,
        runtime_features,
        separate_runtimes,
        soc_images,
        mcu_cfgs,
        pldm_manifest,
    } = args;

    // TODO: use temp files
    let platform = platform.unwrap_or("emulator");
    let rom_features = rom_features.unwrap_or_default();
    let mcu_rom = crate::rom_build(Some(platform.to_string()), Some(rom_features.to_string()))?;

    // Build base network ROM (without features)
    let network_rom = crate::network_rom_build(None)?;

    // Parse network ROM features as comma-separated list
    let network_rom_feature_list: Vec<&str> = match network_rom_features {
        Some(f) if !f.is_empty() => f.split(',').collect(),
        _ => vec![],
    };

    let mut used_filenames = std::collections::HashSet::new();
    let mut test_roms = vec![];
    for fwid in firmware::REGISTERED_FW {
        let bin_path = PathBuf::from(crate::test_rom_build(Some(platform), fwid)?);
        let filename = bin_path.file_name().unwrap().to_str().unwrap().to_string();
        if !used_filenames.insert(filename.clone()) {
            panic!("Multiple fwids with filename {filename}")
        }

        test_roms.push((bin_path, filename));
    }

    for fwid in firmware::CPTRA_REGISTERED_FW {
        let filename = format!("cptra-test-rom-{}-{}.bin", fwid.crate_name, fwid.bin_name);
        if !used_filenames.insert(filename.clone()) {
            panic!("Multiple fwids with filename {filename}")
        }
        let bin_path = PROJECT_ROOT
            .join("target")
            .join(TARGET)
            .join("release")
            .join(&filename);
        let rom_bytes = caliptra_builder::build_firmware_rom(fwid)?;
        std::fs::write(&bin_path, rom_bytes)?;
        test_roms.push((bin_path, filename));
    }

    if separate_runtimes && (runtime_features.is_none() || runtime_features.unwrap().is_empty()) {
        bail!("Must specify runtime features when building separate runtimes");
    }

    let runtime_features = match runtime_features {
        Some(r) if !r.is_empty() => r.split(",").collect::<Vec<&str>>(),
        _ => vec![],
    };

    let mut base_runtime_features = vec![];
    let mut separate_features = vec![];
    if separate_runtimes {
        // build a separate runtime for each feature flag, since they are used as tests
        separate_features = runtime_features;
    } else {
        // build one runtime with all feature flags
        base_runtime_features = runtime_features;
    }

    let base_runtime_file = tempfile::NamedTempFile::new().unwrap();
    let base_runtime_path = base_runtime_file.path().to_str().unwrap();

    let mcu_runtime = &crate::runtime_build_with_apps(
        &base_runtime_features,
        Some(base_runtime_path.to_string()),
        false,
        Some(platform),
        None,
    )?;

    let fpga = platform == "fpga";
    let mcu_image_cfg = get_image_cfg_feature(&mcu_cfgs.clone().unwrap_or_default(), "none");
    let mut caliptra_builder = crate::CaliptraBuilder::new(
        fpga,
        None,
        None,
        None,
        None,
        Some(mcu_runtime.into()),
        soc_images.clone(),
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
    let flash_image = create_flash_image(
        Some(caliptra_fw.clone()),
        Some(soc_manifest.clone()),
        Some(mcu_runtime.into()),
        soc_images
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|img| img.path.clone())
            .collect(),
        false, // Base flash image is not for flash-based boot
    )?;
    let pldm_manifest_decoded = match pldm_manifest {
        Some(path) => {
            let mut file = std::fs::File::open(path)?;
            let mut data = Vec::new();
            file.read_to_end(&mut data)?;
            FirmwareManifest::decode_firmware_package(&path.to_string(), None)?
        }
        None => {
            let dev_uuid = get_device_uuid();
            let mut file = std::fs::File::open(flash_image.clone())?;
            let mut data = Vec::new();
            file.read_to_end(&mut data)?;
            get_default_pldm_fw_manifest(&dev_uuid, &data)
        }
    };
    let pldm_fw_pkg = tempfile::NamedTempFile::new().unwrap();
    let pldm_fw_pkg_path = pldm_fw_pkg
        .path()
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid path"))?
        .to_string();
    pldm_manifest_decoded.generate_firmware_package(&pldm_fw_pkg_path)?;

    // Build feature-specific MCU ROMs so tests don't need to compile at runtime.
    // Only builds for features that the ROM crate supports; tests using other features
    // will fall back to the generic MCU ROM.
    for feature in separate_features.iter() {
        match crate::rom_build(Some(platform.to_string()), Some(feature.to_string())) {
            Ok(rom_path) => {
                let rom_name = format!("mcu-test-rom-feature-{}.bin", feature);
                println!("Built feature ROM: {rom_path:?} -> {}", rom_name);
                test_roms.push((rom_path, rom_name));
            }
            Err(e) => {
                println!(
                    "Skipping feature ROM for {}: {} (will use generic ROM)",
                    feature, e
                );
            }
        }
    }

    // Build feature-specific Network ROMs
    let mut test_network_roms: Vec<(PathBuf, String)> = vec![];
    for feature in network_rom_feature_list.iter() {
        match crate::network_rom_build(Some(feature)) {
            Ok(rom_path) => {
                let rom_name = format!("network-rom-feature-{}.bin", feature);
                println!("Built feature Network ROM: {} -> {}", rom_path, rom_name);
                test_network_roms.push((PathBuf::from(rom_path), rom_name));
            }
            Err(e) => {
                println!(
                    "Skipping Network ROM for feature {}: {} (will use generic Network ROM)",
                    feature, e
                );
            }
        }
    }

    let mut test_runtimes = vec![];
    for feature in separate_features.iter() {
        let feature_runtime_file = tempfile::NamedTempFile::new().unwrap();
        let feature_runtime_path = feature_runtime_file.path().to_str().unwrap().to_string();
        let include_example_app = FEATURES_WITH_EXAMPLE_APP.contains(feature);

        crate::runtime_build_with_apps(
            &[feature],
            Some(feature_runtime_path),
            include_example_app,
            Some(platform),
            None,
        )?;

        let mcu_image_cfg = get_image_cfg_feature(&mcu_cfgs.clone().unwrap_or_default(), feature);

        // For features that require SoC images, create default ones if not provided
        let (feature_soc_images, feature_soc_images_paths) =
            if FEATURES_REQUIRING_SOC_IMAGES.contains(feature) && soc_images.is_none() {
                let (images, paths) = create_default_soc_images();
                (Some(images), paths)
            } else {
                (
                    soc_images.clone(),
                    soc_images
                        .clone()
                        .unwrap_or_default()
                        .iter()
                        .map(|img| img.path.clone())
                        .collect(),
                )
            };

        let mut caliptra_builder = crate::CaliptraBuilder::new(
            fpga,
            Some(caliptra_rom.clone()),
            Some(caliptra_fw.clone()),
            None,
            Some(vendor_pk_hash.clone()),
            Some(feature_runtime_file.path().to_path_buf()),
            feature_soc_images.clone(),
            mcu_image_cfg.clone(),
            None,
            None,
            None,
        );
        let feature_soc_manifest_file = tempfile::NamedTempFile::new().unwrap();
        caliptra_builder.get_soc_manifest(feature_soc_manifest_file.path().to_str())?;

        // Flash-based boot features require partition table at offset 0
        let is_flash_based_boot = FEATURES_REQUIRING_FLASH_BOOT.contains(feature);

        // Clone paths for potential second use
        let feature_soc_images_paths_clone = feature_soc_images_paths.clone();

        let feature_flash_image = create_flash_image(
            Some(caliptra_fw.clone()),
            Some(feature_soc_manifest_file.path().to_path_buf()),
            Some(feature_runtime_file.path().to_path_buf()),
            feature_soc_images_paths,
            is_flash_based_boot,
        )?;

        // For firmware update tests, create a separate "update" flash image WITHOUT partition table
        // This is used for the PLDM update package (the downloaded firmware)
        let is_firmware_update_feature = *feature == "test-firmware-update-flash"
            || *feature == "test-firmware-update-streaming";
        let feature_update_flash_image = if is_firmware_update_feature {
            Some(create_flash_image(
                Some(caliptra_fw.clone()),
                Some(feature_soc_manifest_file.path().to_path_buf()),
                Some(feature_runtime_file.path().to_path_buf()),
                feature_soc_images_paths_clone,
                false, // No partition table for update image
            )?)
        } else {
            None
        };

        // For PLDM package, use the update flash image (without partition table) if available
        let pldm_source_image = feature_update_flash_image
            .as_ref()
            .unwrap_or(&feature_flash_image);

        let feature_pldm_manifest = match pldm_manifest {
            Some(path) => {
                let mut file = std::fs::File::open(path)?;
                let mut data = Vec::new();
                file.read_to_end(&mut data)?;
                FirmwareManifest::decode_firmware_package(&path.to_string(), None)?
            }
            None => {
                let dev_uuid = get_device_uuid();
                let mut file = std::fs::File::open(pldm_source_image.clone())?;
                let mut data = Vec::new();
                file.read_to_end(&mut data)?;
                get_default_pldm_fw_manifest(&dev_uuid, &data)
            }
        };
        let feature_pldm_fw_pkg = tempfile::NamedTempFile::new().unwrap();
        let pldm_fw_pkg_path = feature_pldm_fw_pkg
            .path()
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid path"))?
            .to_string();
        feature_pldm_manifest.generate_firmware_package(&pldm_fw_pkg_path)?;

        test_runtimes.push((
            feature.to_string(),
            feature_runtime_file,
            feature_soc_manifest_file,
            feature_flash_image,
            feature_pldm_fw_pkg,
            feature_update_flash_image,
        ));
    }

    let default_path = crate::target_dir().join("all-fw.zip");
    let path = output.map(Path::new).unwrap_or(&default_path);
    println!("Creating ZIP file: {}", path.display());
    let file = std::fs::File::create(path)?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o644)
        .last_modified_time(zip::DateTime::try_from(chrono::Local::now().naive_local())?);

    add_to_zip(
        &caliptra_rom,
        FirmwareBinaries::CALIPTRA_ROM_NAME,
        &mut zip,
        options,
    )?;
    add_to_zip(
        &caliptra_fw,
        FirmwareBinaries::CALIPTRA_FW_NAME,
        &mut zip,
        options,
    )?;
    add_to_zip(&mcu_rom, FirmwareBinaries::MCU_ROM_NAME, &mut zip, options)?;
    add_to_zip(
        &PathBuf::from(mcu_runtime),
        FirmwareBinaries::MCU_RUNTIME_NAME,
        &mut zip,
        options,
    )?;
    add_to_zip(
        &PathBuf::from(network_rom),
        FirmwareBinaries::NETWORK_ROM_NAME,
        &mut zip,
        options,
    )?;
    add_to_zip(
        &soc_manifest,
        FirmwareBinaries::SOC_MANIFEST_NAME,
        &mut zip,
        options,
    )?;
    add_to_zip(
        &flash_image,
        FirmwareBinaries::FLASH_IMAGE_NAME,
        &mut zip,
        options,
    )?;
    add_to_zip(
        &PathBuf::from(pldm_fw_pkg_path),
        FirmwareBinaries::PLDM_FW_PKG_NAME,
        &mut zip,
        options,
    )?;
    for (test_rom, name) in test_roms {
        add_to_zip(&test_rom, &name, &mut zip, options)?;
    }

    for (network_rom_path, name) in test_network_roms {
        add_to_zip(&network_rom_path, &name, &mut zip, options)?;
    }

    for (feature, runtime, soc_manifest, flash_image, pldm_fw_pkg, update_flash_image) in
        test_runtimes
    {
        let runtime_name = format!("mcu-test-runtime-{}.bin", feature);
        println!("Adding {} -> {}", runtime.path().display(), runtime_name);
        add_to_zip(
            &runtime.path().to_path_buf(),
            &runtime_name,
            &mut zip,
            options,
        )?;

        let soc_manifest_name = format!("mcu-test-soc-manifest-{}.bin", feature);
        println!(
            "Adding {} -> {}",
            soc_manifest.path().display(),
            soc_manifest_name
        );
        add_to_zip(
            &soc_manifest.path().to_path_buf(),
            &soc_manifest_name,
            &mut zip,
            options,
        )?;

        println!(
            "Adding {} -> mcu-test-flash-image-{}.bin",
            flash_image.display(),
            feature
        );
        add_to_zip(
            &flash_image,
            &format!("mcu-test-flash-image-{}.bin", feature),
            &mut zip,
            options,
        )?;

        // Add update flash image (without partition table) for firmware update tests
        if let Some(update_flash) = update_flash_image {
            let update_flash_name = format!("mcu-test-update-flash-image-{}.bin", feature);
            println!("Adding {} -> {}", update_flash.display(), update_flash_name);
            add_to_zip(&update_flash, &update_flash_name, &mut zip, options)?;
        }

        let pldm_fw_pkg_name = format!("mcu-test-pldm-fw-pkg-{}.bin", feature);
        println!(
            "Adding {} -> {}",
            pldm_fw_pkg.path().display(),
            pldm_fw_pkg_name
        );
        add_to_zip(
            &pldm_fw_pkg.path().to_path_buf(),
            &pldm_fw_pkg_name,
            &mut zip,
            options,
        )?;
    }

    zip.finish()?;

    Ok(())
}

#[derive(Default)]
pub struct EmulatorBuildArgs<'a> {
    pub output: Option<&'a str>,
    pub features: Option<&'a str>,
}

/// Build emulator binaries for all specified features and package them in emulators.zip.
pub fn emulator_build(args: EmulatorBuildArgs) -> Result<()> {
    let EmulatorBuildArgs { output, features } = args;

    let features = match features {
        Some(f) if !f.is_empty() => f.split(",").collect::<Vec<&str>>(),
        _ => bail!("Must specify features to build emulators for"),
    };

    let mut emulators: Vec<(String, PathBuf)> = vec![];

    for feature in features.iter() {
        if let Some(emulator_path) = build_emulator_with_feature(feature)? {
            // Copy to a unique path so we can keep all emulators
            let emulator_dest = crate::target_dir().join(format!("emulator-{}", feature));
            std::fs::copy(&emulator_path, &emulator_dest)?;
            emulators.push((feature.to_string(), emulator_dest));
        }
    }

    let default_path = crate::target_dir().join("emulators.zip");
    let path = output.map(Path::new).unwrap_or(&default_path);
    println!("Creating emulator ZIP file: {}", path.display());
    let file = std::fs::File::create(path)?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o755) // Make emulators executable
        .last_modified_time(zip::DateTime::try_from(chrono::Local::now().naive_local())?);

    for (feature, emulator_path) in emulators {
        let emulator_name = format!("emulator-{}", feature);
        println!("Adding {} -> {}", emulator_path.display(), emulator_name);
        add_to_zip(&emulator_path, &emulator_name, &mut zip, options)?;
    }

    zip.finish()?;
    println!("Emulator build complete: {}", path.display());

    Ok(())
}

fn get_image_cfg_feature(image_cfg: &[ImageCfg], feature: &str) -> Option<ImageCfg> {
    for img in image_cfg {
        if img.feature == feature {
            return Some(img.clone());
        }
    }
    None
}

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

fn create_flash_image(
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
    }

    Ok(flash_image_path)
}

// Helper function to retrieve a default sample PLDM firmware manifest, if one is not provided
// Identifier and classification should match the device's component image information
fn get_default_pldm_fw_manifest(dev_uuid: &[u8], image: &[u8]) -> FirmwareManifest {
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

// Helper function to retrieve the device UUID
fn get_device_uuid() -> [u8; 16] {
    // This an arbitrary UUID that should match the one used in the device's ID record
    [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ]
}
