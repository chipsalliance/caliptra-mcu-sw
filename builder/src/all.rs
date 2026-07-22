// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use caliptra_image_types::ImageManifest;
use caliptra_mcu_config::boot::{PartitionId, PartitionStatus, RollbackEnable};
use caliptra_mcu_config_emulator::flash::{
    PartitionTable, StandAloneChecksumCalculator, IMAGE_A_PARTITION,
};
use caliptra_mcu_flash_image::MCU_RT_IDENTIFIER;
use caliptra_mcu_pldm_fw_pkg::{
    manifest::{
        ComponentImageInformation, Descriptor, DescriptorType, FirmwareDeviceIdRecord,
        PackageHeaderInformation, StringType,
    },
    FirmwareManifest,
};
use chrono::{TimeZone, Utc};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zerocopy::FromBytes;
use zip::{
    write::{FileOptions, SimpleFileOptions},
    ZipWriter,
};

use crate::PROJECT_ROOT;
use crate::TARGET;
use crate::{firmware, ImageCfg};
use crate::{CaliptraBuildArgs, CaliptraBuilder};

use std::{env::var, sync::OnceLock};

struct FeatureTestResource {
    feature: String,
    runtime_file: tempfile::NamedTempFile,
    soc_manifest_file: tempfile::NamedTempFile,
    flash_image: PathBuf,
    pldm_fw_pkg: tempfile::NamedTempFile,
    update_flash_image: Option<PathBuf>,
    /// Raw bytes of the user-app ELF for this feature build. Carries the
    /// `.defmt` table needed by host-side defmt decoders.
    user_app_elf: Option<Vec<u8>>,
}

cfg_if::cfg_if! {
    if #[cfg(feature = "parallel-build")] {
        use rayon::prelude::*;
        fn maybe_par_iter<'a, T: Sync + 'a>(slice: &'a [T]) -> impl ParallelIterator<Item = &'a T> { slice.par_iter() }
        fn maybe_into_par_iter<T: Send + 'static>(v: Vec<T>) -> impl ParallelIterator<Item = T> { v.into_par_iter() }
    } else {
        fn maybe_par_iter<'a, T: 'a>(slice: &'a [T]) -> impl Iterator<Item = &'a T> { slice.iter() }
        fn maybe_into_par_iter<T: 'static>(v: Vec<T>) -> impl Iterator<Item = T> { v.into_iter() }
    }
}

/// MCI base address for SoC image load addresses.
/// Uses FPGA memory map since the emulator's AXI simulation uses FPGA-like addresses.
const MCI_BASE_AXI_ADDRESS: u64 = caliptra_mcu_config_fpga::FPGA_MEMORY_MAP.mci_offset as u64;

/// Build the emulator with a specific feature flag.
/// Returns the path to the built emulator binary, or None if the feature is not supported by the emulator.
pub fn build_emulator_with_feature(feature: &str) -> Result<Option<PathBuf>> {
    use std::process::Command;

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&*PROJECT_ROOT).args([
        "build",
        "-p",
        "caliptra-mcu-emulator",
        "--profile",
        "test",
    ]);

    if !feature.is_empty() {
        cmd.args(["--features", feature]);
    }

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

    // The emulator binary is at target/debug/caliptra-mcu-emulator (profile "test" uses the debug directory)
    let emulator_path = PROJECT_ROOT
        .join("target")
        .join("debug")
        .join("caliptra-mcu-emulator");

    if !emulator_path.exists() {
        bail!("Emulator binary not found at {:?}", emulator_path);
    }

    Ok(Some(emulator_path))
}

/// MCU MBOX SRAM1 offset from MCI base.
/// Matches caliptra_mcu_mbox_driver::MCU_MBOX1_SRAM_OFFSET (0x80_0000).
const MCU_MBOX_SRAM1_OFFSET: u64 = 0x80_0000;

/// MCU SRAM offset from MCI base.
const MCU_SRAM_OFFSET: u64 = 0xC0_0000;

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

/// Creates a single dummy SoC image for the attestation demo.
/// Uses fw_id 0x0003 so it appears as a distinct SoC firmware component
/// in the auth manifest, evidence, and reference value CoRIM.
fn create_attestation_soc_images() -> (Vec<ImageCfg>, Vec<PathBuf>) {
    let soc_image_fw = vec![0xDEu8; 512];
    let soc_image_path = std::env::temp_dir().join("attestation-soc-image.bin");
    std::fs::write(&soc_image_path, &soc_image_fw).expect("Failed to write attestation SoC image");

    let soc_images = vec![ImageCfg {
        path: soc_image_path.clone(),
        load_addr: MCI_BASE_AXI_ADDRESS + MCU_MBOX_SRAM1_OFFSET,
        image_id: 0x0003,
        component_id: 0x0003,
        exec_bit: 5,
        ..Default::default()
    }];

    (soc_images, vec![soc_image_path])
}

/// Pre-generate `target/generated/attestation_manifest.toml` so the runtime build can embed
/// the integrator-owned static attestation configuration.
fn pre_generate_attestation_manifest_config(
    vendor: &str,
    model: &str,
    soc_images: &[ImageCfg],
) -> Result<()> {
    crate::attestation_manifest::write_config(
        vendor,
        model,
        soc_images,
        "pre_generate_attestation_manifest_config",
        "Pre-generated",
    )
}

#[derive(Debug, Clone, Default)]
pub struct CaliptraRomBinary(pub Vec<u8>);

impl std::ops::Deref for CaliptraRomBinary {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for CaliptraRomBinary {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, Default)]
pub struct CaliptraRtBinary(pub Vec<u8>);

impl std::ops::Deref for CaliptraRtBinary {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for CaliptraRtBinary {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, Default)]
pub struct McuRomBinary(pub Vec<u8>);

impl std::ops::Deref for McuRomBinary {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for McuRomBinary {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, Default)]
pub struct SocManifestBinary(pub Vec<u8>);

impl std::ops::Deref for SocManifestBinary {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for SocManifestBinary {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, Default)]
pub struct McuFwBinary {
    pub bytes: Vec<u8>,
    pub flash_image: Vec<u8>,
    pub pldm_fw_pkg: Vec<u8>,
    pub update_flash_image: Vec<u8>,
    pub user_app_elf: Option<Vec<u8>>,
}

impl std::ops::Deref for McuFwBinary {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl AsRef<[u8]> for McuFwBinary {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone, Default)]
pub struct FirmwareBundle {
    pub caliptra_rom: CaliptraRomBinary,
    pub caliptra_rt: CaliptraRtBinary,
    pub mcu_rom: McuRomBinary,
    pub mcu_fw: McuFwBinary,
    pub soc_manifest: SocManifestBinary,
}

impl FirmwareBundle {
    pub fn new(target: &crate::firmware::FirmwareTarget) -> Result<&'static Self> {
        let binaries = FirmwareBinaries::from_env()?;
        binaries.get(target)
    }
}

#[derive(Default)]
pub struct FirmwareBinaries {
    pub bundles: std::sync::RwLock<
        std::collections::HashMap<crate::firmware::FirmwareTarget, &'static FirmwareBundle>,
    >,
}

impl FirmwareBinaries {
    pub const CALIPTRA_ROM_NAME: &'static str = "caliptra_rom.bin";
    pub const CALIPTRA_FW_NAME: &'static str = "caliptra_fw.bin";
    pub const CALIPTRA_FW_SVN7_NAME: &'static str = "caliptra_fw_svn7.bin";
    pub const CALIPTRA_FW_SVN128_NAME: &'static str = "caliptra_fw_svn128.bin";
    pub const CALIPTRA_FW_KEY2_NAME: &'static str = "caliptra_fw_key2.bin";
    pub const CALIPTRA_FW_OCP_LOCK_NAME: &'static str = "caliptra_fw_ocp_lock.bin";
    pub const MCU_ROM_NAME: &'static str = "mcu_rom.bin";
    pub const MCU_RUNTIME_NAME: &'static str = "mcu_runtime.bin";
    pub const USER_APP_ELF_NAME: &'static str = "user_app_elf.bin";
    pub const SOC_MANIFEST_NAME: &'static str = "soc_manifest.bin";
    pub const FLASH_IMAGE_NAME: &'static str = "flash_image.bin";
    pub const PLDM_FW_PKG_NAME: &'static str = "pldm_fw_pkg.bin";

    pub fn as_bundle(&self, target: &crate::firmware::FirmwareTarget) -> &FirmwareBundle {
        self.get(target).unwrap_or_else(|e| {
            panic!(
                "Failed to get or build bundle for target {}: {}",
                target.id(),
                e
            )
        })
    }

    pub fn get(&self, target: &crate::firmware::FirmwareTarget) -> Result<&'static FirmwareBundle> {
        {
            let map = self.bundles.read().unwrap();
            if let Some(&bundle) = map.get(target) {
                return Ok(bundle);
            }
        }
        let mut map = self.bundles.write().unwrap();
        if let Some(&bundle) = map.get(target) {
            return Ok(bundle);
        }
        let built_bundle = self.build_bundle(target)?;
        let static_bundle: &'static FirmwareBundle = Box::leak(Box::new(built_bundle));
        map.insert(*target, static_bundle);
        Ok(static_bundle)
    }

    fn build_bundle(&self, target: &crate::firmware::FirmwareTarget) -> Result<FirmwareBundle> {
        let platform = match target.platform() {
            crate::firmware::TargetPlatform::Fpga => "fpga",
            _ => "emulator",
        };

        // 1. MCU ROM
        let mcu_rom_bytes = if let Some(fwid) = firmware::REGISTERED_FW.iter().find(|f| {
            f.crate_name == target.id()
                || format!("mcu-test-rom-{}-{}", f.crate_name, f.bin_name) == target.id()
        }) {
            let bin_path = crate::test_rom_build(&CaliptraBuildArgs {
                platform: Some(platform),
                fwid: Some(fwid),
                ..Default::default()
            })?;
            std::fs::read(bin_path)?
        } else if let Some(&rom_feature) = target.mcu_rom_spec().features().first() {
            let bin_path = crate::rom_build(&CaliptraBuildArgs {
                platform: Some(platform),
                features: Some(rom_feature),
                ..Default::default()
            })?;
            std::fs::read(bin_path)?
        } else {
            let bin_path = crate::rom_build(&CaliptraBuildArgs {
                platform: Some(platform),
                ..Default::default()
            })?;
            std::fs::read(bin_path)?
        };

        // 2. Caliptra ROM
        let caliptra_rom_bytes = if let Some(cptra_fwid) = firmware::CPTRA_REGISTERED_FW
            .iter()
            .find(|f| format!("cptra-test-rom-{}-{}.bin", f.crate_name, f.bin_name) == target.id())
        {
            caliptra_builder::build_firmware_rom(cptra_fwid)?
        } else {
            caliptra_builder::rom_for_fw_integration_tests()?.to_vec()
        };

        // 3. Caliptra RT
        let (caliptra_fw_path, _vendor_pk_hash) = CaliptraBuilder::compile_caliptra_fw_cached(
            target.platform() == crate::firmware::TargetPlatform::Fpga,
            target.caliptra_rt_spec().features().contains(&"ocp-lock"),
            target.caliptra_rt_spec().svn().map(|s| s as u16),
            false,
        )?;
        let caliptra_rt_bytes = std::fs::read(caliptra_fw_path)?;

        // 4. MCU FW / Runtime
        let features_vec = target.mcu_fw_spec().features().to_vec();
        let features_str = if features_vec.is_empty() {
            None
        } else {
            Some(features_vec.join(","))
        };
        let profile_str = match target.mcu_fw_spec().profile() {
            crate::firmware::FirmwareProfile::Devel => "devel",
            crate::firmware::FirmwareProfile::Release => "release",
        };
        let runtime_path = crate::runtime_build_with_apps(&CaliptraBuildArgs {
            features: features_str.as_deref(),
            example_app: target.mcu_fw_spec().example_app(),
            platform: Some(platform),
            profile: Some(profile_str),
            ..Default::default()
        })?;
        let mcu_fw_bytes = std::fs::read(&runtime_path)?;

        let user_app_elf_path = crate::target_dir()
            .join(TARGET)
            .join(profile_str)
            .join("user-app");
        let user_app_elf = std::fs::read(&user_app_elf_path).ok();

        // 5. Flash image
        let flash_image = if target.id().contains("flash") || target.id().contains("boot") {
            crate::flash_image::build_flash_image_bytes(
                Some(&caliptra_rt_bytes),
                None,
                Some(&mcu_fw_bytes),
            )
        } else {
            vec![]
        };

        // 6. SoC manifest
        let soc_manifest_bytes = match target.id() {
            "test-ocp-lock" => {
                let mut builder = CaliptraBuilder::new(&CaliptraBuildArgs {
                    features: Some("ocp-lock"),
                    mcu_firmware: Some(runtime_path.clone()),
                    ..Default::default()
                });
                let path = builder.get_soc_manifest(None)?;
                std::fs::read(path).unwrap_or_default()
            }
            _ => vec![],
        };

        Ok(FirmwareBundle {
            caliptra_rom: CaliptraRomBinary(caliptra_rom_bytes),
            caliptra_rt: CaliptraRtBinary(caliptra_rt_bytes),
            mcu_rom: McuRomBinary(mcu_rom_bytes),
            mcu_fw: McuFwBinary {
                bytes: mcu_fw_bytes,
                flash_image,
                pldm_fw_pkg: vec![],
                update_flash_image: vec![],
                user_app_elf,
            },
            soc_manifest: SocManifestBinary(soc_manifest_bytes),
        })
    }

    /// Reads the environment variable `CPTRA_FIRMWARE_BUNDLE`.
    pub fn from_env() -> Result<&'static Self> {
        static BINARIES: OnceLock<FirmwareBinaries> = OnceLock::new();
        let binaries = BINARIES.get_or_init(|| {
            if let Ok(bundle_path) = var("CPTRA_FIRMWARE_BUNDLE") {
                Self::read_from_zip(&bundle_path.into()).unwrap_or_default()
            } else {
                FirmwareBinaries::default()
            }
        });

        Ok(binaries)
    }

    pub fn read_from_zip(path: &PathBuf) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        let mut zip = zip::ZipArchive::new(file)?;
        let mut raw_files: std::collections::HashMap<String, Vec<u8>> =
            std::collections::HashMap::new();
        let binaries = FirmwareBinaries::default();

        for i in 0..zip.len() {
            let mut file = zip.by_index(i)?;
            let name = file.name().to_string();
            let mut data = Vec::new();
            file.read_to_end(&mut data)?;
            raw_files.insert(name, data);
        }

        // Construct FirmwareBundle for every target in FIRMWARE_TARGETS
        for target in crate::firmware::targets::FIRMWARE_TARGETS {
            let id = target.id();

            let caliptra_rom = raw_files.get(target.caliptra_rom_filename());
            let caliptra_fw = raw_files.get(target.caliptra_rt_filename());
            let mcu_rom = raw_files.get(target.mcu_rom_filename());
            let mcu_runtime = raw_files.get(target.mcu_fw_filename());
            let soc_manifest = raw_files.get(target.soc_manifest_filename());
            let flash_image = raw_files.get(target.flash_image_filename());
            let pldm_fw_pkg = raw_files.get(target.pldm_fw_pkg_filename());
            let update_flash_image = target
                .update_flash_image_filename()
                .and_then(|f| raw_files.get(f));
            let user_app_elf = raw_files.get(target.user_app_elf_filename()).cloned();

            let c_rom_bytes = caliptra_rom.map(|v| v.as_slice()).unwrap_or(&[]);
            let c_fw_bytes = caliptra_fw.map(|v| v.as_slice()).unwrap_or(&[]);
            let m_rom_bytes = mcu_rom.map(|v| v.as_slice()).unwrap_or(&[]);
            let soc_m_bytes = soc_manifest.map(|v| v.as_slice()).unwrap_or(&[]);

            if let Some(m_rt) = mcu_runtime {
                let bundle = FirmwareBundle {
                    caliptra_rom: CaliptraRomBinary(c_rom_bytes.to_vec()),
                    caliptra_rt: CaliptraRtBinary(c_fw_bytes.to_vec()),
                    mcu_rom: McuRomBinary(m_rom_bytes.to_vec()),
                    mcu_fw: McuFwBinary {
                        bytes: m_rt.clone(),
                        flash_image: flash_image.cloned().unwrap_or_default(),
                        pldm_fw_pkg: pldm_fw_pkg.cloned().unwrap_or_default(),
                        update_flash_image: update_flash_image.cloned().unwrap_or_default(),
                        user_app_elf,
                    },
                    soc_manifest: SocManifestBinary(soc_m_bytes.to_vec()),
                };
                let static_bundle: &'static FirmwareBundle = Box::leak(Box::new(bundle));
                binaries
                    .bundles
                    .write()
                    .unwrap()
                    .insert(**target, static_bundle);
            } else {
                return Err(anyhow::anyhow!(
                    "Firmware bundle is incomplete: missing binaries for target '{id}'"
                ));
            }
        }

        Ok(binaries)
    }

    pub fn vendor_pk_hash_for_target(
        &self,
        target: &crate::firmware::FirmwareTarget,
    ) -> Option<[u8; 48]> {
        let bundle = self.get(target).ok()?;
        if let Ok((manifest, _)) = ImageManifest::ref_from_prefix(&bundle.caliptra_rt) {
            CaliptraBuilder::vendor_pk_hash(manifest).ok()
        } else {
            None
        }
    }

    pub fn vendor_pk_hash(&self) -> Option<[u8; 48]> {
        self.vendor_pk_hash_for_target(&crate::firmware::targets::TEST_DO_NOTHING)
    }

    pub fn owner_pk_hash_for_target(
        &self,
        target: &crate::firmware::FirmwareTarget,
    ) -> Option<[u8; 48]> {
        let bundle = self.get(target).ok()?;
        if let Ok((manifest, _)) = ImageManifest::ref_from_prefix(&bundle.caliptra_rt) {
            CaliptraBuilder::owner_pk_hash(manifest).ok()
        } else {
            None
        }
    }

    pub fn owner_pk_hash(&self) -> Option<[u8; 48]> {
        self.owner_pk_hash_for_target(&crate::firmware::targets::TEST_DO_NOTHING)
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

            if name == "emulator" {
                binaries.emulators.push((name, data));
            }
        }

        Ok(binaries)
    }

    /// Get the prebuilt emulator binary.
    pub fn emulator(&self) -> Result<Vec<u8>> {
        for (name, data) in self.emulators.iter() {
            if name == "emulator" {
                return Ok(data.clone());
            }
        }

        Err(anyhow::anyhow!("Emulator binary not found in bundle"))
    }
}

#[derive(Default)]
pub struct AllBuildArgs<'a> {
    pub output: Option<&'a str>,
    pub platform: Option<&'a str>,
    pub rom_features: Option<&'a str>,
    pub runtime_features: Option<&'a str>,
    pub separate_runtimes: bool,
    pub soc_images: Option<Vec<ImageCfg>>,
    pub mcu_cfgs: Option<Vec<ImageCfg>>,
    pub pldm_manifest: Option<&'a str>,
    pub vendor: Option<&'a str>,
    pub model: Option<&'a str>,
    pub profile: Option<&'a str>,
}

/// Build Caliptra ROM and firmware bundle, MCU ROM and runtime, and SoC manifest, and package them all together in a ZIP file.
pub fn all_build(args: AllBuildArgs) -> Result<()> {
    let AllBuildArgs {
        output,
        platform,
        rom_features,
        runtime_features,
        separate_runtimes,
        soc_images,
        mcu_cfgs,
        pldm_manifest,
        vendor,
        model,
        profile,
    } = args;

    // TODO: use temp files
    let platform = platform.unwrap_or("emulator");
    let rom_features = rom_features.unwrap_or_default();
    let mcu_rom = crate::rom_build(&CaliptraBuildArgs {
        platform: Some(platform),
        features: Some(rom_features),
        ..Default::default()
    })?;

    let test_roms: Result<Vec<(PathBuf, String)>> =
        maybe_into_par_iter(firmware::REGISTERED_FW.to_vec())
            .map(|fwid| {
                let target_dir = if cfg!(feature = "parallel-build") {
                    Some(
                        crate::target_dir()
                            .join(format!("target-rom-{}-{}", fwid.crate_name, fwid.bin_name)),
                    )
                } else {
                    None
                };
                let bin_path = PathBuf::from(crate::test_rom_build(&CaliptraBuildArgs {
                    platform: Some(platform),
                    fwid: Some(fwid),
                    target_dir,
                    ..Default::default()
                })?);

                let filename = bin_path.file_name().unwrap().to_str().unwrap().to_string();
                Ok((bin_path, filename))
            })
            .collect();
    let mut test_roms = test_roms?;

    let cptra_test_roms: Result<Vec<(PathBuf, String)>> =
        maybe_into_par_iter(firmware::CPTRA_REGISTERED_FW.to_vec())
            .map(|fwid| {
                let filename = format!("cptra-test-rom-{}-{}.bin", fwid.crate_name, fwid.bin_name);
                let target_dir = if cfg!(feature = "parallel-build") {
                    crate::target_dir().join(format!("target-cptra-rom-{}", filename))
                } else {
                    crate::target_dir()
                };
                let release_dir = target_dir.join(TARGET).join("release");

                std::fs::create_dir_all(&release_dir)?;
                let bin_path = release_dir.join(&filename);
                let rom_bytes = caliptra_builder::build_firmware_rom(fwid)?;
                std::fs::write(&bin_path, rom_bytes)?;
                Ok((bin_path, filename))
            })
            .collect();
    test_roms.extend(cptra_test_roms?);

    // Auto-enable the `release` cargo feature when building with the `release`
    // profile, mirroring the same logic in `xtask runtime-build`.  This strips
    // kernel `debug!()`, romtime `println!()`, Console, DebugWriter, etc.
    let is_release = matches!(profile, Some("release"));

    let mut runtime_features = match runtime_features {
        Some(r) if !r.is_empty() => r.split(",").collect::<Vec<&str>>(),
        _ => {
            if separate_runtimes {
                if is_release {
                    crate::features::RELEASE_RUNTIME_TEST_FEATURES.to_vec()
                } else if platform == "fpga" {
                    crate::features::FPGA_RUNTIME_TEST_FEATURES.to_vec()
                } else {
                    crate::features::EMULATOR_RUNTIME_TEST_FEATURES.to_vec()
                }
            } else {
                vec![]
            }
        }
    };

    // Propagate hw-2-1 from rom_features to runtime builds so that
    // staging SRAM is enabled (required when ImageManifest > 16 KB).
    let propagate_hw_2_1 = rom_features.contains("hw-2-1");
    if propagate_hw_2_1 && !runtime_features.iter().any(|f| *f == "hw-2-1") {
        runtime_features.push("hw-2-1");
    }

    let mut base_runtime_features = vec![];
    let mut separate_features = vec![];
    if separate_runtimes {
        // build a separate runtime for each feature flag, since they are used as tests
        separate_features = runtime_features;
    } else {
        // build one runtime with all feature flags
        base_runtime_features = runtime_features;
    }

    if is_release && !base_runtime_features.contains(&"release") {
        base_runtime_features.push("release");
    }

    // Determine effective SoC images for base runtime features.
    // When the caller didn't supply --soc_image args, auto-create them for
    let effective_soc_images = if soc_images.is_none() {
        let needs_soc = base_runtime_features.iter().any(|f| {
            f.contains("flash")
                || f.contains("streaming")
                || f.contains("attestation")
                || f.contains("firmware-activate")
        });
        if needs_soc {
            let is_attestation = base_runtime_features.iter().any(|f| {
                *f == "test-mctp-spdm-attestation" || *f == "test-mctp-spdm-attestation-pcr-quote"
            });
            let (images, _paths) = if is_attestation {
                create_attestation_soc_images()
            } else {
                create_default_soc_images()
            };
            Some(images)
        } else {
            None
        }
    } else {
        soc_images.clone()
    };

    let effective_vendor = vendor.unwrap_or("ChipsAlliance");
    let effective_model = model.unwrap_or("Caliptra-SS");
    pre_generate_attestation_manifest_config(
        effective_vendor,
        effective_model,
        effective_soc_images.as_deref().unwrap_or(&[]),
    )?;

    let base_runtime_file = tempfile::NamedTempFile::new().unwrap();
    let base_runtime_path = base_runtime_file.path().to_str().unwrap();

    let base_runtime_features_str = if base_runtime_features.is_empty() {
        if propagate_hw_2_1 {
            Some("hw-2-1".to_string())
        } else {
            None
        }
    } else {
        Some(base_runtime_features.join(","))
    };

    // For FPGA devel builds with no explicit base-runtime features (i.e.
    // separate-runtimes mode where every test gets its own runtime), suppress
    // the crate's `default = ["all-features"]` because that would include
    // streaming-boot, flash-boot, firmware-update, etc. and overflow the
    // FPGA's 512 KB SRAM. Tests that need services such as SPDM should use an
    // explicit test feature so the corresponding separate runtime enables it.
    // Release builds (any platform) also suppress defaults: `all-features`
    // pulls in SPDM, streaming-boot, firmware-update, etc. on top of `release`
    // and overflows both the 512 KB FPGA and emulator release SRAM budgets.
    // Feature-specific release test runtimes below use `--no-default-features`
    // too, so `release` must not pull in unrelated services such as
    // firmware-update.
    let base_no_default = is_release || (platform == "fpga" && base_runtime_features.is_empty());
    let effective_features = base_runtime_features_str.as_deref();

    let mcu_runtime = &crate::runtime_build_with_apps(&CaliptraBuildArgs {
        features: effective_features,
        output_name: Some(base_runtime_path.to_string()),
        example_app: false,
        platform: Some(platform),
        profile,
        no_default_features: base_no_default,
        ..Default::default()
    })?;
    let user_app_profile = profile.unwrap_or("devel");
    let user_app_elf_path = crate::target_dir()
        .join(TARGET)
        .join(user_app_profile)
        .join("user-app");
    let user_app_elf = std::fs::read(&user_app_elf_path)?;

    let mut bare_metal_paths = vec![];
    for package in crate::features::BARE_METAL_BINARIES {
        let path = crate::bare_metal_build(Some(platform), package)?;
        bare_metal_paths.push((package.to_string(), path));
    }

    let mcu_image_cfg = get_image_cfg_feature(&mcu_cfgs.clone().unwrap_or_default(), "none");
    let mut caliptra_builder = crate::CaliptraBuilder::new(&CaliptraBuildArgs {
        fpga: platform == "fpga",
        mcu_firmware: Some(mcu_runtime.into()),
        soc_images: effective_soc_images.clone(),
        mcu_image_cfg,
        vendor: vendor.map(|s| s.to_string()),
        model: model.map(|s| s.to_string()),
        ..Default::default()
    });
    let caliptra_rom = caliptra_builder.get_caliptra_rom()?;
    let caliptra_fw = caliptra_builder.get_caliptra_fw()?;
    let vendor_pk_hash = caliptra_builder.get_vendor_pk_hash()?.to_string();
    println!("Vendor PK hash: {:x?}", vendor_pk_hash);
    let soc_manifest = caliptra_builder.get_soc_manifest(None)?;

    let mut builder_svn7 = crate::CaliptraBuilder::new(&CaliptraBuildArgs {
        fpga: platform == "fpga",
        svn: Some(7),
        ..Default::default()
    });
    let caliptra_fw_svn7 = builder_svn7.get_caliptra_fw()?;

    let mut builder_svn128 = crate::CaliptraBuilder::new(&CaliptraBuildArgs {
        fpga: platform == "fpga",
        svn: Some(128),
        ..Default::default()
    });
    let caliptra_fw_svn128 = builder_svn128.get_caliptra_fw()?;
    let mut builder_key2 = crate::CaliptraBuilder::new(&CaliptraBuildArgs {
        fpga: platform == "fpga",
        use_second_key: true,
        ..Default::default()
    });
    let caliptra_fw_key2 = builder_key2.get_caliptra_fw()?;

    let mut builder_ocp_lock = crate::CaliptraBuilder::new(&CaliptraBuildArgs {
        fpga: platform == "fpga",
        ocp_lock: true,
        ..Default::default()
    });
    let caliptra_fw_ocp_lock = builder_ocp_lock.get_caliptra_fw()?;
    let flash_image = create_flash_image(
        Some(caliptra_fw.clone()),
        Some(soc_manifest.clone()),
        Some(mcu_runtime.into()),
        effective_soc_images
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
    // Include both runtime features (which may have matching ROM features) and
    // ROM-only test features that don't have a corresponding runtime feature.
    //
    // Preserve the base ROM binary: feature ROM builds reuse the same bundler
    // output path (`mcu-rom-<platform>.bin`) and rename it to the feature-specific
    // name, which would delete the base ROM that `mcu_rom` still references.
    let mcu_rom_preserved = tempfile::NamedTempFile::new()?;
    std::fs::copy(&mcu_rom, mcu_rom_preserved.path())?;
    let mcu_rom = mcu_rom_preserved.path().to_path_buf();

    let rom_features_to_build: Vec<&str> = separate_features
        .iter()
        .copied()
        .chain(crate::features::ROM_ONLY_TEST_FEATURES.iter().copied())
        .collect();
    let feature_roms: Result<Vec<(PathBuf, String)>> = maybe_par_iter(&rom_features_to_build)
        .filter_map(|feature| {
            let target_dir = if cfg!(feature = "parallel-build") {
                Some(crate::target_dir().join(format!("target-feature-rom-{}", feature)))
            } else {
                None
            };
            match crate::rom_build(&CaliptraBuildArgs {
                platform: Some(platform),
                features: Some(feature),
                target_dir,
                ..Default::default()
            }) {
                Ok(rom_path) => {
                    let rom_name = format!("mcu-test-rom-feature-{}.bin", feature);
                    println!("Built feature ROM: {rom_path:?} -> {}", rom_name);
                    Some(Ok((rom_path, rom_name)))
                }
                Err(e) => {
                    println!(
                        "Skipping feature ROM for {}: {} (will use generic ROM)",
                        feature, e
                    );
                    None
                }
            }
        })
        .collect();
    test_roms.extend(feature_roms?);

    let test_runtimes: Result<Vec<FeatureTestResource>> = maybe_par_iter(&separate_features)
        .map(|feature| {
            let target_dir = if cfg!(feature = "parallel-build") {
                Some(crate::target_dir().join(format!("target-runtime-{}", feature)))
            } else {
                None
            };
            let feature_runtime_file = tempfile::NamedTempFile::new().unwrap();
            let feature_runtime_path = feature_runtime_file.path().to_str().unwrap().to_string();
            let target = firmware::targets::FIRMWARE_TARGETS
                .iter()
                .copied()
                .find(|t| t.id() == *feature);
            let include_example_app = target.is_some_and(|t| t.example_app());

            // When the matching ROM feature enables hw-2-1, combine it with
            // the separate runtime feature so the staging SRAM path is enabled.
            let needs_hw_2_1 = propagate_hw_2_1
                || *feature == "test-flash-based-boot"
                || *feature == "test-firmware-activate"
                || *feature == "test-firmware-update-flash"
                || *feature == "test-usb-ocp-recovery";
            let mut combined_features = if needs_hw_2_1 && *feature != "hw-2-1" {
                format!("{},hw-2-1", feature)
            } else {
                feature.to_string()
            };

            if is_release && !combined_features.contains("release") {
                combined_features = format!("{},release", combined_features);
            }

            crate::runtime_build_with_apps(&CaliptraBuildArgs {
                features: Some(&combined_features),
                output_name: Some(feature_runtime_path),
                example_app: include_example_app,
                platform: Some(platform),
                profile,
                target_dir: target_dir.clone(),
                no_default_features: true,
                ..Default::default()
            })?;

            // Capture the user-app ELF bytes for this feature so host-side
            // defmt decoders can read them out of the firmware bundle. Without
            // `parallel-build`, all features share `target/<TARGET>/<profile>/`
            // and overwrite each other, so we must read immediately.
            let user_app_profile = profile.unwrap_or("devel");
            let user_app_target_dir = target_dir.unwrap_or_else(crate::target_dir);
            let user_app_elf_path = user_app_target_dir
                .join(TARGET)
                .join(user_app_profile)
                .join("user-app");
            let user_app_elf = std::fs::read(&user_app_elf_path).ok();

            let mcu_image_cfg =
                get_image_cfg_feature(&mcu_cfgs.clone().unwrap_or_default(), feature).or_else(
                    || default_mcu_image_cfg_for_feature(feature, feature_runtime_file.path()),
                );

            // For features that require SoC images, create default ones if not provided
            let feature_requires_soc = feature.contains("flash")
                || feature.contains("streaming")
                || feature.contains("attestation")
                || feature.contains("firmware-activate");
            let (feature_soc_images, feature_soc_images_paths) =
                if feature_requires_soc && soc_images.is_none() {
                    let (images, paths) = if *feature == "test-mctp-spdm-attestation"
                        || *feature == "test-mctp-spdm-attestation-pcr-quote"
                    {
                        create_attestation_soc_images()
                    } else {
                        create_default_soc_images()
                    };
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

            let mut caliptra_builder = crate::CaliptraBuilder::new(&CaliptraBuildArgs {
                fpga: platform == "fpga",
                caliptra_rom: Some(caliptra_rom.clone()),
                caliptra_firmware: Some(caliptra_fw.clone()),
                vendor_pk_hash: Some(vendor_pk_hash.clone()),
                mcu_firmware: Some(feature_runtime_file.path().to_path_buf()),
                soc_images: feature_soc_images.clone(),
                mcu_image_cfg: mcu_image_cfg.clone(),
                vendor: vendor.map(|s| s.to_string()),
                model: model.map(|s| s.to_string()),
                ..Default::default()
            });
            let feature_soc_manifest_file = tempfile::NamedTempFile::new().unwrap();
            caliptra_builder.get_soc_manifest(feature_soc_manifest_file.path().to_str())?;

            // Flash-based boot features require partition table at offset 0
            let is_flash_based_boot =
                *feature == "test-flash-based-boot" || *feature == "test-firmware-update-flash";

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
                || *feature == "test-firmware-update-streaming"
                || *feature == "test-streaming-boot-flash-write-back"
                || *feature == "test-firmware-activate";
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

            Ok(FeatureTestResource {
                feature: feature.to_string(),
                runtime_file: feature_runtime_file,
                soc_manifest_file: feature_soc_manifest_file,
                flash_image: feature_flash_image,
                pldm_fw_pkg: feature_pldm_fw_pkg,
                update_flash_image: feature_update_flash_image,
                user_app_elf,
            })
        })
        .collect();
    let test_runtimes = test_runtimes?;

    let default_name = if is_release {
        "all-fw-release.zip"
    } else {
        "all-fw.zip"
    };
    let default_path = crate::target_dir().join(default_name);
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
    add_to_zip(
        &caliptra_fw_svn7,
        FirmwareBinaries::CALIPTRA_FW_SVN7_NAME,
        &mut zip,
        options,
    )?;
    add_to_zip(
        &caliptra_fw_svn128,
        FirmwareBinaries::CALIPTRA_FW_SVN128_NAME,
        &mut zip,
        options,
    )?;
    add_to_zip(
        &caliptra_fw_key2,
        FirmwareBinaries::CALIPTRA_FW_KEY2_NAME,
        &mut zip,
        options,
    )?;
    add_to_zip(
        &caliptra_fw_ocp_lock,
        FirmwareBinaries::CALIPTRA_FW_OCP_LOCK_NAME,
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
    add_bytes_to_zip(
        &user_app_elf,
        FirmwareBinaries::USER_APP_ELF_NAME,
        &mut zip,
        options,
    )?;
    for (package, path) in bare_metal_paths {
        let zip_name = format!("bare_metal/{}.bin", package);
        add_to_zip(&path, &zip_name, &mut zip, options)?;
    }
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

    for FeatureTestResource {
        feature,
        runtime_file: runtime,
        soc_manifest_file: soc_manifest,
        flash_image,
        pldm_fw_pkg,
        update_flash_image,
        user_app_elf,
    } in test_runtimes
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

        if let Some(elf_bytes) = user_app_elf.as_ref() {
            let elf_name = format!("mcu-test-user-app-elf-{}.bin", feature);
            add_bytes_to_zip(elf_bytes, &elf_name, &mut zip, options)?;
        }

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
}

/// Build the emulator binary and package it in emulators.zip.
pub fn emulator_build(args: EmulatorBuildArgs) -> Result<()> {
    let EmulatorBuildArgs { output } = args;

    // Build the emulator (no features needed anymore)
    let emulator_path = build_emulator_with_feature("")?
        .ok_or_else(|| anyhow::anyhow!("Failed to build emulator"))?;

    let default_path = crate::target_dir().join("emulators.zip");
    let path = output.map(Path::new).unwrap_or(&default_path);
    println!("Creating emulator ZIP file: {}", path.display());
    let file = std::fs::File::create(path)?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o755) // Make emulator executable
        .last_modified_time(zip::DateTime::try_from(chrono::Local::now().naive_local())?);

    println!("Adding {} -> emulator", emulator_path.display());
    add_to_zip(&emulator_path, "emulator", &mut zip, options)?;

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

fn default_mcu_image_cfg_for_feature(feature: &str, runtime_path: &Path) -> Option<ImageCfg> {
    if feature != "test-firmware-update-flash" {
        return None;
    }

    Some(ImageCfg {
        path: runtime_path.to_path_buf(),
        load_addr: MCI_BASE_AXI_ADDRESS + MCU_SRAM_OFFSET,
        staging_addr: MCI_BASE_AXI_ADDRESS + MCU_MBOX_SRAM1_OFFSET + (512 * 1024),
        image_id: MCU_RT_IDENTIFIER,
        component_id: MCU_RT_IDENTIFIER,
        exec_bit: 2,
        feature: feature.to_string(),
        ..Default::default()
    })
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

fn add_bytes_to_zip(
    data: &[u8],
    name: &str,
    zip: &mut ZipWriter<std::fs::File>,
    options: FileOptions<'_, ()>,
) -> Result<()> {
    println!("Adding {}: {} bytes", name, data.len());
    zip.start_file(name, options)?;
    zip.write_all(data)?;
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

    crate::flash_image::flash_image_create(&CaliptraBuildArgs {
        caliptra_firmware: caliptra_fw_path,
        soc_manifest: soc_manifest_path,
        mcu_firmware: mcu_runtime_path,
        soc_image_paths: Some(
            soc_images_paths
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect(),
        ),
        offset: flash_offset,
        output_path: Some(flash_image_path.to_string_lossy().to_string()),
        ..Default::default()
    })?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firmware_binaries_coverage() {
        let binaries = FirmwareBinaries::from_env().unwrap();
        for target in crate::firmware::targets::FIRMWARE_TARGETS {
            let bundle = binaries.as_bundle(target);
            if *target == &crate::firmware::targets::BARE_METAL
                || *target == &crate::firmware::targets::PROVISIONING_TEST_UNLOCKED_FW
            {
                assert!(
                    !bundle.mcu_fw.is_empty(),
                    "Target {} missing mcu_fw",
                    target.id()
                );
            } else {
                assert!(
                    !bundle.caliptra_rom.is_empty(),
                    "Target {} missing caliptra_rom",
                    target.id()
                );
                assert!(
                    !bundle.caliptra_rt.is_empty(),
                    "Target {} missing caliptra_rt",
                    target.id()
                );
                assert!(
                    !bundle.mcu_rom.is_empty(),
                    "Target {} missing mcu_rom",
                    target.id()
                );
                assert!(
                    !bundle.mcu_fw.is_empty(),
                    "Target {} missing mcu_fw",
                    target.id()
                );
            }
        }
    }
}
