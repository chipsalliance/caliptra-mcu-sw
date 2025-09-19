// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use caliptra_builder::FwId;
use caliptra_image_types::ImageManifest;
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zerocopy::FromBytes;
use zip::{
    write::{FileOptions, SimpleFileOptions},
    ZipWriter,
};

use crate::firmware;
use crate::CaliptraBuilder;

use std::{env::var, sync::OnceLock};

#[derive(Default)]
pub struct FirmwareBinaries {
    pub caliptra_rom: Vec<u8>,
    pub caliptra_fw: Vec<u8>,
    pub mcu_rom: Vec<u8>,
    pub mcu_runtime: Vec<u8>,
    pub soc_manifest: Vec<u8>,
    pub test_roms: Vec<(String, Vec<u8>)>,
    pub test_soc_manifests: Vec<(String, Vec<u8>)>,
    pub test_runtimes: Vec<(String, Vec<u8>)>,
}

impl FirmwareBinaries {
    const CALIPTRA_ROM_NAME: &'static str = "caliptra_rom.bin";
    const CALIPTRA_FW_NAME: &'static str = "caliptra_fw.bin";
    const MCU_ROM_NAME: &'static str = "mcu_rom.bin";
    const MCU_RUNTIME_NAME: &'static str = "mcu_runtime.bin";
    const SOC_MANIFEST_NAME: &'static str = "soc_manifest.bin";

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
}

#[derive(Default)]
pub struct AllBuildArgs<'a> {
    pub output: Option<&'a str>,
    pub use_dccm_for_stack: bool,
    pub dccm_offset: Option<u32>,
    pub dccm_size: Option<u32>,
    pub platform: Option<&'a str>,
    pub rom_features: Option<&'a str>,
    pub runtime_features: Option<&'a str>,
    pub separate_runtimes: bool,
}

/// Build Caliptra ROM and firmware bundle, MCU ROM and runtime, and SoC manifest, and package them all together in a ZIP file.
pub fn all_build(args: AllBuildArgs) -> Result<()> {
    let AllBuildArgs {
        output,
        use_dccm_for_stack,
        dccm_offset,
        dccm_size,
        platform,
        rom_features,
        runtime_features,
        separate_runtimes,
    } = args;

    // TODO: use temp files
    let platform = platform.unwrap_or("emulator");
    let rom_features = rom_features.unwrap_or_default();
    let mcu_rom = crate::rom_build(Some(platform), rom_features)?;
    let memory_map = match platform {
        "emulator" => &mcu_config_emulator::EMULATOR_MEMORY_MAP,
        "fpga" => &mcu_config_fpga::FPGA_MEMORY_MAP,
        _ => bail!("Unknown platform: {:?}", platform),
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

    let mcu_runtime = &crate::runtime_build_with_apps_cached(
        &base_runtime_features,
        Some(base_runtime_path),
        false,
        Some(platform),
        Some(memory_map),
        use_dccm_for_stack,
        dccm_offset,
        dccm_size,
        None,
        None,
    )?;

    let fpga = platform == "fpga";
    let mut caliptra_builder = crate::CaliptraBuilder::new(
        fpga,
        None,
        None,
        None,
        None,
        Some(mcu_runtime.into()),
        None,
        None,
        None,
    );
    let caliptra_rom = caliptra_builder.get_caliptra_rom()?;
    let caliptra_fw = caliptra_builder.get_caliptra_fw()?;
    let vendor_pk_hash = caliptra_builder.get_vendor_pk_hash()?.to_string();
    println!("Vendor PK hash: {:x?}", vendor_pk_hash);
    let soc_manifest = caliptra_builder.get_soc_manifest(None)?;

    let mut test_runtimes = vec![];
    for feature in separate_features.iter() {
        let feature_runtime_file = tempfile::NamedTempFile::new().unwrap();
        let feature_runtime_path = feature_runtime_file.path().to_str().unwrap().to_string();

        crate::runtime_build_with_apps_cached(
            &[feature],
            Some(&feature_runtime_path),
            false,
            Some(platform),
            Some(memory_map),
            use_dccm_for_stack,
            dccm_offset,
            dccm_size,
            None,
            None,
        )?;

        let mut caliptra_builder = crate::CaliptraBuilder::new(
            fpga,
            Some(caliptra_rom.clone()),
            Some(caliptra_fw.clone()),
            None,
            Some(vendor_pk_hash.clone()),
            Some(feature_runtime_file.path().to_path_buf()),
            None,
            None,
            None,
        );
        let feature_soc_manifest_file = tempfile::NamedTempFile::new().unwrap();
        caliptra_builder.get_soc_manifest(feature_soc_manifest_file.path().to_str())?;
        test_runtimes.push((
            feature.to_string(),
            feature_runtime_file,
            feature_soc_manifest_file,
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
    add_to_zip(
        &PathBuf::from(mcu_rom),
        FirmwareBinaries::MCU_ROM_NAME,
        &mut zip,
        options,
    )?;
    add_to_zip(
        &PathBuf::from(mcu_runtime),
        FirmwareBinaries::MCU_RUNTIME_NAME,
        &mut zip,
        options,
    )?;
    add_to_zip(
        &soc_manifest,
        FirmwareBinaries::SOC_MANIFEST_NAME,
        &mut zip,
        options,
    )?;
    for (test_rom, name) in test_roms {
        add_to_zip(&test_rom, &name, &mut zip, options)?;
    }

    for (feature, runtime, soc_manifest) in test_runtimes {
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
    }

    zip.finish()?;

    Ok(())
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
