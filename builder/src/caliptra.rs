// Licensed under the Apache-2.0 license

//! Wrappers around the Caliptra builder library to make it easier to build
//! the ROM, firwmare, and SoC manifest.

use crate::target_dir;
use anyhow::{bail, Result};
use caliptra_auth_man_gen::{
    AuthManifestGenerator, AuthManifestGeneratorConfig, AuthManifestGeneratorKeyConfig,
};
use caliptra_auth_man_types::{
    Addr64, AuthManifestFlags, AuthManifestImageMetadata, AuthManifestPrivKeysConfig,
    AuthManifestPubKeysConfig, AuthorizationManifest, ImageMetadataFlags,
};
use caliptra_image_crypto::RustCrypto as Crypto;
use caliptra_image_fake_keys::*;
use caliptra_image_gen::{from_hw_format, ImageGeneratorCrypto};
use caliptra_image_types::{FwVerificationPqcKeyType, ImageManifest};
use cargo_metadata::MetadataCommand;
use flash_image::MCU_RT_IDENTIFIER;
use hex::ToHex;
use std::{num::ParseIntError, path::PathBuf, str::FromStr};
use zerocopy::{transmute, IntoBytes};

#[derive(Clone, Debug)]
pub struct CaliptraBuilder {
    fpga: bool,
    caliptra_rom: Option<PathBuf>,
    caliptra_firmware: Option<PathBuf>,
    soc_manifest: Option<PathBuf>,
    vendor_pk_hash: Option<String>,
    mcu_firmware: Option<PathBuf>,
    soc_images: Option<Vec<ImageCfg>>,
    mcu_image_cfg: Option<ImageCfg>,
    soc_manifest_svn: Option<u32>,
    vendor: String,
    model: String,
}

impl CaliptraBuilder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fpga: bool,
        caliptra_rom: Option<PathBuf>,
        caliptra_firmware: Option<PathBuf>,
        soc_manifest: Option<PathBuf>,
        vendor_pk_hash: Option<String>,
        mcu_firmware: Option<PathBuf>,
        soc_images: Option<Vec<ImageCfg>>,
        mcu_image_cfg: Option<ImageCfg>,
        soc_manifest_svn: Option<u32>,
        vendor: Option<String>,
        model: Option<String>,
    ) -> Self {
        Self {
            fpga,
            caliptra_rom,
            caliptra_firmware,
            soc_manifest,
            vendor_pk_hash,
            mcu_firmware,
            soc_images,
            mcu_image_cfg,
            soc_manifest_svn,
            vendor: vendor.unwrap_or_else(|| "ChipsAlliance".to_string()),
            model: model.unwrap_or_else(|| "Caliptra-SS".to_string()),
        }
    }

    pub fn get_caliptra_rom(&self) -> Result<PathBuf> {
        if let Some(caliptra_rom) = &self.caliptra_rom {
            if !caliptra_rom.exists() {
                bail!("Caliptra ROM file not found: {:?}", caliptra_rom);
            }
            Ok(caliptra_rom.clone())
        } else {
            Self::compile_caliptra_rom_cached(self.fpga)
        }
    }

    pub fn get_caliptra_fw(&mut self) -> Result<PathBuf> {
        if let Some(caliptra_firmware) = self.caliptra_firmware.as_ref() {
            if !caliptra_firmware.exists() {
                bail!("Caliptra runtime bundle not found: {:?}", caliptra_firmware);
            }
            if self.vendor_pk_hash.is_none() {
                bail!("Vendor public key hash is required for active mode if Caliptra FW is passed as an argument");
            }
        } else {
            let (path, vendor_pk_hash) = Self::compile_caliptra_fw_cached(self.fpga)?;
            self.vendor_pk_hash = Some(vendor_pk_hash);
            self.caliptra_firmware = Some(path);
        }
        Ok(self.caliptra_firmware.clone().unwrap())
    }

    fn get_soc_images_metadata(&self) -> Result<Vec<AuthManifestImageMetadata>> {
        if self.soc_images.is_none() {
            return Ok(vec![]);
        }
        let mut metadata = Vec::new();
        if let Some(soc_images) = &self.soc_images {
            for soc_image in soc_images {
                let soc_metadata = Self::get_soc_manifest_metadata(soc_image)?;
                metadata.push(soc_metadata);
            }
        }
        Ok(metadata)
    }

    pub fn get_soc_manifest(&mut self, name: Option<&str>) -> Result<PathBuf> {
        if self.soc_manifest.is_none() {
            let _ = self.get_caliptra_fw()?;
        }
        // check if we wrote it already when compiling the firmware
        if self.soc_manifest.is_none() {
            if self.mcu_firmware.is_none() {
                bail!("MCU firmware is required to build SoC manifest");
            }
            let mcu_fw_metadata =
                self.get_mcu_manifest_metadata(self.mcu_firmware.as_ref().unwrap())?;
            let soc_images_metadata = self.get_soc_images_metadata()?;
            let mut metadata = vec![mcu_fw_metadata];
            metadata.extend(soc_images_metadata);

            let path = Self::write_soc_manifest(
                metadata.clone(),
                self.soc_manifest_svn.unwrap_or(0),
                name,
            )?;
            self.write_fw_components_config(&metadata)?;
            self.soc_manifest = Some(path);
        }
        Ok(self.soc_manifest.clone().unwrap())
    }

    pub fn replace_manifest_config(
        &mut self,
        metadata: Vec<ImageCfg>,
        svn: Option<u32>,
    ) -> Result<PathBuf> {
        println!("Replacing SoC manifest metadata with: {:?}", metadata);
        // Replace the current metadata
        self.soc_images = Some(metadata);
        self.soc_manifest_svn = svn;

        self.soc_manifest = None; // Clear the cached manifest

        // Rebuild the SoC manifest
        println!("Rebuilding SoC manifest with new metadata");
        self.get_soc_manifest(None)
    }

    pub fn get_vendor_pk_hash(&mut self) -> Result<&str> {
        if self.vendor_pk_hash.is_none() {
            let _ = self.get_caliptra_fw()?;
        }
        Ok(self.vendor_pk_hash.as_ref().unwrap())
    }

    fn get_mcu_manifest_metadata(
        &self,
        runtime_path: &PathBuf,
    ) -> Result<AuthManifestImageMetadata> {
        const IMAGE_SOURCE_IN_REQUEST: u32 = 1;
        let data = std::fs::read(runtime_path).unwrap();
        let mut flags = ImageMetadataFlags(0);
        flags.set_image_source(IMAGE_SOURCE_IN_REQUEST);
        let crypto = Crypto::default();
        let digest = from_hw_format(&crypto.sha384_digest(&data)?);
        let d: String = digest.clone().encode_hex();
        println!("MCU len {} digest: {}", data.len(), d);

        let cfg = if self.mcu_image_cfg.is_some() {
            self.mcu_image_cfg.clone().unwrap()
        } else {
            // Default MCU image configuration with valid addresses and exec_bit
            // Uses FPGA memory map for DMA-accessible staging area
            // exec_bit must be >= 2 (bits 0 and 1 are reserved by Caliptra)
            ImageCfg {
                image_id: MCU_RT_IDENTIFIER,
                exec_bit: 2,
                // MCU staging address in SRAM region (FPGA memory map)
                staging_addr: mcu_config_fpga::FPGA_MEMORY_MAP.sram_offset as u64,
                ..Default::default()
            }
        };
        flags.set_exec_bit(cfg.exec_bit);

        Ok(AuthManifestImageMetadata {
            fw_id: cfg.image_id,
            flags: flags.0,
            digest,
            image_load_address: Addr64 {
                lo: cfg.load_addr as u32,
                hi: (cfg.load_addr >> 32) as u32,
            },
            image_staging_address: Addr64 {
                lo: cfg.staging_addr as u32,
                hi: (cfg.staging_addr >> 32) as u32,
            },
            ..Default::default()
        })
    }

    fn get_soc_manifest_metadata(image_cfg: &ImageCfg) -> Result<AuthManifestImageMetadata> {
        const IMAGE_SOURCE_LOAD_ADDRESS: u32 = 2;
        let data = std::fs::read(&image_cfg.path).unwrap();
        let mut flags = ImageMetadataFlags(0);
        flags.set_ignore_auth_check(false);
        flags.set_image_source(IMAGE_SOURCE_LOAD_ADDRESS);
        flags.set_exec_bit(image_cfg.exec_bit);
        let crypto = Crypto::default();
        let digest = from_hw_format(&crypto.sha384_digest(&data)?);

        Ok(AuthManifestImageMetadata {
            fw_id: image_cfg.image_id,
            flags: flags.0,
            digest,
            image_staging_address: Addr64 {
                lo: image_cfg.staging_addr as u32,
                hi: (image_cfg.staging_addr >> 32) as u32,
            },
            image_load_address: Addr64 {
                lo: image_cfg.load_addr as u32,
                hi: (image_cfg.load_addr >> 32) as u32,
            },
            ..Default::default()
        })
    }

    fn write_soc_manifest(
        metadata: Vec<AuthManifestImageMetadata>,
        svn: u32,
        name: Option<&str>,
    ) -> Result<PathBuf> {
        let manifest = Self::create_auth_manifest_with_metadata(metadata, svn);

        let path = name
            .map(PathBuf::from)
            .unwrap_or(target_dir().join("soc-manifest"));
        std::fs::write(&path, manifest.as_bytes())?;
        Ok(path)
    }

    /// Build the Rust source string containing firmware components config constants.
    fn fw_components_config_source(&self, metadata: &[AuthManifestImageMetadata]) -> String {
        let vendor = &self.vendor;
        let model = &self.model;
        let num_fw_components = metadata.len();
        let fw_ids: Vec<u32> = metadata.iter().map(|m| m.fw_id).collect();
        // NOTE: If ordering matters beyond insertion order, sort here.
        // fw_ids.sort_unstable();
        let mut s = String::new();
        s.push_str("// Licensed under the Apache-2.0 license\n");
        s.push_str("// AUTO-GENERATED FILE. DO NOT EDIT.\n");
        s.push_str("// Generated by CaliptraBuilder::write_fw_components_config\n");
        s.push_str(&format!("pub const VENDOR: &str = \"{}\";\n", vendor));
        s.push_str(&format!("pub const MODEL: &str = \"{}\";\n", model));
        s.push_str(&format!(
            "pub const NUM_FW_COMPONENTS: usize = {};\n",
            num_fw_components
        ));
        s.push_str("// Alias for code wanting a semantic name focused on IDs specifically.\n");
        s.push_str("pub const NUM_FW_IDS: usize = NUM_FW_COMPONENTS;\n");
        // Emit two parallel arrays:
        // 1. Numeric FW IDs (u32) for code needing arithmetic / comparisons.
        // 2. String FW IDs (hex) for display / protocols wanting string OIDs.
        s.push_str("pub const FW_IDS: [u32; NUM_FW_COMPONENTS] = [");
        for (i, fw_id) in fw_ids.iter().enumerate() {
            if i > 0 {
                s.push_str(", ");
            }
            s.push_str(&format!("0x{:08X}", fw_id));
        }
        s.push_str("];\n");

        s.push_str("pub const FW_ID_STRS: [&str; NUM_FW_COMPONENTS] = [");
        for (i, fw_id) in fw_ids.iter().enumerate() {
            if i > 0 {
                s.push_str(", ");
            }
            s.push_str(&format!("\"0x{:08X}\"", fw_id));
        }
        s.push_str("];\n");
        s
    }

    /// Write the soc_env_config.rs file into target/generated only (no OUT_DIR dependency).
    pub fn write_fw_components_config(&self, metadata: &[AuthManifestImageMetadata]) -> Result<()> {
        let consts_file = self.fw_components_config_source(metadata);
        // Destination: workspace target/generated (stable location for consumers to include or copy).
        let generated_dir = target_dir().join("generated");
        std::fs::create_dir_all(&generated_dir)?;
        let relay_path = generated_dir.join("soc_env_config.rs");
        std::fs::write(&relay_path, &consts_file)?;
        println!(
            "Generated FW components config relay file at: {}",
            relay_path.display()
        );
        Ok(())
    }

    /// Explicit path-based writer; lets tests or tools put the file anywhere without relying on OUT_DIR.
    pub fn write_fw_components_config_to<P: AsRef<std::path::Path>>(
        &self,
        metadata: &[AuthManifestImageMetadata],
        path: P,
    ) -> Result<()> {
        let consts_file = self.fw_components_config_source(metadata);
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path.as_ref(), consts_file)?;
        Ok(())
    }

    fn caliptra_version() -> Option<String> {
        let metadata = MetadataCommand::new().exec().unwrap();
        if let Some(caliptra) = metadata
            .packages
            .iter()
            .find(|p| *p.name == "caliptra-builder")
        {
            if let Some(source) = caliptra.source.as_ref() {
                if source.repr.starts_with("git") && source.repr.contains('#') {
                    // If the source is a git repository, we can extract the commit hash
                    return source.repr.split('#').next_back().map(|s| s.to_string());
                }
            }
        }
        println!("Could not determine Caliptra version from Cargo metadata, local checkout?");
        None
    }

    fn compile_caliptra_rom_cached(fpga: bool) -> Result<PathBuf> {
        let platform = if fpga { "fpga" } else { "emulator" };
        if let Some(version) = Self::caliptra_version() {
            let path = target_dir().join(format!("caliptra-rom-{}-{}.bin", version, platform));
            if path.exists() {
                println!("Using cached Caliptra ROM at {:?}", path);
                return Ok(path);
            }
            println!(
                "Caliptra version {} not found in cache, compiling ROM...",
                version
            );
            let compiled_rom = Self::compile_caliptra_rom_uncached(fpga)?;
            std::fs::copy(compiled_rom, &path)?;
            Ok(path)
        } else {
            println!("Caliptra version not found so cannot use cached ROM");
            Self::compile_caliptra_rom_uncached(fpga)
        }
    }

    fn compile_caliptra_rom_uncached(fpga: bool) -> Result<PathBuf> {
        let rom_bytes = if fpga {
            caliptra_builder::build_firmware_rom(
                &caliptra_builder::firmware::ROM_FPGA_WITH_UART,
                // TODO: use &caliptra_builder::firmware::ROM_FPGA_WITH_UART_SS,
            )?
        } else {
            caliptra_builder::rom_for_fw_integration_tests()?.to_vec()
            // TODO: use caliptra_builder::ss_rom_for_fw_integration_tests()?.to_vec()
        };
        let path = target_dir().join("caliptra-rom.bin");
        std::fs::write(&path, rom_bytes)?;
        Ok(path)
    }

    fn compile_caliptra_fw_cached(fpga: bool) -> Result<(PathBuf, String)> {
        let platform = if fpga { "fpga" } else { "emulator" };
        if let Some(version) = Self::caliptra_version() {
            let path =
                target_dir().join(format!("caliptra-fw-bundle-{}-{}.bin", version, platform));
            if path.exists() {
                println!("Using cached Caliptra FW bundle at {:?}", path);
                return Self::parse_fw_bundle(path);
            }
            println!(
                "Caliptra FW bundle version {} not found in cache, compiling...",
                version
            );
            let compiled_fw_bundle = Self::compile_caliptra_fw_uncached(fpga)?.0;
            std::fs::copy(compiled_fw_bundle, &path)?;
            Self::parse_fw_bundle(path)
        } else {
            println!("Caliptra version not found so cannot use cached FW bundle");
            Self::compile_caliptra_fw_uncached(fpga)
        }
    }

    fn parse_fw_bundle(path: PathBuf) -> Result<(PathBuf, String)> {
        let manifest = {
            let bundle: [u8; core::mem::size_of::<ImageManifest>()] = std::fs::read(&path)?
                [..core::mem::size_of::<ImageManifest>()]
                .try_into()
                .unwrap();
            transmute!(bundle)
        };
        Ok((path, Self::vendor_pk_hash_str(manifest)?))
    }

    pub fn vendor_pk_hash(manifest: &ImageManifest) -> Result<[u8; 48]> {
        let crypto = Crypto::default();
        Ok(from_hw_format(&crypto.sha384_digest(
            manifest.preamble.vendor_pub_key_info.as_bytes(),
        )?))
    }

    fn vendor_pk_hash_str(manifest: ImageManifest) -> Result<String> {
        Ok(Self::vendor_pk_hash(&manifest)?.encode_hex())
    }

    fn compile_caliptra_fw_uncached(fpga: bool) -> Result<(PathBuf, String)> {
        let opts = caliptra_builder::ImageOptions {
            pqc_key_type: FwVerificationPqcKeyType::LMS,
            ..Default::default()
        };

        let bundle = if fpga {
            caliptra_builder::build_and_sign_image(
                &caliptra_builder::firmware::FMC_FPGA_WITH_UART,
                &caliptra_builder::firmware::APP_WITH_UART_FPGA,
                opts,
            )?
        } else {
            caliptra_builder::build_and_sign_image(
                &caliptra_builder::firmware::FMC_WITH_UART,
                &caliptra_builder::firmware::APP_WITH_UART,
                opts,
            )?
        };
        let fw_bytes = bundle.to_bytes()?;
        let path = target_dir().join("caliptra-fw-bundle.bin");
        std::fs::write(&path, fw_bytes)?;
        Ok((path, Self::vendor_pk_hash_str(bundle.manifest)?))
    }

    pub fn create_auth_manifest_with_metadata(
        image_metadata_list: Vec<AuthManifestImageMetadata>,
        svn: u32,
    ) -> AuthorizationManifest {
        let vendor_fw_key_info: AuthManifestGeneratorKeyConfig = AuthManifestGeneratorKeyConfig {
            pub_keys: AuthManifestPubKeysConfig {
                ecc_pub_key: VENDOR_ECC_KEY_0_PUBLIC,
                lms_pub_key: VENDOR_LMS_KEY_0_PUBLIC,
                mldsa_pub_key: VENDOR_MLDSA_KEY_0_PUBLIC,
            },
            priv_keys: Some(AuthManifestPrivKeysConfig {
                ecc_priv_key: VENDOR_ECC_KEY_0_PRIVATE,
                lms_priv_key: VENDOR_LMS_KEY_0_PRIVATE,
                mldsa_priv_key: VENDOR_MLDSA_KEY_0_PRIVATE,
            }),
        };

        let vendor_man_key_info: AuthManifestGeneratorKeyConfig = AuthManifestGeneratorKeyConfig {
            pub_keys: AuthManifestPubKeysConfig {
                ecc_pub_key: VENDOR_ECC_KEY_1_PUBLIC,
                lms_pub_key: VENDOR_LMS_KEY_1_PUBLIC,
                mldsa_pub_key: VENDOR_MLDSA_KEY_0_PUBLIC,
            },
            priv_keys: Some(AuthManifestPrivKeysConfig {
                ecc_priv_key: VENDOR_ECC_KEY_1_PRIVATE,
                lms_priv_key: VENDOR_LMS_KEY_1_PRIVATE,
                mldsa_priv_key: VENDOR_MLDSA_KEY_0_PRIVATE,
            }),
        };

        let owner_fw_key_info: Option<AuthManifestGeneratorKeyConfig> =
            Some(AuthManifestGeneratorKeyConfig {
                pub_keys: AuthManifestPubKeysConfig {
                    ecc_pub_key: OWNER_ECC_KEY_PUBLIC,
                    lms_pub_key: OWNER_LMS_KEY_PUBLIC,
                    mldsa_pub_key: OWNER_MLDSA_KEY_PUBLIC,
                },
                priv_keys: Some(AuthManifestPrivKeysConfig {
                    ecc_priv_key: OWNER_ECC_KEY_PRIVATE,
                    lms_priv_key: OWNER_LMS_KEY_PRIVATE,
                    mldsa_priv_key: OWNER_MLDSA_KEY_PRIVATE,
                }),
            });

        let owner_man_key_info: Option<AuthManifestGeneratorKeyConfig> =
            Some(AuthManifestGeneratorKeyConfig {
                pub_keys: AuthManifestPubKeysConfig {
                    ecc_pub_key: OWNER_ECC_KEY_PUBLIC,
                    lms_pub_key: OWNER_LMS_KEY_PUBLIC,
                    mldsa_pub_key: OWNER_MLDSA_KEY_PUBLIC,
                },
                priv_keys: Some(AuthManifestPrivKeysConfig {
                    ecc_priv_key: OWNER_ECC_KEY_PRIVATE,
                    lms_priv_key: OWNER_LMS_KEY_PRIVATE,
                    mldsa_priv_key: OWNER_MLDSA_KEY_PRIVATE,
                }),
            });

        let gen_config: AuthManifestGeneratorConfig = AuthManifestGeneratorConfig {
            vendor_fw_key_info: Some(vendor_fw_key_info),
            vendor_man_key_info: Some(vendor_man_key_info),
            owner_fw_key_info,
            owner_man_key_info,
            image_metadata_list,
            version: 1,
            flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
            pqc_key_type: FwVerificationPqcKeyType::LMS,
            svn,
        };

        let gen = AuthManifestGenerator::new(Crypto::default());
        gen.generate(&gen_config).unwrap()
    }
}

#[derive(Debug, Clone)]
pub struct ImageCfg {
    pub path: PathBuf,
    pub load_addr: u64,
    pub staging_addr: u64,
    pub image_id: u32,
    pub exec_bit: u32,
    pub feature: String,
}
impl Default for ImageCfg {
    fn default() -> Self {
        ImageCfg {
            path: PathBuf::new(),
            load_addr: 0,
            staging_addr: 0,
            image_id: 0,
            // exec_bit must be >= 2 (bits 0 and 1 are reserved by Caliptra)
            exec_bit: 2,
            feature: String::new(),
        }
    }
}

impl FromStr for ImageCfg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(',').collect();
        if parts.len() != 6 {
            return Err(
                "Expected format: <path>,<load_addr>,<staging_addr>,<image_id>,<exec_bit>,<feature>".into(),
            );
        }

        let path = PathBuf::from(parts[0]);
        let load_addr = u64::from_str_radix(parts[1].trim_start_matches("0x"), 16)
            .map_err(|e: ParseIntError| e.to_string())?;
        let staging_addr = u64::from_str_radix(parts[2].trim_start_matches("0x"), 16)
            .map_err(|e: ParseIntError| e.to_string())?;
        let image_id = parts[3].parse::<u32>().map_err(|e| e.to_string())?;
        let exec_bit = parts[4].parse::<u32>().map_err(|e| e.to_string())?;
        let feature = parts[5].to_string();

        Ok(ImageCfg {
            path,
            load_addr,
            staging_addr,
            image_id,
            exec_bit,
            feature,
        })
    }
}
