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
use caliptra_image_gen::{
    from_hw_format, ImageGenerator, ImageGeneratorConfig, ImageGeneratorCrypto,
    ImageGeneratorExecutable, ImageGeneratorOwnerConfig,
};
use caliptra_image_types::{
    FwVerificationPqcKeyType, ImageBundle, ImageManifest, ImageRevision, IMAGE_MANIFEST_BYTE_SIZE,
};
use caliptra_mcu_flash_image::MCU_RT_IDENTIFIER;
use cargo_metadata::MetadataCommand;
use hex::ToHex;
use std::{num::ParseIntError, path::PathBuf, str::FromStr};
use zerocopy::{transmute, FromBytes, IntoBytes};

/// A wrapper for raw firmware bytes that implements ImageGeneratorExecutable.
/// Used to re-sign existing FW bundles without recompiling.
struct RawExecutable {
    version: u32,
    rev: ImageRevision,
    load_addr: u32,
    entry_point: u32,
    content: Vec<u8>,
}

impl ImageGeneratorExecutable for RawExecutable {
    fn version(&self) -> u32 {
        self.version
    }
    fn rev(&self) -> &ImageRevision {
        &self.rev
    }
    fn load_addr(&self) -> u32 {
        self.load_addr
    }
    fn entry_point(&self) -> u32 {
        self.entry_point
    }
    fn content(&self) -> &Vec<u8> {
        &self.content
    }
    fn size(&self) -> u32 {
        self.content.len() as u32
    }
}

/// Configuration for owner keys used in auth manifest (SoC manifest) signing.
/// This parallels `ImageGeneratorOwnerConfig` but uses the auth manifest key types.
#[derive(Clone)]
pub struct AuthManifestOwnerConfig {
    pub pub_keys: AuthManifestPubKeysConfig,
    pub priv_keys: Option<AuthManifestPrivKeysConfig>,
}

#[derive(Clone)]
pub struct CaliptraBuilder {
    fpga: bool,
    ocp_lock: bool,
    caliptra_rom: Option<PathBuf>,
    caliptra_firmware: Option<PathBuf>,
    soc_manifest: Option<PathBuf>,
    vendor_pk_hash: Option<String>,
    owner_pk_hash: Option<String>,
    mcu_firmware: Option<PathBuf>,
    soc_images: Option<Vec<ImageCfg>>,
    mcu_image_cfg: Option<ImageCfg>,
    soc_manifest_svn: Option<u32>,
    vendor: String,
    model: String,
    /// Optional custom owner configuration for re-signing FW bundles.
    /// If provided, the FW bundle will be re-signed with these owner keys.
    owner_config: Option<ImageGeneratorOwnerConfig>,
    /// Optional custom owner configuration for re-signing auth manifests (SoC manifest).
    /// If provided, the auth manifest will be signed with these owner keys.
    auth_manifest_owner_config: Option<AuthManifestOwnerConfig>,
    svn: Option<u16>,
    use_second_key: bool,
    /// `Some` → v2 SoC manifest w/ Vendor Ext 0x0001 anchor; `None` → legacy v1.
    vendor_cmd_auth_pk_hash: Option<[u8; 48]>,
}

impl CaliptraBuilder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(args: &crate::CaliptraBuildArgs) -> Self {
        Self {
            fpga: args.fpga,
            ocp_lock: args.ocp_lock,
            caliptra_rom: args.caliptra_rom.clone(),
            caliptra_firmware: args.caliptra_firmware.clone(),
            soc_manifest: args.soc_manifest.clone(),
            vendor_pk_hash: args.vendor_pk_hash.clone(),
            owner_pk_hash: None,
            mcu_firmware: args.mcu_firmware.clone(),
            soc_images: args.soc_images.clone(),
            mcu_image_cfg: args.mcu_image_cfg.clone(),
            soc_manifest_svn: args.soc_manifest_svn,
            vendor: args
                .vendor
                .clone()
                .unwrap_or_else(|| "ChipsAlliance".to_string()),
            model: args
                .model
                .clone()
                .unwrap_or_else(|| "Caliptra-SS".to_string()),
            owner_config: None,
            auth_manifest_owner_config: None,
            svn: args.svn,
            use_second_key: args.use_second_key,
            vendor_cmd_auth_pk_hash: None,
        }
    }

    pub fn from_args(args: &crate::CaliptraBuildArgs) -> Self {
        Self::new(args)
    }

    /// Emit the next SoC manifest as v2 with `pk_hash` as the vendor-command-auth anchor.
    pub fn with_vendor_cmd_auth_pk_hash(mut self, pk_hash: [u8; 48]) -> Self {
        self.vendor_cmd_auth_pk_hash = Some(pk_hash);
        self.soc_manifest = None; // force a rebuild with the new anchor
        self
    }

    /// Sets a custom owner configuration for re-signing the FW bundle.
    /// When set, the FW bundle will be re-signed with the specified owner keys.
    pub fn with_owner_config(mut self, owner_config: ImageGeneratorOwnerConfig) -> Self {
        self.owner_config = Some(owner_config);
        self
    }

    /// Sets a custom owner configuration for signing the auth manifest (SoC manifest).
    /// When set, the auth manifest will be signed with the specified owner keys.
    pub fn with_auth_manifest_owner_config(
        mut self,
        auth_manifest_owner_config: AuthManifestOwnerConfig,
    ) -> Self {
        self.auth_manifest_owner_config = Some(auth_manifest_owner_config);
        self
    }

    /// Returns the owner public key hash if available.
    pub fn get_owner_pk_hash(&self) -> Option<&str> {
        self.owner_pk_hash.as_deref()
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
        // First, get the base FW bundle (cached/prebuilt or compiled)
        let base_bundle_path = if let Some(caliptra_firmware) = self.caliptra_firmware.as_ref() {
            if !caliptra_firmware.exists() {
                bail!("Caliptra runtime bundle not found: {:?}", caliptra_firmware);
            }
            caliptra_firmware.clone()
        } else {
            let (path, vendor_pk_hash) = Self::compile_caliptra_fw_cached(
                self.fpga,
                self.ocp_lock,
                self.svn,
                self.use_second_key,
            )?;
            self.vendor_pk_hash = Some(vendor_pk_hash);
            self.caliptra_firmware = Some(path.clone());
            path
        };

        // If we have a custom owner_config, re-sign the bundle
        if let Some(owner_config) = self.owner_config.take() {
            let existing_bundle = std::fs::read(&base_bundle_path)?;
            let (new_bundle, vendor_hash, owner_hash) =
                Self::resign_fw_bundle(&existing_bundle, owner_config, self.fpga)?;

            // Write the re-signed bundle to a new path
            let path = target_dir().join("caliptra-fw-bundle-resigned.bin");
            let fw_bytes = new_bundle.to_bytes()?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, fw_bytes)?;

            self.vendor_pk_hash = Some(vendor_hash);
            self.owner_pk_hash = Some(owner_hash);
            self.caliptra_firmware = Some(path.clone());

            println!(
                "Re-signed Caliptra FW bundle with custom owner config, owner_pk_hash: {}",
                self.owner_pk_hash.as_ref().unwrap()
            );

            return Ok(path);
        }

        // No custom owner config - compute owner_pk_hash from existing bundle if needed
        if self.owner_pk_hash.is_none() {
            let bundle_bytes = std::fs::read(&base_bundle_path)?;
            let (manifest, _) = ImageManifest::ref_from_prefix(&bundle_bytes)
                .map_err(|_| anyhow::anyhow!("Failed to parse manifest"))?;
            self.owner_pk_hash = Some(Self::owner_pk_hash_str(manifest)?);
        }

        if self.vendor_pk_hash.is_none() {
            bail!("Vendor public key hash is required for active mode if Caliptra FW is passed as an argument");
        }

        Ok(base_bundle_path)
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
                metadata,
                self.soc_manifest_svn.unwrap_or(0),
                name,
                self.auth_manifest_owner_config.as_ref(),
                self.vendor_cmd_auth_pk_hash,
            )?;
            self.write_attestation_manifest_config(self.soc_images.as_deref().unwrap_or(&[]))?;
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
            // exec_bit must be >= 2 (bits 0 and 1 are reserved by Caliptra)
            let (staging_addr, load_addr) = if self.fpga {
                // FPGA: use external staging SRAM
                let staging_memory_map: u64 = 0xB00C_0000;
                let staging_memory_size: u64 = 0x0004_0000; // 256 KB
                let max_mcu_fw_size: u64 = 0x3EC00;
                let staging = staging_memory_map + staging_memory_size - max_mcu_fw_size;
                let load = caliptra_mcu_config_fpga::FPGA_MEMORY_MAP.sram_offset as u64;
                (staging, load)
            } else {
                // Emulator: staging uses Caliptra's External Test SRAM (0x8000_0000)
                // which is shared with the MCU's External SRAM (0xB00C_0000) via events.
                // The DMAMapping::cptra_axi_to_mcu_axi converts 0x8000_xxxx -> 0xB00C_xxxx
                // so the MCU's AXI CDMA writes to the same backing store.
                // Load address uses Caliptra's mcu_sram (SS_MCI_OFFSET + 0xC0_0000)
                // which is only accessed by Caliptra's DMA.
                const CPTRA_EXTERNAL_TEST_SRAM: u64 = 0x8000_0000;
                const MCI_BASE_AXI_ADDRESS: u64 = 0xA800_0000;
                const MCU_SRAM_OFFSET: u64 = 0xC0_0000;
                let staging = CPTRA_EXTERNAL_TEST_SRAM;
                let load = MCI_BASE_AXI_ADDRESS + MCU_SRAM_OFFSET; // 0xA8C0_0000
                (staging, load)
            };
            ImageCfg {
                image_id: MCU_RT_IDENTIFIER,
                component_id: MCU_RT_IDENTIFIER,
                exec_bit: 2,
                staging_addr,
                load_addr,
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
            component_id: cfg.component_id,
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
            component_id: image_cfg.component_id,
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
        owner_config: Option<&AuthManifestOwnerConfig>,
        vendor_cmd_auth_pk_hash: Option<[u8; 48]>,
    ) -> Result<PathBuf> {
        let manifest = Self::create_auth_manifest_with_metadata_and_owner(
            metadata,
            svn,
            owner_config,
            vendor_cmd_auth_pk_hash,
        );

        let path = name
            .map(PathBuf::from)
            .unwrap_or(target_dir().join("soc-manifest"));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, manifest.as_bytes())?;
        Ok(path)
    }

    pub fn write_attestation_manifest_config(&self, soc_images: &[ImageCfg]) -> Result<()> {
        crate::attestation_manifest::write_config(
            &self.vendor,
            &self.model,
            soc_images,
            "CaliptraBuilder::write_attestation_manifest_config",
            "Generated",
        )
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

    fn compile_caliptra_fw_cached(
        fpga: bool,
        ocp_lock: bool,
        svn: Option<u16>,
        use_second_key: bool,
    ) -> Result<(PathBuf, String)> {
        let platform = if fpga { "fpga" } else { "emulator" };
        let ocp_lock_suffix = if ocp_lock { "-ocp-lock" } else { "" };
        if let Some(version) = Self::caliptra_version() {
            let svn_or_default = svn.unwrap_or_default();
            let key_str = if use_second_key { "key2" } else { "key1" };
            let path = target_dir().join(format!(
                "caliptra-fw-bundle-{}-{}{}-{}-{}.bin",
                version, platform, ocp_lock_suffix, svn_or_default, key_str
            ));
            if path.exists() {
                println!("Using cached Caliptra FW bundle at {:?}", path);
                return Self::parse_fw_bundle(path);
            }
            println!(
                "Caliptra FW bundle version {} not found in cache, compiling...",
                version
            );
            let compiled_fw_bundle =
                Self::compile_caliptra_fw_uncached(fpga, ocp_lock, svn, use_second_key)?.0;
            // std::fs::copy truncates the file to 0 bytes if both paths are the same
            if compiled_fw_bundle != path {
                std::fs::copy(compiled_fw_bundle, &path)?;
            }
            Self::parse_fw_bundle(path)
        } else {
            println!("Caliptra version not found so cannot use cached FW bundle");
            Self::compile_caliptra_fw_uncached(fpga, ocp_lock, svn, use_second_key)
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

    /// Computes the SHA384 hash of the owner public keys from the firmware bundle manifest.
    pub fn owner_pk_hash(manifest: &ImageManifest) -> Result<[u8; 48]> {
        let crypto = Crypto::default();
        Ok(from_hw_format(&crypto.sha384_digest(
            manifest.preamble.owner_pub_keys.as_bytes(),
        )?))
    }

    fn owner_pk_hash_str(manifest: &ImageManifest) -> Result<String> {
        Ok(Self::owner_pk_hash(manifest)?.encode_hex())
    }

    /// Re-signs an existing FW bundle with a custom owner configuration.
    /// This extracts the FMC and runtime binaries from the existing bundle
    /// and generates a new bundle with the specified owner keys.
    ///
    /// # Arguments
    /// * `existing_bundle` - Path to the existing FW bundle to re-sign
    /// * `owner_config` - Custom owner configuration with keys for signing
    /// * `fpga` - Whether this is for FPGA or emulator
    ///
    /// # Returns
    /// A tuple of (new bundle, vendor_pk_hash, owner_pk_hash)
    fn resign_fw_bundle(
        existing_bundle: &[u8],
        owner_config: ImageGeneratorOwnerConfig,
        _fpga: bool,
    ) -> Result<(ImageBundle, String, String)> {
        // Parse the existing manifest
        let manifest_size = IMAGE_MANIFEST_BYTE_SIZE;
        if existing_bundle.len() < manifest_size {
            bail!("FW bundle too small to contain manifest");
        }

        let manifest: ImageManifest = {
            let bytes: [u8; IMAGE_MANIFEST_BYTE_SIZE] = existing_bundle[..manifest_size]
                .try_into()
                .map_err(|_| anyhow::anyhow!("Failed to read manifest bytes"))?;
            transmute!(bytes)
        };

        // Extract FMC and runtime from the bundle
        let fmc_offset = manifest.fmc.offset as usize;
        let fmc_size = manifest.fmc.size as usize;
        let rt_offset = manifest.runtime.offset as usize;
        let rt_size = manifest.runtime.size as usize;

        if fmc_offset + fmc_size > existing_bundle.len()
            || rt_offset + rt_size > existing_bundle.len()
        {
            bail!("FW bundle truncated - FMC or runtime extends beyond bundle size");
        }

        let fmc_content = existing_bundle[fmc_offset..fmc_offset + fmc_size].to_vec();
        let rt_content = existing_bundle[rt_offset..rt_offset + rt_size].to_vec();

        // Create RawExecutable wrappers
        let fmc_exe = RawExecutable {
            version: manifest.fmc.version,
            rev: manifest.fmc.revision,
            load_addr: manifest.fmc.load_addr,
            entry_point: manifest.fmc.entry_point,
            content: fmc_content,
        };

        let rt_exe = RawExecutable {
            version: manifest.runtime.version,
            rev: manifest.runtime.revision,
            load_addr: manifest.runtime.load_addr,
            entry_point: manifest.runtime.entry_point,
            content: rt_content,
        };

        // Generate new bundle with custom owner config
        let gen = ImageGenerator::new(Crypto::default());
        let new_bundle = gen.generate(&ImageGeneratorConfig {
            fmc: fmc_exe,
            runtime: rt_exe,
            fw_svn: manifest.header.svn,
            vendor_config: caliptra_image_fake_keys::VENDOR_CONFIG_KEY_0,
            owner_config: Some(owner_config),
            pqc_key_type: FwVerificationPqcKeyType::LMS,
        })?;

        let vendor_hash = Self::vendor_pk_hash_str(new_bundle.manifest)?;
        let owner_hash = Self::owner_pk_hash_str(&new_bundle.manifest)?;

        Ok((new_bundle, vendor_hash, owner_hash))
    }

    fn compile_caliptra_fw_uncached(
        fpga: bool,
        ocp_lock: bool,
        svn: Option<u16>,
        use_second_key: bool,
    ) -> Result<(PathBuf, String)> {
        let opts = caliptra_builder::ImageOptions {
            pqc_key_type: FwVerificationPqcKeyType::LMS,
            fw_svn: svn.unwrap_or(0) as u32,
            vendor_config: if use_second_key {
                caliptra_image_fake_keys::VENDOR_CONFIG_KEY_1
            } else {
                caliptra_image_fake_keys::VENDOR_CONFIG_KEY_0
            },
            ..Default::default()
        };

        let bundle = if fpga {
            let app = if ocp_lock {
                &caliptra_builder::firmware::APP_WITH_UART_OCP_LOCK_FPGA
            } else {
                &caliptra_builder::firmware::APP_WITH_UART_FPGA
            };
            caliptra_builder::build_and_sign_image(
                &caliptra_builder::firmware::FMC_FPGA_WITH_UART,
                app,
                opts,
            )?
        } else {
            let app = if ocp_lock {
                &caliptra_builder::firmware::APP_WITH_UART_OCP_LOCK
            } else {
                &caliptra_builder::firmware::APP_WITH_UART
            };
            caliptra_builder::build_and_sign_image(
                &caliptra_builder::firmware::FMC_WITH_UART,
                app,
                opts,
            )?
        };
        let fw_bytes = bundle.to_bytes()?;
        let platform = if fpga { "fpga" } else { "emulator" };
        let ocp_lock_suffix = if ocp_lock { "-ocp-lock" } else { "" };
        let version = Self::caliptra_version().unwrap_or("no_version".to_string());
        let svn_or_default = svn.unwrap_or_default();
        let key_str = if use_second_key { "key2" } else { "key1" };
        let path = target_dir().join(format!(
            "caliptra-fw-bundle-{}-{}{}-{}-{}.bin",
            version, platform, ocp_lock_suffix, svn_or_default, key_str
        ));
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
            vendor_cmd_auth_pk_hash: None,
        };

        let gen = AuthManifestGenerator::new(Crypto::default());
        gen.generate(&gen_config).unwrap()
    }

    /// Creates an auth manifest with optional custom owner keys.
    /// If owner_config is None, uses default owner keys.
    fn create_auth_manifest_with_metadata_and_owner(
        image_metadata_list: Vec<AuthManifestImageMetadata>,
        svn: u32,
        owner_config: Option<&AuthManifestOwnerConfig>,
        vendor_cmd_auth_pk_hash: Option<[u8; 48]>,
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

        // Use custom owner keys if provided, otherwise use defaults
        let (owner_fw_key_info, owner_man_key_info) = if let Some(cfg) = owner_config {
            let key_config = AuthManifestGeneratorKeyConfig {
                pub_keys: cfg.pub_keys,
                priv_keys: cfg.priv_keys,
            };
            (Some(key_config.clone()), Some(key_config))
        } else {
            let default_owner_key = AuthManifestGeneratorKeyConfig {
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
            };
            (Some(default_owner_key.clone()), Some(default_owner_key))
        };

        let gen_config: AuthManifestGeneratorConfig = AuthManifestGeneratorConfig {
            vendor_fw_key_info: Some(vendor_fw_key_info),
            vendor_man_key_info: Some(vendor_man_key_info),
            owner_fw_key_info,
            owner_man_key_info,
            image_metadata_list,
            version: if vendor_cmd_auth_pk_hash.is_some() {
                2
            } else {
                1
            },
            flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
            pqc_key_type: FwVerificationPqcKeyType::LMS,
            svn,
            vendor_cmd_auth_pk_hash,
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
    pub component_id: u32,
    pub is_tcb: bool,
    pub is_ak_target: bool,
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
            component_id: 0,
            is_tcb: false,
            is_ak_target: false,
            feature: String::new(),
        }
    }
}

impl FromStr for ImageCfg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(',').collect();
        if !(7..=9).contains(&parts.len()) {
            return Err(
                "Expected format: <path>,<load_addr>,<staging_addr>,<image_id>,<exec_bit>,<component_id>,<feature>[,<is_tcb>[,<is_ak_target>]]".into(),
            );
        }

        let path = PathBuf::from(parts[0]);
        let load_addr = u64::from_str_radix(parts[1].trim_start_matches("0x"), 16)
            .map_err(|e: ParseIntError| e.to_string())?;
        let staging_addr = u64::from_str_radix(parts[2].trim_start_matches("0x"), 16)
            .map_err(|e: ParseIntError| e.to_string())?;
        let image_id = parts[3].parse::<u32>().map_err(|e| e.to_string())?;
        let exec_bit = parts[4].parse::<u32>().map_err(|e| e.to_string())?;
        let component_id = parts[5].parse::<u32>().map_err(|e| e.to_string())?;
        let feature = parts[6].to_string();
        let is_tcb = if let Some(is_tcb) = parts.get(7) {
            is_tcb.parse::<bool>().map_err(|e| e.to_string())?
        } else {
            false
        };
        let is_ak_target = if let Some(is_ak_target) = parts.get(8) {
            is_ak_target.parse::<bool>().map_err(|e| e.to_string())?
        } else {
            false
        };

        Ok(ImageCfg {
            path,
            load_addr,
            staging_addr,
            image_id,
            exec_bit,
            component_id,
            is_tcb,
            is_ak_target,
            feature,
        })
    }
}
