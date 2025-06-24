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
use hex::ToHex;
use std::{num::ParseIntError, path::PathBuf, str::FromStr};
use zerocopy::{transmute, IntoBytes};

pub struct CaliptraBuilder {
    active_mode: bool,
    fpga: bool,
    caliptra_rom: Option<PathBuf>,
    caliptra_firmware: Option<PathBuf>,
    soc_manifest: Option<PathBuf>,
    vendor_pk_hash: Option<String>,
    mcu_firmware: Option<PathBuf>,
    soc_images: Option<Vec<SocImage>>,
}

impl CaliptraBuilder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        active_mode: bool,
        fpga: bool,
        caliptra_rom: Option<PathBuf>,
        caliptra_firmware: Option<PathBuf>,
        soc_manifest: Option<PathBuf>,
        vendor_pk_hash: Option<String>,
        mcu_firmware: Option<PathBuf>,
        soc_images: Option<Vec<SocImage>>,
    ) -> Self {
        Self {
            active_mode,
            fpga,
            caliptra_rom,
            caliptra_firmware,
            soc_manifest,
            vendor_pk_hash,
            mcu_firmware,
            soc_images,
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
            if self.active_mode && self.vendor_pk_hash.is_none() {
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
                let soc_metadata = Self::get_soc_manifest_metadata(
                    &soc_image.path,
                    soc_image.image_id,
                    Addr64 {
                        lo: soc_image.load_addr as u32,
                        hi: (soc_image.load_addr >> 32) as u32,
                    },
                )?;
                metadata.push(soc_metadata);
            }
        }
        Ok(metadata)
    }

    pub fn get_soc_manifest(&mut self) -> Result<PathBuf> {
        if self.soc_manifest.is_none() {
            let _ = self.get_caliptra_fw()?;
        }
        // check if we wrote it already when compiling the firmware
        if self.soc_manifest.is_none() {
            if self.mcu_firmware.is_none() {
                bail!("MCU firmware is required to build SoC manifest");
            }
            let mcu_fw_metadata =
                Self::get_mcu_manifest_metadata(self.mcu_firmware.as_ref().unwrap())?;
            let soc_images_metadata = self.get_soc_images_metadata()?;
            let mut metadata = vec![mcu_fw_metadata];
            metadata.extend(soc_images_metadata);

            let path = Self::write_soc_manifest(metadata)?;
            self.soc_manifest = Some(path);
        }
        Ok(self.soc_manifest.clone().unwrap())
    }

    pub fn get_vendor_pk_hash(&mut self) -> Result<&str> {
        if self.vendor_pk_hash.is_none() {
            let _ = self.get_caliptra_fw()?;
        }
        Ok(self.vendor_pk_hash.as_ref().unwrap())
    }

    fn get_mcu_manifest_metadata(runtime_path: &PathBuf) -> Result<AuthManifestImageMetadata> {
        const IMAGE_SOURCE_IN_REQUEST: u32 = 1;
        let data = std::fs::read(runtime_path).unwrap();
        let mut flags = ImageMetadataFlags(0);
        flags.set_image_source(IMAGE_SOURCE_IN_REQUEST);
        let crypto = Crypto::default();
        let digest = from_hw_format(&crypto.sha384_digest(&data)?);
        let d: String = digest.clone().encode_hex();
        println!("MCU len {} digest: {}", data.len(), d);

        Ok(AuthManifestImageMetadata {
            fw_id: 2,
            flags: flags.0,
            digest,
            ..Default::default()
        })
    }

    fn get_soc_manifest_metadata(
        runtime_path: &PathBuf,
        fw_id: u32,
        load_address: Addr64,
    ) -> Result<AuthManifestImageMetadata> {
        const IMAGE_SOURCE_LOAD_ADDRESS: u32 = 2;
        let data = std::fs::read(runtime_path).unwrap();
        let mut flags = ImageMetadataFlags(0);
        flags.set_ignore_auth_check(false);
        flags.set_image_source(IMAGE_SOURCE_LOAD_ADDRESS);
        let crypto = Crypto::default();
        let digest = from_hw_format(&crypto.sha384_digest(&data)?);

        Ok(AuthManifestImageMetadata {
            fw_id,
            flags: flags.0,
            digest,
            image_load_address: load_address,
            ..Default::default()
        })
    }

    fn write_soc_manifest(metadata: Vec<AuthManifestImageMetadata>) -> Result<PathBuf> {
        let manifest = Self::create_auth_manifest_with_metadata(metadata);

        let path = target_dir().join("soc-manifest");
        std::fs::write(&path, manifest.as_bytes())?;
        Ok(path)
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
        if let Some(version) = Self::caliptra_version() {
            let path = target_dir().join(format!("caliptra-rom-{}.bin", version));
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
            caliptra_builder::build_firmware_rom(&caliptra_builder::firmware::ROM_FPGA_WITH_UART)?
        } else {
            caliptra_builder::rom_for_fw_integration_tests()?.to_vec()
        };
        let path = target_dir().join("caliptra-rom.bin");
        std::fs::write(&path, rom_bytes)?;
        Ok(path)
    }

    fn compile_caliptra_fw_cached(fpga: bool) -> Result<(PathBuf, String)> {
        if let Some(version) = Self::caliptra_version() {
            let path = target_dir().join(format!("caliptra-fw-bundle-{}.bin", version));
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
        Ok((path, Self::vendor_pk_hash(manifest)?))
    }

    fn vendor_pk_hash(manifest: ImageManifest) -> Result<String> {
        let crypto = Crypto::default();
        let x = from_hw_format(
            &crypto.sha384_digest(manifest.preamble.vendor_pub_key_info.as_bytes())?,
        )
        .encode_hex();
        Ok(x)
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
        Ok((path, Self::vendor_pk_hash(bundle.manifest)?))
    }

    pub fn create_auth_manifest_with_metadata(
        image_metadata_list: Vec<AuthManifestImageMetadata>,
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
            vendor_fw_key_info,
            vendor_man_key_info,
            owner_fw_key_info,
            owner_man_key_info,
            image_metadata_list,
            version: 1,
            flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
            pqc_key_type: FwVerificationPqcKeyType::LMS,
        };

        let gen = AuthManifestGenerator::new(Crypto::default());
        gen.generate(&gen_config).unwrap()
    }
}

#[derive(Debug, Clone)]
pub struct SocImage {
    pub path: PathBuf,
    pub load_addr: u64,
    pub image_id: u32,
}
impl FromStr for SocImage {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(',').collect();
        if parts.len() != 3 {
            return Err("Expected format: <path>,<load_addr>,<image_id>".into());
        }

        let path = PathBuf::from(parts[0]);
        let load_addr = u64::from_str_radix(parts[1].trim_start_matches("0x"), 16)
            .map_err(|e: ParseIntError| e.to_string())?;
        let image_id = parts[2].parse::<u32>().map_err(|e| e.to_string())?;

        Ok(SocImage {
            path,
            load_addr,
            image_id,
        })
    }
}
