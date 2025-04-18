// Licensed under the Apache-2.0 license

//! Wrappers around the Caliptra builder library to make it easier to build
//! the ROM, firwmare, and SoC manifest.

use crate::PROJECT_ROOT;
use anyhow::{bail, Result};
use caliptra_auth_man_gen::{
    AuthManifestGenerator, AuthManifestGeneratorConfig, AuthManifestGeneratorKeyConfig,
};
use caliptra_auth_man_types::{
    AuthManifestFlags, AuthManifestImageMetadata, AuthManifestPrivKeys, AuthManifestPubKeys,
    AuthorizationManifest, ImageMetadataFlags,
};
use caliptra_image_crypto::RustCrypto as Crypto;
use caliptra_image_fake_keys::*;
use caliptra_image_gen::{from_hw_format, ImageGeneratorCrypto};
use caliptra_image_types::FwVerificationPqcKeyType;
use hex::ToHex;
use std::path::PathBuf;
use zerocopy::IntoBytes;

pub struct CaliptraBuilder {
    active_mode: bool,
    caliptra_rom: Option<PathBuf>,
    caliptra_firmware: Option<PathBuf>,
    soc_manifest: Option<PathBuf>,
    vendor_pk_hash: Option<String>,
    mcu_firmware: Option<PathBuf>,
}

impl CaliptraBuilder {
    pub fn new(
        active_mode: bool,
        caliptra_rom: Option<PathBuf>,
        caliptra_firmware: Option<PathBuf>,
        soc_manifest: Option<PathBuf>,
        vendor_pk_hash: Option<String>,
        mcu_firmware: Option<PathBuf>,
    ) -> Self {
        Self {
            active_mode,
            caliptra_rom,
            caliptra_firmware,
            soc_manifest,
            vendor_pk_hash,
            mcu_firmware,
        }
    }

    pub fn get_caliptra_rom(&self) -> Result<PathBuf> {
        if let Some(caliptra_rom) = &self.caliptra_rom {
            if !caliptra_rom.exists() {
                bail!("Caliptra ROM file not found: {:?}", caliptra_rom);
            }
            Ok(caliptra_rom.clone())
        } else {
            Self::compile_caliptra_rom()
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
            let (path, vendor_pk_hash) = Self::compile_caliptra_fw()?;
            self.vendor_pk_hash = Some(vendor_pk_hash);
            self.caliptra_firmware = Some(path);
        }
        Ok(self.caliptra_firmware.clone().unwrap())
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
            let path = Self::write_soc_manifest(self.mcu_firmware.as_ref().unwrap())?;
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

    fn write_soc_manifest(runtime_path: &PathBuf) -> Result<PathBuf> {
        const IMAGE_SOURCE_IN_REQUEST: u32 = 1;
        let data = std::fs::read(runtime_path).unwrap();
        let mut flags = ImageMetadataFlags(0);
        flags.set_image_source(IMAGE_SOURCE_IN_REQUEST);
        let crypto = Crypto::default();
        let digest = from_hw_format(&crypto.sha384_digest(&data)?);
        let metadata = vec![AuthManifestImageMetadata {
            fw_id: 2,
            flags: flags.0,
            digest,
        }];
        let manifest = Self::create_auth_manifest_with_metadata(metadata);

        let path = PROJECT_ROOT.join("target").join("soc-manifest");
        std::fs::write(&path, manifest.as_bytes())?;
        Ok(path)
    }

    fn compile_caliptra_rom() -> Result<PathBuf> {
        let rom_bytes = caliptra_builder::rom_for_fw_integration_tests()?;
        let path = PROJECT_ROOT.join("target").join("caliptra-rom.bin");
        std::fs::write(&path, rom_bytes)?;
        Ok(path)
    }

    fn compile_caliptra_fw() -> Result<(PathBuf, String)> {
        let opts = caliptra_builder::ImageOptions {
            pqc_key_type: FwVerificationPqcKeyType::LMS,
            ..Default::default()
        };
        let bundle = caliptra_builder::build_and_sign_image(
            &caliptra_builder::firmware::FMC_WITH_UART,
            &caliptra_builder::firmware::APP_WITH_UART,
            opts,
        )?;
        let crypto = Crypto::default();
        let vendor_pk_hash = from_hw_format(
            &crypto.sha384_digest(bundle.manifest.preamble.vendor_pub_key_info.as_bytes())?,
        )
        .encode_hex();
        let fw_bytes = bundle.to_bytes()?;
        let path = PROJECT_ROOT.join("target").join("caliptra-fw-bundle.bin");
        std::fs::write(&path, fw_bytes)?;
        Ok((path, vendor_pk_hash))
    }

    pub fn create_auth_manifest_with_metadata(
        image_metadata_list: Vec<AuthManifestImageMetadata>,
    ) -> AuthorizationManifest {
        let vendor_fw_key_info: AuthManifestGeneratorKeyConfig = AuthManifestGeneratorKeyConfig {
            pub_keys: AuthManifestPubKeys {
                ecc_pub_key: VENDOR_ECC_KEY_0_PUBLIC,
                lms_pub_key: VENDOR_LMS_KEY_0_PUBLIC,
            },
            priv_keys: Some(AuthManifestPrivKeys {
                ecc_priv_key: VENDOR_ECC_KEY_0_PRIVATE,
                lms_priv_key: VENDOR_LMS_KEY_0_PRIVATE,
            }),
        };

        let vendor_man_key_info: AuthManifestGeneratorKeyConfig = AuthManifestGeneratorKeyConfig {
            pub_keys: AuthManifestPubKeys {
                ecc_pub_key: VENDOR_ECC_KEY_1_PUBLIC,
                lms_pub_key: VENDOR_LMS_KEY_1_PUBLIC,
            },
            priv_keys: Some(AuthManifestPrivKeys {
                ecc_priv_key: VENDOR_ECC_KEY_1_PRIVATE,
                lms_priv_key: VENDOR_LMS_KEY_1_PRIVATE,
            }),
        };

        let owner_fw_key_info: Option<AuthManifestGeneratorKeyConfig> =
            Some(AuthManifestGeneratorKeyConfig {
                pub_keys: AuthManifestPubKeys {
                    ecc_pub_key: OWNER_ECC_KEY_PUBLIC,
                    lms_pub_key: OWNER_LMS_KEY_PUBLIC,
                },
                priv_keys: Some(AuthManifestPrivKeys {
                    ecc_priv_key: OWNER_ECC_KEY_PRIVATE,
                    lms_priv_key: OWNER_LMS_KEY_PRIVATE,
                }),
            });

        let owner_man_key_info: Option<AuthManifestGeneratorKeyConfig> =
            Some(AuthManifestGeneratorKeyConfig {
                pub_keys: AuthManifestPubKeys {
                    ecc_pub_key: OWNER_ECC_KEY_PUBLIC,
                    lms_pub_key: OWNER_LMS_KEY_PUBLIC,
                },
                priv_keys: Some(AuthManifestPrivKeys {
                    ecc_priv_key: OWNER_ECC_KEY_PRIVATE,
                    lms_priv_key: OWNER_LMS_KEY_PRIVATE,
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
        };

        let gen = AuthManifestGenerator::new(Crypto::default());
        gen.generate(&gen_config).unwrap()
    }
}
