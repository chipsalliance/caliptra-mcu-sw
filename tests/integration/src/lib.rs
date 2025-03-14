// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
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
    use mcu_builder::TARGET;
    use std::process::ExitStatus;
    use std::sync::atomic::AtomicU32;
    use std::sync::Mutex;
    use std::{
        path::{Path, PathBuf},
        process::Command,
        sync::LazyLock,
    };
    use zerocopy::IntoBytes;

    static PROJECT_ROOT: LazyLock<PathBuf> = LazyLock::new(|| {
        Path::new(&env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf()
    });

    fn target_binary(name: &str) -> PathBuf {
        PROJECT_ROOT
            .join("target")
            .join(TARGET)
            .join("release")
            .join(name)
    }

    // only build the ROM once
    static ROM: LazyLock<PathBuf> = LazyLock::new(compile_rom);

    static TEST_LOCK: LazyLock<Mutex<AtomicU32>> = LazyLock::new(|| Mutex::new(AtomicU32::new(0)));

    fn compile_rom() -> PathBuf {
        mcu_builder::rom_build().expect("ROM build failed");
        let output = target_binary("rom.bin");
        assert!(output.exists());
        output
    }

    fn compile_runtime(feature: &str) -> PathBuf {
        let output = target_binary(&format!("runtime-{}.bin", feature));
        let output_name = format!("{}", output.display());
        mcu_builder::runtime_build_with_apps(&[feature], Some(&output_name))
            .expect("Runtime build failed");
        assert!(output.exists());
        output
    }

    fn write_soc_manifest(runtime_path: &PathBuf) -> PathBuf {
        const IMAGE_SOURCE_IN_REQUEST: u32 = 1;
        let data = std::fs::read(runtime_path).unwrap();
        let mut flags = ImageMetadataFlags(0);
        flags.set_image_source(IMAGE_SOURCE_IN_REQUEST);
        let crypto = Crypto::default();
        let digest = from_hw_format(&crypto.sha384_digest(&data).unwrap());
        let metadata = vec![AuthManifestImageMetadata {
            fw_id: 0,
            flags: flags.0,
            digest,
        }];
        let manifest = create_auth_manifest_with_metadata(metadata);

        let path = PROJECT_ROOT.join("target").join("soc-manifest");
        std::fs::write(&path, manifest.as_bytes()).unwrap();
        path
    }

    fn compile_caliptra_rom() -> PathBuf {
        let rom_bytes = caliptra_builder::rom_for_fw_integration_tests().unwrap();
        let path = PROJECT_ROOT.join("target").join("caliptra-rom.bin");
        std::fs::write(&path, rom_bytes).unwrap();
        path
    }

    fn compile_caliptra_fw() -> (PathBuf, String) {
        let opts = caliptra_builder::ImageOptions {
            pqc_key_type: FwVerificationPqcKeyType::LMS,
            ..Default::default()
        };
        let bundle = caliptra_builder::build_and_sign_image(
            &caliptra_builder::firmware::FMC_WITH_UART,
            &caliptra_builder::firmware::APP_WITH_UART,
            opts,
        )
        .unwrap();
        let crypto = Crypto::default();
        let vendor_pk_hash = from_hw_format(
            &crypto
                .sha384_digest(bundle.manifest.preamble.vendor_pub_key_info.as_bytes())
                .unwrap(),
        )
        .encode_hex();
        let fw_bytes = bundle.to_bytes().unwrap();
        let path = PROJECT_ROOT.join("target").join("caliptra-fw-bundle.bin");
        std::fs::write(&path, fw_bytes).unwrap();
        (path, vendor_pk_hash)
    }

    fn run_runtime(
        feature: &str,
        rom_path: PathBuf,
        runtime_path: PathBuf,
        i3c_port: String,
        soc_manifest: Option<PathBuf>,
        caliptra_rom: Option<PathBuf>,
        caliptra_fw: Option<PathBuf>,
        vendor_pk_hash: Option<String>,
        active_mode: bool,
    ) -> ExitStatus {
        let mut cargo_run_args = vec![
            "run",
            "-p",
            "emulator",
            "--release",
            "--features",
            feature,
            "--",
            "--rom",
            rom_path.to_str().unwrap(),
            "--firmware",
            runtime_path.to_str().unwrap(),
            "--i3c-port",
            i3c_port.as_str(),
        ];
        if active_mode {
            cargo_run_args.push("--active-mode");
        }
        if let Some(soc_manifest) = soc_manifest.as_ref() {
            cargo_run_args.push("--soc-manifest");
            cargo_run_args.push(soc_manifest.to_str().unwrap());
        }
        if let Some(caliptra_rom) = caliptra_rom.as_ref() {
            cargo_run_args.push("--caliptra");
            cargo_run_args.push("--caliptra-rom");
            cargo_run_args.push(caliptra_rom.to_str().unwrap());
        }
        if let Some(caliptra_fw) = caliptra_fw.as_ref() {
            cargo_run_args.push("--caliptra-firmware");
            cargo_run_args.push(caliptra_fw.to_str().unwrap());
        }
        if let Some(vendor_pk_hash) = vendor_pk_hash.as_ref() {
            cargo_run_args.push("--vendor-pk-hash");
            cargo_run_args.push(vendor_pk_hash.as_str());
        }
        println!("Running test firmware {}", feature.replace("_", "-"));
        let mut cmd = Command::new("cargo");
        let cmd = cmd.args(&cargo_run_args).current_dir(&*PROJECT_ROOT);
        cmd.status().unwrap()
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

    #[macro_export]
    macro_rules! run_test {
        ($test:ident) => {
            #[test]
            fn $test() {
                let lock = TEST_LOCK.lock().unwrap();
                lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                println!("Compiling test firmware {}", stringify!($test));
                let feature = stringify!($test).replace("_", "-");
                let test_runtime = compile_runtime(&feature);
                let i3c_port = "65534".to_string();
                let test = run_runtime(
                    &feature,
                    ROM.to_path_buf(),
                    test_runtime,
                    i3c_port,
                    None,
                    None,
                    None,
                    None,
                    false,
                );
                assert_eq!(0, test.code().unwrap_or_default());

                // force the compiler to keep the lock
                lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        };
    }

    // To add a test:
    // * add the test name here
    // * add the feature to the emulator and use it to implement any behavior needed
    // * add the feature to the runtime and use it in board.rs at the end of the main function to call your test
    // These use underscores but will be converted to dashes in the feature flags
    run_test!(test_i3c_simple);
    run_test!(test_i3c_constant_writes);
    run_test!(test_flash_ctrl_init);
    run_test!(test_flash_ctrl_read_write_page);
    run_test!(test_flash_ctrl_erase_page);
    run_test!(test_flash_storage_read_write);
    run_test!(test_flash_storage_erase);
    run_test!(test_flash_usermode);
    run_test!(test_mctp_ctrl_cmds);
    run_test!(test_mctp_capsule_loopback);
    run_test!(test_mctp_user_loopback);
    run_test!(test_pldm_request_response);
    run_test!(test_spdm_validator);
    run_test!(test_pldm_discovery);

    /// This tests a full active mode boot run through with Caliptra, including
    /// loading MCU's firmware from Caliptra over the recovery interface.
    #[test]
    fn test_active_mode_recovery_with_caliptra() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let feature = "test-exit-immediately".to_string();
        println!("Compiling test firmware {}", &feature);
        let test_runtime = compile_runtime(&feature);
        let i3c_port = "65534".to_string();
        let soc_manifest = write_soc_manifest(&test_runtime);
        let caliptra_rom = compile_caliptra_rom();
        let (caliptra_fw, vendor_pk_hash) = compile_caliptra_fw();
        let test = run_runtime(
            &feature,
            ROM.to_path_buf(),
            test_runtime,
            i3c_port,
            Some(soc_manifest),
            Some(caliptra_rom),
            Some(caliptra_fw),
            Some(vendor_pk_hash),
            true,
        );
        assert_eq!(0, test.code().unwrap_or_default());

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
