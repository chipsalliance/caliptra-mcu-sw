// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use chrono::{TimeZone, Utc};
    use mcu_builder::{CaliptraBuilder, SocImage, TARGET};
    use pldm_fw_pkg::manifest::{
        ComponentImageInformation, Descriptor, DescriptorType, FirmwareDeviceIdRecord,
        PackageHeaderInformation, StringType,
    };
    use pldm_fw_pkg::FirmwareManifest;
    use std::process::ExitStatus;
    use std::sync::atomic::AtomicU32;
    use std::sync::Mutex;
    use std::{
        path::{Path, PathBuf},
        process::Command,
        sync::LazyLock,
    };

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

    fn compile_runtime(feature: &str, example_app: bool) -> PathBuf {
        let output = target_binary(&format!("runtime-{}.bin", feature));
        let output_name = format!("{}", output.display());
        mcu_builder::runtime_build_with_apps(&[feature], Some(&output_name), example_app)
            .expect("Runtime build failed");
        assert!(output.exists());
        output
    }

    #[allow(clippy::too_many_arguments)]
    fn run_runtime(
        feature: &str,
        rom_path: PathBuf,
        runtime_path: PathBuf,
        i3c_port: String,
        active_mode: bool,
        soc_images: Option<Vec<SocImage>>,
        streaming_boot_package_path: Option<PathBuf>,
        flash_image_path: Option<PathBuf>,
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

        let mut caliptra_builder = CaliptraBuilder::new(
            true,
            None,
            None,
            None,
            None,
            Some(runtime_path.clone()),
            soc_images,
        );

        if active_mode {
            cargo_run_args.push("--active-mode");
            let caliptra_rom = caliptra_builder
                .get_caliptra_rom()
                .expect("Failed to build Caliptra ROM");
            cargo_run_args.push("--caliptra");
            cargo_run_args.push("--caliptra-rom");
            cargo_run_args.push(caliptra_rom.to_str().unwrap());
            let caliptra_fw = caliptra_builder
                .get_caliptra_fw()
                .expect("Failed to build Caliptra firmware");
            cargo_run_args.push("--caliptra-firmware");
            cargo_run_args.push(caliptra_fw.to_str().unwrap());
            let soc_manifest = caliptra_builder
                .get_soc_manifest()
                .expect("Failed to build SoC manifest");
            cargo_run_args.push("--soc-manifest");
            cargo_run_args.push(soc_manifest.to_str().unwrap());
            let vendor_pk_hash = caliptra_builder
                .get_vendor_pk_hash()
                .expect("Failed to get vendor PK hash");
            cargo_run_args.push("--vendor-pk-hash");
            cargo_run_args.push(vendor_pk_hash);

            let streaming_boot_path;
            if let Some(path) = streaming_boot_package_path {
                cargo_run_args.push("--streaming-boot");
                streaming_boot_path = path;
                cargo_run_args.push(streaming_boot_path.to_str().unwrap());
            }

            let flash_image;
            if let Some(path) = flash_image_path {
                cargo_run_args.push("--flash-image");
                flash_image = path;
                cargo_run_args.push(flash_image.to_str().unwrap());
            }

            println!("Running test firmware {}", feature.replace("_", "-"));
            let mut cmd = Command::new("cargo");
            let cmd = cmd.args(&cargo_run_args).current_dir(&*PROJECT_ROOT);
            cmd.status().unwrap()
        } else {
            println!("Running test firmware {}", feature.replace("_", "-"));
            let mut cmd = Command::new("cargo");
            let cmd = cmd.args(&cargo_run_args).current_dir(&*PROJECT_ROOT);
            cmd.status().unwrap()
        }
    }

    #[macro_export]
    macro_rules! run_test_options {
        ($test:ident, $example_app:expr, $active:expr) => {
            #[test]
            fn $test() {
                let lock = TEST_LOCK.lock().unwrap();
                lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                println!("Compiling test firmware {}", stringify!($test));
                let feature = stringify!($test).replace("_", "-");
                let test_runtime = compile_runtime(&feature, $example_app);
                let i3c_port = "65534".to_string();
                let test = run_runtime(
                    &feature,
                    ROM.to_path_buf(),
                    test_runtime,
                    i3c_port,
                    $active,
                    None,
                    None,
                    None,
                );
                assert_eq!(0, test.code().unwrap_or_default());

                // force the compiler to keep the lock
                lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        };
    }
    #[macro_export]
    macro_rules! run_test {
        ($test:ident) => {
            run_test_options!($test, false, false);
        };
        ($test:ident, example_app) => {
            run_test_options!($test, true, false);
        };
        ($test:ident, example_app, caliptra) => {
            run_test_options!($test, true, true);
        };
        ($test:ident, caliptra) => {
            run_test_options!($test, false, true);
        };
    }

    // To add a test:
    // * add the test name here
    // * add the feature to the emulator and use it to implement any behavior needed
    // * add the feature to the runtime and use it in board.rs at the end of the main function to call your test
    // These use underscores but will be converted to dashes in the feature flags
    run_test!(test_caliptra_mailbox, example_app, caliptra);
    run_test!(test_caliptra_crypto, example_app, caliptra);
    run_test!(test_dma, example_app);
    run_test!(test_i3c_simple);
    run_test!(test_i3c_constant_writes);
    run_test!(test_flash_ctrl_init);
    run_test!(test_flash_ctrl_read_write_page);
    run_test!(test_flash_ctrl_erase_page);
    run_test!(test_flash_storage_read_write);
    run_test!(test_flash_storage_erase);
    run_test!(test_flash_usermode, example_app);
    run_test!(test_mctp_ctrl_cmds);
    run_test!(test_mctp_capsule_loopback);
    run_test!(test_mctp_user_loopback, example_app);
    run_test!(test_pldm_discovery);
    run_test!(test_pldm_fw_update);
    run_test!(test_pldm_fw_update_e2e);
    run_test!(test_spdm_validator, caliptra);

    /// This tests a full active mode boot run through with Caliptra, including
    /// loading MCU's firmware from Caliptra over the recovery interface.
    #[test]
    fn test_active_mode_recovery_with_caliptra() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let feature = "test-exit-immediately".to_string();
        println!("Compiling test firmware {}", &feature);
        let test_runtime = compile_runtime(&feature, false);
        let i3c_port = "65534".to_string();
        let test = run_runtime(
            &feature,
            ROM.to_path_buf(),
            test_runtime,
            i3c_port,
            true,
            None,
            None,
            None,
        );
        assert_eq!(0, test.code().unwrap_or_default());

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn test_streaming_boot(is_flash: bool) {
        const CALIPTRA_EXTERNAL_RAM_BASE: u64 = 0x8000_0000;
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let feature = if is_flash {
            "test-flash-streaming-boot".to_string()
        } else {
            "test-pldm-streaming-boot".to_string()
        };

        // Define test firmware contents
        let soc_image_fw_1 = [0x55u8; 512]; // Example firmware data for SOC image 1
        let soc_image_fw_2 = [0xAAu8; 256]; // Example firmware data for SOC image 2

        // Create temporary files for SOC images
        let soc_image_path_1 =
            tempfile::NamedTempFile::new().expect("Failed to create temp file 1");
        let soc_image_path_2 =
            tempfile::NamedTempFile::new().expect("Failed to create temp file 2");

        // get pathbuf of the temp files
        let soc_images_paths = vec![
            soc_image_path_1.path().to_path_buf(),
            soc_image_path_2.path().to_path_buf(),
        ];

        println!("SOC image paths: {:?}", soc_images_paths);

        // Write firmware data to the temporary files
        std::fs::write(soc_image_path_1.path(), soc_image_fw_1)
            .expect("Failed to write temp file 1");
        std::fs::write(soc_image_path_2.path(), soc_image_fw_2)
            .expect("Failed to write temp file 2");

        let caliptra_image = None;

        // Create a flash image with only the SOC images
        let flash_image_path = tempfile::NamedTempFile::new()
            .expect("Failed to create flash image file")
            .path()
            .to_str()
            .unwrap()
            .to_string();
        mcu_builder::flash_image::flash_image_create(
            &caliptra_image,
            &caliptra_image,
            &caliptra_image,
            &Some(
                soc_images_paths
                    .iter()
                    .map(|p| p.to_string_lossy().to_string())
                    .collect(),
            ),
            flash_image_path.as_str(),
        )
        .expect("Failed to create flash image");

        println!("Flash image path: {:?}", flash_image_path);

        // Read the contents of the flash image
        let flash_image =
            std::fs::read(flash_image_path.clone()).expect("Failed to read flash image");

        // Define the PLDM Firmware package manifest
        // This an arbitrary UUID, it should match the one in the device' fw_params definition.
        pub const DEVICE_UUID: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let pldm_fw_pkg: FirmwareManifest = FirmwareManifest {
            package_header_information: PackageHeaderInformation {
                package_header_identifier: uuid::Uuid::parse_str(
                    "7B291C996DB64208801B02026E463C78",
                )
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
                    descriptor_data: DEVICE_UUID.to_vec(),
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

                size: flash_image.len() as u32,
                image_data: Some(flash_image),
                ..Default::default()
            }],
        };

        // Write the PLDM package to a temporary file
        let pldm_fw_pkg_path = tempfile::NamedTempFile::new()
            .expect("Failed to create temp file")
            .path()
            .to_str()
            .unwrap()
            .to_string();
        pldm_fw_pkg
            .generate_firmware_package(&pldm_fw_pkg_path)
            .expect("Failed to generate firmware package");

        println!("PLDM Firmware Package: {:?}", pldm_fw_pkg_path);

        println!("Compiling test firmware {}", &feature);
        let test_runtime = compile_runtime(&feature, false);
        let i3c_port = "65534".to_string();

        let streaming_boot = if is_flash {
            None
        } else {
            Some(PathBuf::from(pldm_fw_pkg_path))
        };
        let flash_image = if is_flash {
            Some(PathBuf::from(flash_image_path.clone()))
        } else {
            None
        };

        let soc_images = Some(vec![
            SocImage {
                path: soc_image_path_1.path().to_path_buf(),
                load_addr: CALIPTRA_EXTERNAL_RAM_BASE,
                image_id: 4096,
            },
            SocImage {
                path: soc_image_path_2.path().to_path_buf(),
                load_addr: CALIPTRA_EXTERNAL_RAM_BASE + soc_image_fw_1.len() as u64,
                image_id: 4097,
            },
        ]);

        let test = run_runtime(
            &feature,
            ROM.to_path_buf(),
            test_runtime,
            i3c_port,
            true,
            soc_images,
            streaming_boot,
            flash_image,
        );
        assert_eq!(0, test.code().unwrap_or_default());

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_pldm_streaming_boot() {
        test_streaming_boot(false);
    }

    #[test]
    fn test_flash_streaming_boot() {
        test_streaming_boot(true);
    }
}
