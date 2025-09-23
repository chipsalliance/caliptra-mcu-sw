// Licensed under the Apache-2.0 license

mod i3c_socket;
#[cfg(feature = "fpga_realtime")]
mod jtag;
#[cfg(test)]
mod rom;
#[cfg(feature = "fpga_realtime")]
mod test_axi_bypass;
mod test_firmware_update;
mod test_mctp_capsule_loopback;
mod test_pldm_fw_update;
mod test_soc_boot;

pub fn platform() -> &'static str {
    if cfg!(feature = "fpga_realtime") {
        "fpga"
    } else {
        "emulator"
    }
}

#[cfg(test)]
mod test {
    use caliptra_hw_model::BootParams;
    use caliptra_image_types::FwVerificationPqcKeyType;
    use mcu_builder::{CaliptraBuilder, FirmwareBinaries, ImageCfg, TARGET};
    use mcu_config::McuMemoryMap;
    use mcu_hw_model::{DefaultHwModel, Fuses, InitParams, McuHwModel};
    use mcu_image_header::McuImageHeader;
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
    pub static ROM: LazyLock<PathBuf> = LazyLock::new(|| compile_rom(""));

    pub static TEST_LOCK: LazyLock<Mutex<AtomicU32>> =
        LazyLock::new(|| Mutex::new(AtomicU32::new(0)));

    // Compile the ROM for a given feature flag (empty string for default ROM).
    pub fn get_rom_with_feature(feature: &str) -> PathBuf {
        compile_rom(feature)
    }

    fn platform() -> &'static str {
        if cfg!(feature = "fpga_realtime") {
            "fpga"
        } else {
            "emulator"
        }
    }

    fn memory_map() -> &'static McuMemoryMap {
        if cfg!(feature = "fpga_realtime") {
            &mcu_config_fpga::FPGA_MEMORY_MAP
        } else {
            &mcu_config_emulator::EMULATOR_MEMORY_MAP
        }
    }

    fn compile_rom(feature: &str) -> PathBuf {
        let output: PathBuf = mcu_builder::rom_build(Some(platform()), feature)
            .expect("ROM build failed")
            .into();
        assert!(output.exists());
        output
    }

    pub fn compile_runtime(feature: Option<&str>, example_app: bool) -> PathBuf {
        let mut features = vec![];
        if let Some(feature) = feature {
            features.push(feature);
        }
        let feature = feature.map(|f| format!("-{f}")).unwrap_or_default();
        let output = target_binary(&format!("runtime{}-{}.bin", feature, platform()));
        let output_name = format!("{}", output.display());
        mcu_builder::runtime_build_with_apps_cached(
            &features,
            Some(&output_name),
            example_app,
            Some(platform()),
            Some(memory_map()),
            false,
            None,
            None,
            Some(&mcu_config_emulator::flash::LOGGING_FLASH_CONFIG),
            None,
        )
        .expect("Runtime build failed");
        assert!(output.exists());
        output
    }

    struct TestBinaries {
        vendor_pk_hash_u8: Vec<u8>,
        caliptra_rom: Vec<u8>,
        caliptra_fw: Vec<u8>,
        mcu_rom: Vec<u8>,
        soc_manifest: Vec<u8>,
        mcu_runtime: Vec<u8>,
    }

    fn prebuilt_binaries(
        feature: Option<&str>,
        binaries: &'static FirmwareBinaries,
    ) -> TestBinaries {
        let mut test_binaries = TestBinaries {
            vendor_pk_hash_u8: binaries
                .vendor_pk_hash()
                .expect("Failed to get Vendor PK hash")
                .to_vec(),
            caliptra_rom: binaries.caliptra_rom.clone(),
            caliptra_fw: binaries.caliptra_fw.clone(),
            mcu_rom: binaries.mcu_rom.clone(),
            soc_manifest: binaries.soc_manifest.clone(),
            mcu_runtime: binaries.mcu_runtime.clone(),
        };

        // check for prebuilt binaries for our test feature
        if let Some(feature) = feature {
            let err = format!(
                "Failed to get MCU firmware and manifest for feature {}",
                feature
            );
            test_binaries.soc_manifest = binaries.test_soc_manifest(feature).expect(&err).clone();
            test_binaries.mcu_runtime = binaries.test_runtime(feature).expect(&err).clone();
        }

        test_binaries
    }

    fn build_test_binaries(feature: Option<&str>) -> TestBinaries {
        let mcu_runtime = compile_runtime(feature, false);
        let mut builder = CaliptraBuilder::new(
            cfg!(feature = "fpga_realtime"),
            None,
            None,
            None,
            None,
            Some(mcu_runtime.clone()),
            None,
            None,
            None,
            None,
            None,
        );
        let caliptra_rom = std::fs::read(
            builder
                .get_caliptra_rom()
                .expect("Failed to build Caliptra ROM"),
        )
        .unwrap();

        let caliptra_fw = std::fs::read(
            builder
                .get_caliptra_fw()
                .expect("Failed to build Caliptra ROM"),
        )
        .unwrap();

        let mcu_rom = std::fs::read(&*ROM).unwrap();
        let soc_manifest = std::fs::read(
            builder
                .get_soc_manifest(None)
                .expect("Failed to build SoC manifest"),
        )
        .unwrap();
        let vendor_pk_hash_u8 = hex::decode(builder.get_vendor_pk_hash().unwrap())
            .expect("Invalid hex string for vendor_pk_hash");
        let mcu_runtime = std::fs::read(mcu_runtime).unwrap();

        TestBinaries {
            vendor_pk_hash_u8,
            caliptra_rom,
            caliptra_fw,
            mcu_rom,
            soc_manifest,
            mcu_runtime,
        }
    }

    pub fn start_runtime_hw_model(feature: Option<&str>, i3c_port: Option<u16>) -> DefaultHwModel {
        let TestBinaries {
            vendor_pk_hash_u8,
            caliptra_rom,
            caliptra_fw,
            mcu_rom,
            soc_manifest,
            mcu_runtime,
        } = match FirmwareBinaries::from_env() {
            Ok(binaries) => prebuilt_binaries(feature, binaries),
            _ => {
                println!("Could not find prebuilt firmware binaries, building firmware...");
                build_test_binaries(feature)
            }
        };

        let vendor_pk_hash: Vec<u32> = vendor_pk_hash_u8
            .chunks(4)
            .map(|chunk| {
                let mut array = [0u8; 4];
                array.copy_from_slice(chunk);
                u32::from_be_bytes(array)
            })
            .collect();
        let vendor_pk_hash: [u32; 12] = vendor_pk_hash.as_slice().try_into().unwrap();

        // TODO: read the PQC type
        mcu_hw_model::new(
            InitParams {
                caliptra_rom: &caliptra_rom,
                mcu_rom: &mcu_rom,
                vendor_pk_hash: Some(vendor_pk_hash_u8.try_into().unwrap()),
                active_mode: true,
                vendor_pqc_type: Some(FwVerificationPqcKeyType::LMS),
                i3c_port,
                enable_mcu_uart_log: true,
                ..Default::default()
            },
            BootParams {
                fw_image: Some(&caliptra_fw),
                soc_manifest: Some(&soc_manifest),
                mcu_fw_image: Some(&mcu_runtime),
                fuses: Fuses {
                    fuse_pqc_key_type: FwVerificationPqcKeyType::LMS as u32,
                    vendor_pk_hash,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap()
    }

    pub fn finish_runtime_hw_model(hw: &mut DefaultHwModel) -> i32 {
        match hw.step_until_exit_success() {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("Emulator exited with error: {}", e);
                1
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_runtime(
        feature: &str,
        rom_path: PathBuf,
        runtime_path: PathBuf,
        i3c_port: String,
        active_mode: bool,
        manufacturing_mode: bool,
        soc_images: Option<Vec<ImageCfg>>,
        streaming_boot_package_path: Option<PathBuf>,
        primary_flash_image_path: Option<PathBuf>,
        secondary_flash_image_path: Option<PathBuf>,
        caliptra_builder: Option<CaliptraBuilder>,
        hw_revision: Option<String>,
        fuse_soc_manifest_svn: Option<u8>,
        fuse_soc_manifest_max_svn: Option<u8>,
        fuse_vendor_hashes_prod_partition: Option<Vec<u8>>,
    ) -> i32 {
        let mut cargo_run_args = vec![
            "run",
            "-p",
            "emulator",
            "--profile",
            "test",
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

        // map the memory map to the emulator
        let rom_offset = format!(
            "0x{:x}",
            mcu_config_emulator::EMULATOR_MEMORY_MAP.rom_offset
        );
        cargo_run_args.extend(["--rom-offset", &rom_offset]);
        let rom_size = format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.rom_size);
        cargo_run_args.extend(["--rom-size", &rom_size]);
        let dccm_offset = format!(
            "0x{:x}",
            mcu_config_emulator::EMULATOR_MEMORY_MAP.dccm_offset
        );
        cargo_run_args.extend(["--dccm-offset", &dccm_offset]);
        let dccm_size = format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.dccm_size);
        cargo_run_args.extend(["--dccm-size", &dccm_size]);
        let sram_offset = format!(
            "0x{:x}",
            mcu_config_emulator::EMULATOR_MEMORY_MAP.sram_offset
        );
        cargo_run_args.extend(["--sram-offset", &sram_offset]);
        let sram_size = format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.sram_size);
        cargo_run_args.extend(["--sram-size", &sram_size]);
        let pic_offset = format!(
            "0x{:x}",
            mcu_config_emulator::EMULATOR_MEMORY_MAP.pic_offset
        );
        cargo_run_args.extend(["--pic-offset", &pic_offset]);
        let i3c_offset = format!(
            "0x{:x}",
            mcu_config_emulator::EMULATOR_MEMORY_MAP.i3c_offset
        );
        cargo_run_args.extend(["--i3c-offset", &i3c_offset]);
        let i3c_size = format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.i3c_size);
        cargo_run_args.extend(["--i3c-size", &i3c_size]);
        let mci_offset = format!(
            "0x{:x}",
            mcu_config_emulator::EMULATOR_MEMORY_MAP.mci_offset
        );
        cargo_run_args.extend(["--mci-offset", &mci_offset]);
        let mci_size = format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.mci_size);
        cargo_run_args.extend(["--mci-size", &mci_size]);
        let mbox_offset = format!(
            "0x{:x}",
            mcu_config_emulator::EMULATOR_MEMORY_MAP.mbox_offset
        );
        cargo_run_args.extend(["--mbox-offset", &mbox_offset]);
        let mbox_size = format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.mbox_size);
        cargo_run_args.extend(["--mbox-size", &mbox_size]);
        let soc_offset = format!(
            "0x{:x}",
            mcu_config_emulator::EMULATOR_MEMORY_MAP.soc_offset
        );
        cargo_run_args.extend(["--soc-offset", &soc_offset]);
        let soc_size = format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.soc_size);
        cargo_run_args.extend(["--soc-size", &soc_size]);
        let otp_offset = format!(
            "0x{:x}",
            mcu_config_emulator::EMULATOR_MEMORY_MAP.otp_offset
        );
        cargo_run_args.extend(["--otp-offset", &otp_offset]);
        let otp_size = format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.otp_size);
        cargo_run_args.extend(["--otp-size", &otp_size]);
        let lc_offset = format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.lc_offset);
        cargo_run_args.extend(["--lc-offset", &lc_offset]);
        let lc_size = format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.lc_size);
        cargo_run_args.extend(["--lc-size", &lc_size]);

        let mut caliptra_builder = if let Some(caliptra_builder) = caliptra_builder {
            caliptra_builder
        } else {
            CaliptraBuilder::new(
                false,
                None,
                None,
                None,
                None,
                Some(runtime_path.clone()),
                soc_images,
                None,
                None,
                None,
                None,
            )
        };

        let hw_revision_str;
        if let Some(hw_revision) = hw_revision {
            hw_revision_str = hw_revision;
            cargo_run_args.extend(["--hw-revision", &hw_revision_str]);
        }

        if active_mode {
            if manufacturing_mode {
                cargo_run_args.push("--manufacturing-mode");
            }
            let caliptra_rom = caliptra_builder
                .get_caliptra_rom()
                .expect("Failed to build Caliptra ROM");
            cargo_run_args.push("--caliptra-rom");
            cargo_run_args.push(caliptra_rom.to_str().unwrap());
            let caliptra_fw = caliptra_builder
                .get_caliptra_fw()
                .expect("Failed to build Caliptra firmware");
            cargo_run_args.push("--caliptra-firmware");
            cargo_run_args.push(caliptra_fw.to_str().unwrap());
            let soc_manifest = caliptra_builder
                .get_soc_manifest(None)
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

            let primary_flash_image;
            if let Some(path) = primary_flash_image_path {
                cargo_run_args.push("--primary-flash-image");
                primary_flash_image = path;
                cargo_run_args.push(primary_flash_image.to_str().unwrap());
            }

            let secondary_flash_image;
            if let Some(path) = secondary_flash_image_path {
                cargo_run_args.push("--secondary-flash-image");
                secondary_flash_image = path;
                cargo_run_args.push(secondary_flash_image.to_str().unwrap());
            }

            let soc_manifest_svn_str;
            if let Some(soc_manifest_svn) = fuse_soc_manifest_svn {
                cargo_run_args.push("--fuse-soc-manifest-svn");
                soc_manifest_svn_str = soc_manifest_svn.to_string();
                cargo_run_args.push(soc_manifest_svn_str.as_str());
            }

            let soc_manifest_max_svn_str;
            if let Some(soc_manifest_max_svn) = fuse_soc_manifest_max_svn {
                cargo_run_args.push("--fuse-soc-manifest-max-svn");
                soc_manifest_max_svn_str = soc_manifest_max_svn.to_string();
                cargo_run_args.push(soc_manifest_max_svn_str.as_str());
            }

            let fuse_vendor_hashes_prod_partition_str;
            if let Some(fuse_vendor_hashes_prod_partition) = fuse_vendor_hashes_prod_partition {
                let hex_string: String = fuse_vendor_hashes_prod_partition
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect();
                cargo_run_args.push("--fuse-vendor-hashes-prod-partition");
                fuse_vendor_hashes_prod_partition_str = hex_string;
                cargo_run_args.push(fuse_vendor_hashes_prod_partition_str.as_str());
            }

            println!("Running test firmware {}", feature.replace("_", "-"));
            let mut cmd = Command::new("cargo");
            let cmd = cmd.args(&cargo_run_args).current_dir(&*PROJECT_ROOT);
            cmd.status().unwrap().code().unwrap_or(1)
        } else {
            println!("Running test firmware {}", feature.replace("_", "-"));
            let mut cmd = Command::new("cargo");
            let cmd = cmd.args(&cargo_run_args).current_dir(&*PROJECT_ROOT);
            cmd.status().unwrap().code().unwrap_or(1)
        }
    }

    fn run_test(feature: &str, example_app: bool) {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        println!("Compiling test firmware {}", feature);
        let feature = feature.replace("_", "-");
        let test_runtime = compile_runtime(Some(&feature), example_app);
        let i3c_port = "65534".to_string();
        let test = run_runtime(
            &feature,
            ROM.to_path_buf(),
            test_runtime,
            i3c_port,
            true,  // active mode is always true
            false, //set this to true if you want to run in manufacturing mode
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(0, test);

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[macro_export]
    macro_rules! run_test_options {
        ($test:ident, $example_app:expr) => {
            #[test]
            fn $test() {
                run_test(stringify!($test), $example_app);
            }
        };
    }

    #[macro_export]
    macro_rules! run_test_options_nightly {
        ($test:ident, $example_app:expr) => {
            #[ignore]
            #[test]
            fn $test() {
                run_test(stringify!($test), $example_app);
            }
        };
    }

    #[macro_export]
    macro_rules! run_test {
        ($test:ident) => {
            run_test_options!($test, false);
        };
        ($test:ident, example_app) => {
            run_test_options!($test, true);
        };
        ($test:ident, nightly) => {
            run_test_options_nightly!($test, false);
        };
    }

    // To add a test:
    // * add the test name here
    // * add the feature to the emulator and use it to implement any behavior needed
    // * add the feature to the runtime and use it in board.rs at the end of the main function to call your test
    // These use underscores but will be converted to dashes in the feature flags
    run_test!(test_caliptra_certs, example_app);
    run_test!(test_caliptra_crypto, example_app);
    run_test!(test_caliptra_mailbox, example_app);
    run_test!(test_dma, example_app);
    run_test!(test_doe_transport_loopback, example_app);
    run_test!(test_doe_user_loopback, example_app);
    run_test!(test_doe_discovery, example_app);
    run_test!(test_get_device_state, example_app);
    run_test!(test_i3c_simple);
    run_test!(test_i3c_constant_writes);
    run_test!(test_flash_ctrl_init);
    run_test!(test_flash_ctrl_read_write_page);
    run_test!(test_flash_ctrl_erase_page);
    run_test!(test_flash_storage_read_write);
    run_test!(test_flash_storage_erase);
    run_test!(test_flash_usermode, example_app);
    run_test!(test_log_flash_linear);
    run_test!(test_log_flash_circular);
    run_test!(test_log_flash_usermode, example_app);
    run_test!(test_mctp_ctrl_cmds);
    // run_test!(test_mctp_user_loopback, example_app);
    run_test!(test_pldm_discovery);
    run_test!(test_pldm_fw_update);
    run_test!(test_mctp_spdm_responder_conformance, nightly);
    run_test!(test_doe_spdm_responder_conformance, nightly);
    run_test!(test_mci, example_app);
    run_test!(test_mcu_mbox);
    run_test!(test_mcu_mbox_soc_requester_loopback, example_app);
    run_test!(test_mcu_mbox_usermode, example_app);
    run_test!(test_mcu_mbox_cmds);
    run_test!(test_mbox_sram, example_app);

    run_test!(test_warm_reset, example_app);

    /// This tests a full active mode boot run through with Caliptra, including
    /// loading MCU's firmware from Caliptra over the recovery interface.
    #[test]
    fn test_active_mode_recovery_with_caliptra() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let feature = "test-exit-immediately".to_string();
        println!("Compiling test firmware {}", &feature);
        let test_runtime = compile_runtime(Some(&feature), false);
        let i3c_port = "65534".to_string();
        let test = run_runtime(
            &feature,
            ROM.to_path_buf(),
            test_runtime,
            i3c_port,
            true,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(0, test);

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_mcu_rom_flash_access() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let feature = "test-mcu-rom-flash-access".to_string();
        println!("Compiling test firmware {}", &feature);
        let test_runtime = compile_runtime(Some(&feature), false);
        let i3c_port = "65534".to_string();
        let test = run_runtime(
            &feature,
            get_rom_with_feature(&feature),
            test_runtime,
            i3c_port,
            true,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(0, test);

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn test_mcu_svn(image_svn: u16, fuse_svn: u16) -> Option<i32> {
        let feature = if image_svn >= fuse_svn {
            "test-mcu-svn-gt-fuse"
        } else {
            "test-mcu-svn-lt-fuse"
        };

        println!("Compiling test firmware {}", &feature);

        let test_runtime = target_binary(&format!("runtime-{}.bin", feature));
        let output_name = format!("{}", test_runtime.display());
        mcu_builder::runtime_build_with_apps_cached(
            &[feature],
            Some(&output_name),
            true,
            None,
            None,
            false,
            None,
            None,
            None,
            Some(
                McuImageHeader {
                    svn: image_svn,
                    ..Default::default()
                }
                .as_bytes(),
            ),
        )
        .expect("Runtime build failed");
        assert!(test_runtime.exists());

        let fuse_vendor_hashes_prod_partition = {
            let n = if fuse_svn > 128 { 128 } else { fuse_svn };
            let val: u128 = if n == 0 {
                0
            } else if n == 128 {
                u128::MAX
            } else {
                (1u128 << n) - 1
            };

            val.to_le_bytes()
        };

        let i3c_port = "65534".to_string();
        Some(run_runtime(
            feature,
            get_rom_with_feature(feature),
            test_runtime,
            i3c_port,
            true,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(fuse_vendor_hashes_prod_partition.to_vec()),
        ))
    }

    #[test]
    fn test_mcu_svn_gt_fuse() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let result = test_mcu_svn(100, 30);
        assert_eq!(0, result.unwrap_or_default());

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_mcu_svn_lt_fuse() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let result = test_mcu_svn(25, 40);
        assert_ne!(0, result.unwrap_or_default());

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
