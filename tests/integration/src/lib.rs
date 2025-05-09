// Licensed under the Apache-2.0 license
mod test_soc_boot;
#[cfg(test)]
mod test {
    use mcu_builder::{CaliptraBuilder, SocImage, TARGET};
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
    pub static ROM: LazyLock<PathBuf> = LazyLock::new(compile_rom);

    pub static TEST_LOCK: LazyLock<Mutex<AtomicU32>> =
        LazyLock::new(|| Mutex::new(AtomicU32::new(0)));

    fn compile_rom() -> PathBuf {
        mcu_builder::rom_build().expect("ROM build failed");
        let output = target_binary("rom.bin");
        assert!(output.exists());
        output
    }

    pub fn compile_runtime(feature: &str, example_app: bool) -> PathBuf {
        let output = target_binary(&format!("runtime-{}.bin", feature));
        let output_name = format!("{}", output.display());
        mcu_builder::runtime_build_with_apps(&[feature], Some(&output_name), example_app)
            .expect("Runtime build failed");
        assert!(output.exists());
        output
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_runtime(
        feature: &str,
        rom_path: PathBuf,
        runtime_path: PathBuf,
        i3c_port: String,
        active_mode: bool,
        manufacturing_mode: bool,
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
            if manufacturing_mode {
                cargo_run_args.push("--manufacturing-mode");
            }
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
                    false, //set this to true if you want to run in manufacturing mode
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
    run_test!(test_caliptra_certs, example_app, caliptra);
    run_test!(test_caliptra_crypto, example_app, caliptra);
    run_test!(test_caliptra_mailbox, example_app, caliptra);
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
            false,
            None,
            None,
            None,
        );
        assert_eq!(0, test.code().unwrap_or_default());

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
