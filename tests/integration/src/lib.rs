// Licensed under the Apache-2.0 license

mod i3c_socket;
#[cfg(feature = "fpga_realtime")]
mod jtag;
#[cfg(test)]
mod network;
#[cfg(test)]
mod rom;
mod test_dot;
mod test_exception_handler;
mod test_firmware_update;
mod test_fpga_flash_ctrl;
mod test_i3c_constant_writes;
mod test_i3c_simple;
mod test_mctp_capsule_loopback;
mod test_mctp_vdm_cmds;
mod test_mcu_mbox;
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
    use caliptra_image_types::FwVerificationPqcKeyType;
    use emulator_periph::TapDevice;
    use mcu_builder::flash_image::build_flash_image_bytes;
    use mcu_builder::{CaliptraBuilder, EmulatorBinaries, FirmwareBinaries, ImageCfg, TARGET};
    use mcu_hw_model::{DefaultHwModel, Fuses, InitParams, McuHwModel};
    use mcu_testing_common::{DeviceLifecycle, MCU_RUNNING};
    use random_port::PortPicker;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};
    use std::{
        path::{Path, PathBuf},
        process::Command,
        sync::LazyLock,
    };

    /// Custom Caliptra firmware bundle for testing with custom keys.
    pub struct CustomCaliptraFw {
        /// The firmware bundle bytes
        pub fw_bytes: Vec<u8>,
        /// The vendor public key hash (48 bytes / 384 bits)
        pub vendor_pk_hash: [u8; 48],
        /// The SoC manifest bytes (re-signed with custom owner keys)
        pub soc_manifest: Vec<u8>,
    }

    const TEST_HW_REVISION: &str = "2.0.0";

    #[derive(Default)]
    pub struct TestParams<'a> {
        pub feature: Option<&'a str>,
        pub network_rom_feature: Option<&'a str>,
        pub i3c_port: Option<u16>,
        pub dot_flash_initial_contents: Option<Vec<u8>>,
        pub rom_only: bool,
        pub include_network_rom: bool,
        pub network_tap_device: Option<Arc<Mutex<Box<dyn TapDevice>>>>,
        /// If true, set the DOT initialized fuse to enable DOT flow
        pub dot_enabled: bool,
        /// Custom Caliptra firmware bundle to use instead of prebuilt/compiled.
        pub custom_caliptra_fw: Option<CustomCaliptraFw>,
        /// Custom OTP memory contents. If provided, takes precedence over dot_enabled.
        pub otp_memory: Option<Vec<u8>>,
        pub flash_boot: bool,
        /// ROM feature flag. If set, compiles a ROM with this feature enabled.
        pub rom_feature: Option<&'a str>,
    }

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

    // Get ROM from prebuilt or compile
    fn get_or_compile_rom(feature: &str) -> PathBuf {
        // Try to get prebuilt ROM from the firmware bundle
        if feature.is_empty() {
            if let Ok(binaries) = FirmwareBinaries::from_env() {
                let output = target_binary("mcu_rom_prebuilt.bin");
                if let Some(parent) = output.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                std::fs::write(&output, &binaries.mcu_rom)
                    .expect("Failed to write prebuilt ROM to file");
                return output;
            }
        }
        // Fall back to compilation
        compile_rom(feature)
    }

    // only build the ROM once
    pub static ROM: LazyLock<PathBuf> = LazyLock::new(|| get_or_compile_rom(""));

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

    fn compile_rom(feature: &str) -> PathBuf {
        let feature = if TEST_HW_REVISION == "2.1.0" && feature.is_empty() {
            "hw-2-1"
        } else {
            feature
        };
        let output: PathBuf =
            mcu_builder::rom_build(Some(platform().to_string()), Some(feature.to_string()))
                .expect("ROM build failed");
        assert!(output.exists());
        output
    }

    pub fn compile_runtime(feature: Option<&str>, example_app: bool) -> PathBuf {
        let platform = platform();
        let feature_name = match feature {
            Some(f) => format!("-{f}"),
            None => String::new(),
        };
        let name = format!("runtime{}-{}.bin", feature_name, platform);

        let feature_str: &[&str] = match feature {
            Some(s) => &[s],
            None => &[],
        };

        let output = mcu_builder::runtime_build_with_apps(
            feature_str,
            Some(name),
            example_app,
            Some(platform),
            None,
        )
        .expect("Runtime failed to compile");
        assert!(output.exists());
        output
    }

    /// Check if prebuilt binaries are available for the given feature.
    pub fn has_prebuilt_binaries(feature: &str) -> bool {
        if let Ok(binaries) = FirmwareBinaries::from_env() {
            binaries.test_runtime(feature).is_ok()
                && binaries.test_pldm_fw_pkg(feature).is_ok()
                && binaries.test_flash_image(feature).is_ok()
        } else {
            false
        }
    }

    struct TestBinaries {
        vendor_pk_hash_u8: Vec<u8>,
        caliptra_rom: Vec<u8>,
        caliptra_fw: Vec<u8>,
        mcu_rom: Vec<u8>,
        soc_manifest: Vec<u8>,
        mcu_runtime: Vec<u8>,
        network_rom: Vec<u8>,
    }

    fn prebuilt_binaries(
        feature: Option<&str>,
        network_rom_feature: Option<&str>,
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
            network_rom: binaries.network_rom.clone(),
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

        // check for prebuilt network ROM with feature
        if let Some(net_feature) = network_rom_feature {
            test_binaries.network_rom = binaries.test_feature_network_rom(net_feature);
        }

        test_binaries
    }

    fn build_test_binaries(
        feature: Option<&str>,
        network_rom_feature: Option<&str>,
        rom_feature: Option<&str>,
    ) -> TestBinaries {
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

        let mcu_rom = if let Some(rf) = rom_feature {
            let rom_path = get_rom_with_feature(rf);
            std::fs::read(rom_path).unwrap()
        } else {
            std::fs::read(&*ROM).unwrap()
        };
        let soc_manifest = std::fs::read(
            builder
                .get_soc_manifest(None)
                .expect("Failed to build SoC manifest"),
        )
        .unwrap();
        let vendor_pk_hash_u8 = hex::decode(builder.get_vendor_pk_hash().unwrap())
            .expect("Invalid hex string for vendor_pk_hash");
        let mcu_runtime = std::fs::read(mcu_runtime).unwrap();

        // Network ROM is optional - build it if the build system supports it
        let network_rom = match mcu_builder::network_rom_build(network_rom_feature) {
            Ok(path) => std::fs::read(path).unwrap_or_default(),
            Err(_) => Vec::new(),
        };

        TestBinaries {
            vendor_pk_hash_u8,
            caliptra_rom,
            caliptra_fw,
            mcu_rom,
            soc_manifest,
            mcu_runtime,
            network_rom,
        }
    }

    pub fn start_runtime_hw_model(params: TestParams) -> DefaultHwModel {
        // reset to known good state for beginning of test so that I3C socket will start correctly
        MCU_RUNNING.store(true, Ordering::Relaxed);

        let TestBinaries {
            vendor_pk_hash_u8,
            caliptra_rom,
            caliptra_fw,
            mcu_rom,
            soc_manifest,
            mcu_runtime,
            network_rom,
        } = match FirmwareBinaries::from_env() {
            Ok(binaries) if params.rom_feature.is_none() => {
                prebuilt_binaries(params.feature, params.network_rom_feature, binaries)
            }
            _ => {
                println!("Could not find prebuilt firmware binaries, building firmware...");
                build_test_binaries(
                    params.feature,
                    params.network_rom_feature,
                    params.rom_feature,
                )
            }
        };

        // Use custom Caliptra FW if provided, otherwise use prebuilt/compiled
        let (caliptra_fw, vendor_pk_hash_u8, soc_manifest) =
            if let Some(custom) = params.custom_caliptra_fw {
                (
                    custom.fw_bytes,
                    custom.vendor_pk_hash.to_vec(),
                    custom.soc_manifest,
                )
            } else {
                (caliptra_fw, vendor_pk_hash_u8, soc_manifest)
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

        // Only include network ROM if requested
        let network_rom_slice: &[u8] = if params.include_network_rom {
            &network_rom
        } else {
            &[]
        };
        // Set up OTP memory: use custom otp_memory if provided, otherwise auto-generate from dot_enabled
        let otp_memory = if let Some(custom_otp) = params.otp_memory {
            Some(custom_otp)
        } else if params.dot_enabled {
            // TODO: move this when we add the fuse-burning scripts
            use registers_generated::fuses::VENDOR_NON_SECRET_PROD_PARTITION_BYTE_OFFSET;
            // Create OTP memory large enough to include the vendor non-secret prod partition
            let mut otp = vec![0u8; VENDOR_NON_SECRET_PROD_PARTITION_BYTE_OFFSET + 256];
            // Set dot_initialized to 1 at the start of the vendor non-secret prod partition
            otp[VENDOR_NON_SECRET_PROD_PARTITION_BYTE_OFFSET] = 0x7; // backed by 3 bits
            Some(otp)
        } else {
            None
        };

        // Build flash image for flash-based boot, or use individual images for streaming boot
        let (flash_image, caliptra_firmware, soc_manifest_bytes, mcu_firmware) =
            if params.flash_boot {
                let flash = build_flash_image_bytes(
                    Some(&caliptra_fw),
                    Some(&soc_manifest),
                    Some(&mcu_runtime),
                );
                (Some(flash), vec![], vec![], vec![])
            } else {
                // For streaming boot, pass individual images to BMC
                (None, caliptra_fw, soc_manifest, mcu_runtime)
            };

        // TODO: read the PQC type
        mcu_hw_model::new(InitParams {
            fuses: Fuses {
                fuse_pqc_key_type: FwVerificationPqcKeyType::LMS as u32,
                vendor_pk_hash,
                ..Default::default()
            },
            caliptra_rom: &caliptra_rom,
            mcu_rom: &mcu_rom,
            caliptra_firmware: &caliptra_firmware,
            soc_manifest: &soc_manifest_bytes,
            mcu_firmware: &mcu_firmware,
            network_rom: network_rom_slice,
            network_tap_device: params.network_tap_device,
            vendor_pk_hash: Some(vendor_pk_hash_u8.try_into().unwrap()),
            active_mode: true,
            vendor_pqc_type: Some(FwVerificationPqcKeyType::LMS),
            i3c_port: params.i3c_port,
            enable_mcu_uart_log: true,
            dot_flash_initial_contents: params.dot_flash_initial_contents,
            check_booted_to_runtime: !params.rom_only,
            otp_memory: otp_memory.as_deref(),
            primary_flash_initial_contents: flash_image,
            flash_boot: params.flash_boot,
            ..Default::default()
        })
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
        device_security_state: DeviceLifecycle,
        soc_images: Option<Vec<ImageCfg>>,
        streaming_boot_package_path: Option<PathBuf>,
        primary_flash_image_path: Option<PathBuf>,
        secondary_flash_image_path: Option<PathBuf>,
        caliptra_builder: Option<CaliptraBuilder>,
        hw_revision: Option<String>,
        fuse_soc_manifest_svn: Option<u8>,
        fuse_soc_manifest_max_svn: Option<u8>,
        fuse_vendor_test_partition: Option<Vec<u8>>,
    ) -> i32 {
        // Check for prebuilt emulator first
        let prebuilt_emulator = get_prebuilt_emulator(feature);

        // Build emulator arguments (these are the same whether using prebuilt or cargo run)
        let rom_path_str = rom_path.to_str().unwrap().to_string();
        let runtime_path_str = runtime_path.to_str().unwrap().to_string();
        let mut emulator_args: Vec<String> = vec![
            "--rom".to_string(),
            rom_path_str,
            "--firmware".to_string(),
            runtime_path_str,
            "--i3c-port".to_string(),
            i3c_port.clone(),
        ];

        // map the memory map to the emulator
        emulator_args.extend([
            "--rom-offset".to_string(),
            format!(
                "0x{:x}",
                mcu_config_emulator::EMULATOR_MEMORY_MAP.rom_offset
            ),
            "--rom-size".to_string(),
            format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.rom_size),
            "--dccm-offset".to_string(),
            format!(
                "0x{:x}",
                mcu_config_emulator::EMULATOR_MEMORY_MAP.dccm_offset
            ),
            "--dccm-size".to_string(),
            format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.dccm_size),
            "--sram-offset".to_string(),
            format!(
                "0x{:x}",
                mcu_config_emulator::EMULATOR_MEMORY_MAP.sram_offset
            ),
            "--sram-size".to_string(),
            format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.sram_size),
            "--pic-offset".to_string(),
            format!(
                "0x{:x}",
                mcu_config_emulator::EMULATOR_MEMORY_MAP.pic_offset
            ),
            "--i3c-offset".to_string(),
            format!(
                "0x{:x}",
                mcu_config_emulator::EMULATOR_MEMORY_MAP.i3c_offset
            ),
            "--i3c-size".to_string(),
            format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.i3c_size),
            "--mci-offset".to_string(),
            format!(
                "0x{:x}",
                mcu_config_emulator::EMULATOR_MEMORY_MAP.mci_offset
            ),
            "--mci-size".to_string(),
            format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.mci_size),
            "--mbox-offset".to_string(),
            format!(
                "0x{:x}",
                mcu_config_emulator::EMULATOR_MEMORY_MAP.mbox_offset
            ),
            "--mbox-size".to_string(),
            format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.mbox_size),
            "--soc-offset".to_string(),
            format!(
                "0x{:x}",
                mcu_config_emulator::EMULATOR_MEMORY_MAP.soc_offset
            ),
            "--soc-size".to_string(),
            format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.soc_size),
            "--otp-offset".to_string(),
            format!(
                "0x{:x}",
                mcu_config_emulator::EMULATOR_MEMORY_MAP.otp_offset
            ),
            "--otp-size".to_string(),
            format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.otp_size),
            "--lc-offset".to_string(),
            format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.lc_offset),
            "--lc-size".to_string(),
            format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.lc_size),
        ]);

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

        if let Some(hw_revision) = hw_revision {
            emulator_args.extend(["--hw-revision".to_string(), hw_revision]);
        }

        if active_mode {
            emulator_args.extend([
                "--device-security-state".to_string(),
                format!("{}", device_security_state as u32),
            ]);
            let caliptra_rom = caliptra_builder
                .get_caliptra_rom()
                .expect("Failed to build Caliptra ROM");
            emulator_args.extend([
                "--caliptra-rom".to_string(),
                caliptra_rom.to_str().unwrap().to_string(),
            ]);
            let caliptra_fw = caliptra_builder
                .get_caliptra_fw()
                .expect("Failed to build Caliptra firmware");
            emulator_args.extend([
                "--caliptra-firmware".to_string(),
                caliptra_fw.to_str().unwrap().to_string(),
            ]);
            let soc_manifest = caliptra_builder
                .get_soc_manifest(None)
                .expect("Failed to build SoC manifest");
            emulator_args.extend([
                "--soc-manifest".to_string(),
                soc_manifest.to_str().unwrap().to_string(),
            ]);
            let vendor_pk_hash = caliptra_builder
                .get_vendor_pk_hash()
                .expect("Failed to get vendor PK hash");
            emulator_args.extend(["--vendor-pk-hash".to_string(), vendor_pk_hash.to_string()]);

            if let Some(path) = streaming_boot_package_path {
                emulator_args.extend([
                    "--streaming-boot".to_string(),
                    path.to_str().unwrap().to_string(),
                ]);
            }

            if let Some(path) = primary_flash_image_path {
                emulator_args.extend([
                    "--primary-flash-image".to_string(),
                    path.to_str().unwrap().to_string(),
                ]);
                // Enable flash-based boot mode only for tests that explicitly use flash-based boot
                // (test-flash-based-boot feature). Other tests like test-firmware-update-flash
                // provide a flash image for firmware updates but still use BMC streaming boot.
                if feature.contains("test-flash-based-boot") {
                    emulator_args.push("--flash-based-boot".to_string());
                }
            }

            if let Some(path) = secondary_flash_image_path {
                emulator_args.extend([
                    "--secondary-flash-image".to_string(),
                    path.to_str().unwrap().to_string(),
                ]);
            }

            if let Some(soc_manifest_svn) = fuse_soc_manifest_svn {
                emulator_args.extend([
                    "--fuse-soc-manifest-svn".to_string(),
                    soc_manifest_svn.to_string(),
                ]);
            }

            if let Some(soc_manifest_max_svn) = fuse_soc_manifest_max_svn {
                emulator_args.extend([
                    "--fuse-soc-manifest-max-svn".to_string(),
                    soc_manifest_max_svn.to_string(),
                ]);
            }

            if let Some(fuse_vendor_test_partition) = fuse_vendor_test_partition {
                emulator_args.extend([
                    "--fuse-vendor-test-partition".to_string(),
                    hex::encode(fuse_vendor_test_partition),
                ]);
            }
        }

        println!("Running test firmware {}", feature.replace("_", "-"));

        // Use prebuilt emulator if available, otherwise fall back to cargo run
        if let Some(emulator_path) = prebuilt_emulator {
            let mut cmd = Command::new(&emulator_path);
            let cmd = cmd.args(&emulator_args).current_dir(&*PROJECT_ROOT);
            cmd.status().unwrap().code().unwrap_or(1)
        } else {
            println!("No prebuilt emulator available, using cargo run...");
            let mut cargo_args: Vec<String> = vec![
                "run".to_string(),
                "-p".to_string(),
                "emulator".to_string(),
                "--profile".to_string(),
                "test".to_string(),
                "--features".to_string(),
                feature.to_string(),
                "--".to_string(),
            ];
            cargo_args.extend(emulator_args);
            let mut cmd = Command::new("cargo");
            let cmd = cmd.args(&cargo_args).current_dir(&*PROJECT_ROOT);
            cmd.status().unwrap().code().unwrap_or(1)
        }
    }

    /// Get prebuilt emulator from EmulatorBinaries if available.
    /// Returns the path to the emulator binary, or None if not available.
    /// Uses the CPTRA_EMULATOR_BUNDLE environment variable.
    fn get_prebuilt_emulator(feature: &str) -> Option<PathBuf> {
        let binaries = EmulatorBinaries::from_env().ok()?;
        let emulator_bytes = binaries.emulator(feature).ok()?;

        // Write prebuilt emulator to target directory
        let output = target_binary(&format!("emulator-{}", feature));
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent).ok()?;
        }
        std::fs::write(&output, emulator_bytes).ok()?;
        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o755)).ok()?;
        }
        println!("Using prebuilt emulator for feature {}", feature);
        Some(output)
    }

    /// Get prebuilt runtime from FirmwareBinaries if available, writing it to a temp file.
    /// Returns the path to the runtime binary.
    fn get_or_compile_runtime(feature: &str, example_app: bool) -> PathBuf {
        // Try to get prebuilt runtime from the firmware bundle
        if let Ok(binaries) = FirmwareBinaries::from_env() {
            if let Ok(runtime_bytes) = binaries.test_runtime(feature) {
                // Write prebuilt runtime to target directory
                let output = target_binary(&format!("runtime-{}-emulator.bin", feature));
                if let Some(parent) = output.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                std::fs::write(&output, runtime_bytes)
                    .expect("Failed to write prebuilt runtime to file");
                println!("Using prebuilt test firmware {}", feature);
                return output;
            }
        }
        // Fall back to compilation if prebuilt not available
        println!(
            "Compiling test firmware {} (no prebuilt available)",
            feature
        );
        compile_runtime(Some(feature), example_app)
    }

    /// Create a CaliptraBuilder with prebuilt binaries if available.
    fn create_caliptra_builder_with_prebuilt(
        runtime_path: PathBuf,
        feature: &str,
    ) -> Option<CaliptraBuilder> {
        let binaries = FirmwareBinaries::from_env().ok()?;

        // Write prebuilt Caliptra binaries to target directory
        let target_dir = PROJECT_ROOT.join("target").join(TARGET).join("release");
        std::fs::create_dir_all(&target_dir).ok()?;

        let caliptra_rom_path = target_dir.join("caliptra_rom_prebuilt.bin");
        std::fs::write(&caliptra_rom_path, &binaries.caliptra_rom).ok()?;

        let caliptra_fw_path = target_dir.join("caliptra_fw_prebuilt.bin");
        std::fs::write(&caliptra_fw_path, &binaries.caliptra_fw).ok()?;

        // Get SoC manifest for this feature, or default
        let soc_manifest_bytes = binaries
            .test_soc_manifest(feature)
            .ok()
            .unwrap_or_else(|| binaries.soc_manifest.clone());
        let soc_manifest_path = target_dir.join(format!("soc_manifest_{}_prebuilt.bin", feature));
        std::fs::write(&soc_manifest_path, soc_manifest_bytes).ok()?;

        let vendor_pk_hash = binaries.vendor_pk_hash().map(hex::encode);

        Some(CaliptraBuilder::new(
            false,
            Some(caliptra_rom_path),
            Some(caliptra_fw_path),
            Some(soc_manifest_path),
            vendor_pk_hash,
            Some(runtime_path),
            None,
            None,
            None,
            None,
            None,
        ))
    }

    fn run_test(feature: &str, example_app: bool) {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let feature = feature.replace("_", "-");
        let test_runtime = get_or_compile_runtime(&feature, example_app);
        let i3c_port = PortPicker::new().random(true).pick().unwrap().to_string();

        // Try to create CaliptraBuilder with prebuilt binaries
        let caliptra_builder =
            create_caliptra_builder_with_prebuilt(test_runtime.clone(), &feature);

        let test = run_runtime(
            &feature,
            ROM.to_path_buf(),
            test_runtime,
            i3c_port,
            true,                        // active mode is always true
            DeviceLifecycle::Production, // set this to DeviceLifecycle::Manufacturing if you want to run in manufacturing mode
            None,
            None,
            None,
            None,
            caliptra_builder,
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
    run_test!(test_caliptra_util_host_validator, nightly);
    run_test!(test_dma, example_app);
    run_test!(test_doe_transport_loopback, example_app);
    run_test!(test_doe_user_loopback, example_app);
    run_test!(test_doe_discovery, example_app);
    run_test!(test_get_device_state, example_app);
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
    run_test!(test_doe_spdm_tdisp_ide_validator, nightly);
    run_test!(test_mci, example_app);
    run_test!(test_mcu_mbox_driver);
    run_test!(test_mcu_mbox_soc_requester_loopback, example_app);
    run_test!(test_mbox_sram, example_app);
    run_test!(test_warm_reset, example_app);

    /// This tests a full active mode boot run through with Caliptra, including
    /// loading MCU's firmware from Caliptra over the recovery interface.
    #[test]
    fn test_active_mode_recovery_with_caliptra() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let feature = "test-exit-immediately".to_string();
        let test_runtime = get_or_compile_runtime(&feature, false);
        let i3c_port = PortPicker::new().random(true).pick().unwrap().to_string();
        let caliptra_builder =
            create_caliptra_builder_with_prebuilt(test_runtime.clone(), &feature);
        let test = run_runtime(
            &feature,
            ROM.to_path_buf(),
            test_runtime,
            i3c_port,
            true,
            DeviceLifecycle::Production,
            None,
            None,
            None,
            None,
            caliptra_builder,
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
        let test_runtime = get_or_compile_runtime(&feature, false);
        let i3c_port = PortPicker::new().random(true).pick().unwrap().to_string();
        let caliptra_builder =
            create_caliptra_builder_with_prebuilt(test_runtime.clone(), &feature);
        let test = run_runtime(
            &feature,
            get_rom_with_feature(&feature),
            test_runtime,
            i3c_port,
            true,
            DeviceLifecycle::Production,
            None,
            None,
            None,
            None,
            caliptra_builder,
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
        let name = format!("runtime-{}.bin", feature);
        let test_runtime = target_binary(&name);

        println!("Compiling test firmware {}", &feature);
        mcu_builder::runtime_build_with_apps(&[feature], Some(name), true, None, Some(image_svn))
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

        let i3c_port = PortPicker::new().random(true).pick().unwrap().to_string();
        Some(run_runtime(
            feature,
            get_rom_with_feature(feature),
            test_runtime,
            i3c_port,
            true,
            DeviceLifecycle::Production,
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
