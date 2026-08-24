// Licensed under the Apache-2.0 license

mod i3c_socket;
#[cfg(feature = "fpga_realtime")]
mod jtag;
#[cfg(test)]
mod mldsa_idevid_cert;
#[cfg(test)]
mod network;
#[cfg(test)]
mod rom;
#[cfg(test)]
mod runtime;
mod test_active_i3c;
mod test_caliptra_runtime_svn_burn;
mod test_caliptra_util_host_mcu_mailbox_validator;
mod test_caliptra_util_host_spdm_vdm_validator;
mod test_defmt_logging_mailbox;
mod test_defmt_logging_release;
mod test_defmt_logging_vdm;
mod test_dot;
mod test_dpe_handle_store;
mod test_ekp;
mod test_exception_handler;
mod test_external_otp;
mod test_fips_zeroization;
mod test_firmware_update;
mod test_fpga_flash_ctrl;
mod test_handoff;
mod test_hek;
mod test_i3c_constant_writes;
mod test_i3c_dcr;
mod test_i3c_simple;
mod test_log_flash_usermode;
mod test_mctp_capsule_loopback;
mod test_mctp_spdm_attestation;
mod test_mctp_spdm_attestation_pcr_quote;
mod test_mctp_spdm_responder_conformance;
mod test_mctp_vdm_cmds;
mod test_mctp_vdm_validator;
mod test_mcu_mbox;
mod test_ocp_dev_identity_provision_tool;
mod test_owner_stable_key;
mod test_pldm_fw_update;
mod test_raw_lifecycle_boot;
mod test_soc_boot;
mod test_svn_manifest;
mod test_sw_pcr_store;
mod test_timer_alarm;
mod test_usb_ocp_recovery;

pub fn platform() -> &'static str {
    if cfg!(feature = "fpga_realtime") {
        "fpga"
    } else {
        "emulator"
    }
}

#[cfg(test)]
mod test {
    use caliptra_mcu_builder::flash_image::{build_flash_image_bytes, write_partition_table};
    use caliptra_mcu_builder::{
        target_dir, CaliptraBuildArgs, CaliptraBuilder, EmulatorBinaries, FirmwareBinaries,
        ImageCfg, TARGET,
    };
    use caliptra_mcu_config::boot::{PartitionId, PartitionStatus, RollbackEnable};
    use caliptra_mcu_config_emulator::flash::{
        PartitionTable, StandAloneChecksumCalculator, IMAGE_A_PARTITION, STAGING_PARTITION,
    };
    use caliptra_mcu_emulator_periph::TapDevice;
    use caliptra_mcu_hw_model::{DefaultHwModel, Fuses, InitParams, McuHwModel, McuManager};
    use caliptra_mcu_testing_common::{i3c::DynamicI3cAddress, DeviceLifecycle, EmulatorState};
    use random_port::PortPicker;
    use std::io::{BufRead, BufReader, Write};
    use std::sync::atomic::AtomicU32;
    use std::sync::{Arc, Condvar, Mutex};
    use std::{
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        sync::LazyLock,
    };
    use std::{thread, time::Duration};
    use zerocopy::FromBytes;

    const TEST_HW_REVISION: &str = "2.1.0";

    /// Custom Caliptra firmware bundle for testing with custom keys.
    pub struct CustomCaliptraFw {
        /// The firmware bundle bytes
        pub fw_bytes: Vec<u8>,
        /// The vendor public key hash (48 bytes / 384 bits)
        pub vendor_pk_hash: [u8; 48],
        /// The SoC manifest bytes (re-signed with custom owner keys)
        pub soc_manifest: Vec<u8>,
    }

    pub struct TestParams<'a> {
        pub feature: Option<&'a str>,
        pub rom_feature: Option<&'a str>,
        pub network_rom_feature: Option<&'a str>,
        pub i3c_port: Option<u16>,
        pub dot_flash_initial_contents: Option<Vec<u8>>,
        pub rom_only: bool,
        pub include_network_rom: bool,
        pub flash_boot: bool,
        /// Seed primary flash for a runtime flash loader while ROM boots via recovery.
        pub seed_primary_flash_image: bool,
        pub network_tap_device: Option<Arc<Mutex<Box<dyn TapDevice>>>>,
        /// If true, set the DOT initialized fuse to enable DOT flow
        pub dot_enabled: bool,
        /// Custom Caliptra firmware bundle to use instead of prebuilt/compiled.
        pub custom_caliptra_fw: Option<CustomCaliptraFw>,
        /// Custom OTP memory contents. If provided, takes precedence over dot_enabled.
        pub otp_memory: Option<Vec<u8>>,
        /// Enable FIPS zeroization PPD signal for cold boot testing.
        pub fips_zeroization: bool,
        pub ocp_lock_en: bool,
        /// If true, drive the MCI generic input wire strap that forces the ROM
        /// to use the `CPTRA_SS_OWNER_PK_HASH` fuse as the owner, bypassing DOT.
        pub force_fuse_owner_pk_hash: bool,
        /// Optional custom MCU ROM bytes (overrides the default/compiled ROM).
        pub custom_mcu_rom: Option<Vec<u8>>,
        /// Optional custom MCU runtime bytes (overrides the default/compiled runtime).
        pub custom_mcu_runtime: Option<Vec<u8>>,
        /// Optional bytes to prepend to the MCU firmware image (e.g., a manifest header).
        pub firmware_prefix: Option<Vec<u8>>,
        pub fw_manifest_dot_hitless: bool,
        #[allow(dead_code)]
        pub active_i3c1: bool,
        pub lifecycle_controller_state: Option<caliptra_mcu_romtime::LifecycleControllerState>,
        pub vendor_pqc_type: Option<caliptra_image_types::FwVerificationPqcKeyType>,
        /// Assert the debug intent strap.
        pub debug_intent: bool,
        /// Production debug unlock keypairs (ECC384 pub key bytes, MLDSA87 pub key bytes).
        pub prod_dbg_unlock_keypairs: Vec<([u8; 96], [u8; 2592])>,
        pub use_strap_secrets: bool,
        /// If set, the kernel logging-flash partition is host-side seeded
        /// with these entries before the firmware boots. Honored on both
        /// emulator and FPGA via `BootParams::primary_flash_initial_contents`.
        pub seeded_log_entries: Option<&'static [&'static [u8]]>,
        /// If true, include the example app in the runtime build instead of the user app.
        pub example_app: bool,
        /// Cargo profile to use for a from-source runtime build.
        pub profile: Option<&'a str>,
        /// Override the Caliptra firmware SVN. Forces a from-source
        /// Caliptra FW + SoC manifest build (ignoring any prebuilt
        /// Caliptra FW) so the reported `FW_INFO.fw_svn` is known. Only
        /// honored on the `firmware_prefix` build path.
        pub caliptra_svn: Option<u16>,
    }

    impl Default for TestParams<'_> {
        fn default() -> Self {
            Self {
                feature: None,
                rom_feature: None,
                network_rom_feature: None,
                i3c_port: None,
                dot_flash_initial_contents: None,
                rom_only: false,
                include_network_rom: false,
                flash_boot: false,
                seed_primary_flash_image: false,
                network_tap_device: None,
                dot_enabled: false,
                custom_caliptra_fw: None,
                otp_memory: None,
                fips_zeroization: false,
                ocp_lock_en: false,
                force_fuse_owner_pk_hash: false,
                custom_mcu_rom: None,
                custom_mcu_runtime: None,
                firmware_prefix: None,
                fw_manifest_dot_hitless: false,
                active_i3c1: false,
                lifecycle_controller_state: None,
                vendor_pqc_type: Some(caliptra_image_types::FwVerificationPqcKeyType::LMS),
                debug_intent: false,
                prod_dbg_unlock_keypairs: Vec::new(),
                use_strap_secrets: false,
                seeded_log_entries: None,
                example_app: false,
                profile: None,
                caliptra_svn: None,
            }
        }
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
        target_dir().join(TARGET).join("release").join(name)
    }

    // Get ROM from prebuilt or compile
    fn get_or_compile_rom(feature: &str) -> PathBuf {
        if let Ok(binaries) = FirmwareBinaries::from_env() {
            // Empty feature → use the generic prebuilt ROM.
            // Otherwise, only use the prebuilt ROM if it was actually built
            // for the requested feature (i.e. don't silently fall back to the
            // generic ROM which lacks the requested feature flags).
            let rom_data = if feature.is_empty() {
                Some(binaries.mcu_rom.clone())
            } else {
                let expected_name = format!("mcu-test-rom-feature-{}.bin", feature);
                binaries
                    .test_roms
                    .iter()
                    .find(|(name, _)| name == &expected_name)
                    .map(|(_, data)| data.clone())
            };
            if let Some(rom_data) = rom_data {
                let safe_name = feature.replace('/', "_");
                let filename = if safe_name.is_empty() {
                    "mcu_rom_prebuilt.bin".to_string()
                } else {
                    format!("mcu_rom_prebuilt_{}.bin", safe_name)
                };
                let output = target_binary(&filename);
                if let Some(parent) = output.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                std::fs::write(&output, &rom_data).expect("Failed to write prebuilt ROM to file");
                return output;
            }
        }
        // Fall back to compilation
        compile_rom(feature)
    }

    // only build the default ROM once
    pub static ROM: LazyLock<PathBuf> = LazyLock::new(|| get_or_compile_rom(""));
    pub static ROM_FW_MANIFEST_DOT: LazyLock<Vec<u8>> =
        LazyLock::new(|| std::fs::read(get_or_compile_rom("test-fw-manifest-dot")).unwrap());
    pub static ROM_FW_MANIFEST_DOT_HITLESS: LazyLock<Vec<u8>> = LazyLock::new(|| {
        std::fs::read(get_or_compile_rom("test-fw-manifest-dot-hitless")).unwrap()
    });

    pub static TEST_LOCK: LazyLock<Mutex<AtomicU32>> =
        LazyLock::new(|| Mutex::new(AtomicU32::new(0)));

    // Compile the ROM for a given feature flag (empty string for default ROM).
    pub fn get_rom_with_feature(feature: &str) -> PathBuf {
        get_or_compile_rom(feature)
    }

    fn platform() -> &'static str {
        if cfg!(feature = "fpga_realtime") {
            "fpga"
        } else {
            "emulator"
        }
    }

    fn compile_rom(feature: &str) -> PathBuf {
        let requested_feature = feature;
        let feature = if TEST_HW_REVISION == "2.1.0" {
            if feature.is_empty() {
                "hw-2-1".to_string()
            } else {
                format!("hw-2-1,{feature}")
            }
        } else {
            feature.to_string()
        };
        // Return the feature-suffixed path directly from rom_build.
        // Do NOT copy to a generic name: subsequent builds re-create the
        // intermediate mcu-rom-<platform>.bin (without the appended ROM
        // digest), which would silently clobber the copy.
        let output: PathBuf = caliptra_mcu_builder::rom_build(&CaliptraBuildArgs {
            platform: Some(platform()),
            features: Some(&feature),
            ..Default::default()
        })
        .expect("ROM build failed");
        assert!(output.exists());
        if requested_feature.is_empty() {
            let stable_output = target_binary(&format!("mcu_rom_default_{}.bin", platform()));
            std::fs::copy(&output, &stable_output).expect("Failed to copy default MCU ROM");
            stable_output
        } else {
            output
        }
    }

    pub fn compile_runtime(feature: Option<&str>, example_app: bool) -> PathBuf {
        let profile_env = std::env::var("MCU_TEST_PROFILE").ok();
        compile_runtime_with_profile(feature, example_app, profile_env.as_deref())
    }

    pub fn compile_runtime_with_profile(
        feature: Option<&str>,
        example_app: bool,
        profile: Option<&str>,
    ) -> PathBuf {
        let mut features = vec![];
        if let Some(feature) = feature {
            features.push(feature);
        }
        if TEST_HW_REVISION == "2.1.0" {
            features.push("hw-2-1");
        }
        let platform = platform();
        let feature_name = match feature {
            Some(f) => format!("-{f}"),
            None => String::new(),
        };
        let name = format!("runtime{}-{}.bin", feature_name, platform);

        // `MCU_TEST_PROFILE` opt-in: lets a developer switch the
        // test firmware build between `devel` (default; 1 MB SRAM,
        // debug components present) and `release` (512 KB SRAM,
        // debug stripped) without code churn. Mirrors xtask's
        // semantics: when the caller asks for `release`, also enable
        // the `release` cargo feature so kernel `debug!()` macros,
        // `romtime::println!`, DebugWriter, Console, LowLevelDebug
        // and ProcessConsole are stripped.
        if matches!(profile, Some("release")) {
            features.push("release");
        }

        let features_str = features.join(",");
        let output = caliptra_mcu_builder::runtime_build_with_apps(&CaliptraBuildArgs {
            features: if features.is_empty() {
                None
            } else {
                Some(&features_str)
            },
            output_name: Some(name),
            example_app,
            platform: Some(platform),
            profile,
            no_default_features: true,
            ..Default::default()
        })
        .expect("Runtime failed to compile");
        assert!(output.exists());
        output
    }

    /// Check if a prebuilt feature-specific MCU ROM is available.
    pub fn has_prebuilt_rom(feature: &str) -> bool {
        if let Ok(binaries) = FirmwareBinaries::from_env() {
            // test_feature_rom always returns data (falls back to generic ROM)
            let _ = binaries.test_feature_rom(feature);
            true
        } else {
            false
        }
    }

    /// Check if prebuilt binaries are available for the given feature.
    pub fn has_prebuilt_binaries(feature: &str) -> bool {
        if let Ok(binaries) = FirmwareBinaries::from_env() {
            binaries.test_runtime(feature).is_ok() && binaries.test_soc_manifest(feature).is_ok()
        } else {
            false
        }
    }

    pub struct TestBinaries {
        pub vendor_pk_hash_u8: Vec<u8>,
        pub caliptra_rom: Vec<u8>,
        pub caliptra_fw: Vec<u8>,
        pub mcu_rom: Vec<u8>,
        pub soc_manifest: Vec<u8>,
        pub mcu_runtime: Vec<u8>,
        pub flash_image: Option<Vec<u8>>,
    }

    fn prebuilt_binaries(params: &TestParams, binaries: &'static FirmwareBinaries) -> TestBinaries {
        let is_ocp_lock = params.ocp_lock_en
            || params.feature.is_some_and(|f| f.contains("ocp-lock"))
            || params.rom_feature.is_some_and(|f| f.contains("ocp-lock"));
        let caliptra_fw = if is_ocp_lock {
            binaries.caliptra_fw_ocp_lock.clone()
        } else {
            binaries.caliptra_fw.clone()
        };
        let mut test_binaries = TestBinaries {
            vendor_pk_hash_u8: binaries
                .vendor_pk_hash()
                .expect("Failed to get Vendor PK hash")
                .to_vec(),
            caliptra_rom: binaries.caliptra_rom.clone(),
            caliptra_fw,
            mcu_rom: binaries.mcu_rom.clone(),
            soc_manifest: binaries.soc_manifest.clone(),
            mcu_runtime: binaries.mcu_runtime.clone(),
            flash_image: None,
        };

        // check for prebuilt binaries for our test feature
        if let Some(feature) = params.feature {
            let err = format!(
                "Failed to get MCU firmware and manifest for feature {}",
                feature
            );
            test_binaries.soc_manifest = binaries.test_soc_manifest(feature).expect(&err).clone();
            test_binaries.mcu_runtime = binaries.test_runtime(feature).expect(&err).clone();
            test_binaries.flash_image = binaries.test_flash_image(feature).ok();
        }

        if let Some(rom_feature) = params.rom_feature {
            test_binaries.mcu_rom = binaries.test_feature_rom(rom_feature);
        }

        test_binaries
    }

    const MAILBOX_TIMEOUT_CYCLES: u64 = 20_000_000;

    /// Execute a mailbox command with a large timeout and return the raw
    /// response bytes.
    pub fn mailbox_execute_with_timeout(
        hw: &mut impl McuHwModel,
        cmd: u32,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, String> {
        hw.start_mailbox_execute(cmd, payload)
            .map_err(|e| format!("start_mailbox_execute failed: {}", e))?;

        let mut remaining = MAILBOX_TIMEOUT_CYCLES;
        while hw.cmd_status().cmd_busy() {
            hw.step();
            remaining -= 1;
            if remaining == 0 {
                return Err("Mailbox command timed out".to_string());
            }
        }

        let status = hw.cmd_status();

        if status.cmd_failure() {
            hw.mcu_manager().with_mbox0(|mbox| {
                mbox.mbox_execute().write(|w| w.execute(false));
            });
            return Err("Mailbox command failed".to_string());
        }

        hw.mcu_manager().with_mbox0(|mbox| {
            if status.cmd_complete() {
                let dlen = mbox.mbox_dlen().read() as usize;
                if dlen == 0 {
                    mbox.mbox_execute().write(|w| w.execute(false));
                    return Ok(None);
                }
            } else if !status.data_ready() {
                mbox.mbox_execute().write(|w| w.execute(false));
                return Err(format!("Unknown mailbox status {:x}", u32::from(status)));
            }

            let dlen = mbox.mbox_dlen().read() as usize;
            let mut output = Vec::with_capacity(dlen);

            let len_words = dlen / size_of::<u32>();
            for i in 0..len_words {
                let word = mbox.mbox_sram().at(i).read();
                output.extend_from_slice(&word.to_le_bytes());
            }

            let remaining_bytes = dlen % size_of::<u32>();
            if remaining_bytes > 0 {
                let word = mbox.mbox_sram().at(len_words).read();
                output.extend_from_slice(&word.to_le_bytes()[..remaining_bytes]);
            }

            mbox.mbox_execute().write(|w| w.execute(false));
            Ok(Some(output))
        })
    }

    // Sample IDevID ECC Cert (same as ECC_DEVID_CERT_DER in external_otp component)
    pub const ECC_DEVID_CERT_DER: [u8; 547] = [
        0x30, 0x82, 0x02, 0x1f, 0x30, 0x82, 0x01, 0xa6, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01,
        0x00, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x30, 0x5e,
        0x31, 0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x11, 0x77, 0x77, 0x77, 0x2e,
        0x6d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x1e,
        0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x15, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x73,
        0x6f, 0x66, 0x74, 0x20, 0x43, 0x6f, 0x72, 0x70, 0x6f, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e,
        0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13,
        0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6e,
        0x67, 0x74, 0x6f, 0x6e, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x35, 0x33, 0x30, 0x30,
        0x32, 0x34, 0x39, 0x30, 0x31, 0x5a, 0x17, 0x0d, 0x32, 0x37, 0x30, 0x35, 0x33, 0x30, 0x30,
        0x32, 0x34, 0x39, 0x30, 0x31, 0x5a, 0x30, 0x70, 0x31, 0x23, 0x30, 0x21, 0x06, 0x03, 0x55,
        0x04, 0x03, 0x0c, 0x1a, 0x43, 0x61, 0x6c, 0x69, 0x70, 0x74, 0x72, 0x61, 0x20, 0x32, 0x2e,
        0x31, 0x20, 0x45, 0x63, 0x63, 0x33, 0x38, 0x34, 0x20, 0x49, 0x44, 0x65, 0x76, 0x49, 0x44,
        0x31, 0x49, 0x30, 0x47, 0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x40, 0x33, 0x43, 0x35, 0x36,
        0x36, 0x46, 0x43, 0x46, 0x35, 0x46, 0x45, 0x42, 0x42, 0x44, 0x39, 0x44, 0x34, 0x39, 0x35,
        0x41, 0x34, 0x33, 0x37, 0x31, 0x43, 0x38, 0x34, 0x38, 0x30, 0x35, 0x44, 0x31, 0x38, 0x36,
        0x44, 0x38, 0x34, 0x31, 0x33, 0x37, 0x30, 0x41, 0x46, 0x30, 0x36, 0x32, 0x30, 0x39, 0x43,
        0x34, 0x33, 0x39, 0x46, 0x30, 0x44, 0x34, 0x44, 0x32, 0x30, 0x44, 0x41, 0x42, 0x34, 0x35,
        0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05,
        0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0x65, 0x1e, 0x70, 0x12, 0x44, 0xb9,
        0x4f, 0x45, 0xc6, 0x55, 0xc8, 0x2d, 0xa4, 0x00, 0xc6, 0x35, 0xc9, 0x56, 0xa0, 0x7e, 0x24,
        0xd6, 0xf6, 0x8a, 0xc0, 0x48, 0xe5, 0x9c, 0xfb, 0x60, 0x96, 0x25, 0xfb, 0xc4, 0xd4, 0x86,
        0xea, 0xa8, 0x16, 0xbe, 0xd2, 0x33, 0x6f, 0xd3, 0xeb, 0x10, 0x0d, 0x4e, 0x0d, 0x80, 0x6d,
        0xe8, 0x8b, 0x09, 0x9c, 0xe9, 0xd6, 0x4f, 0x4d, 0x1d, 0x0b, 0x51, 0x0d, 0x96, 0x57, 0xd5,
        0xa9, 0xe2, 0x4c, 0xe4, 0x81, 0x88, 0xd2, 0xbe, 0x1e, 0x2a, 0xa0, 0xb6, 0xf7, 0xd8, 0x8e,
        0x8e, 0xa1, 0xa5, 0x56, 0x7b, 0x6e, 0x03, 0xe4, 0x12, 0x22, 0x92, 0x57, 0x2d, 0xb1, 0x1b,
        0xa3, 0x26, 0x30, 0x24, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04,
        0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x05, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d,
        0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x02, 0x04, 0x30, 0x0a, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x03, 0x67, 0x00, 0x30, 0x64, 0x02, 0x30, 0x26,
        0x9c, 0x42, 0x4c, 0x8c, 0x7f, 0xa3, 0x92, 0xb9, 0xdf, 0xa5, 0x9f, 0x98, 0x15, 0x4f, 0x29,
        0x87, 0xea, 0x27, 0xd1, 0x43, 0x3e, 0xe3, 0x9b, 0x51, 0xd0, 0xf2, 0xa5, 0x25, 0x17, 0x96,
        0xd9, 0x02, 0x19, 0x09, 0x2a, 0x6c, 0x3a, 0x46, 0x18, 0x54, 0x00, 0x77, 0xd4, 0x54, 0x1c,
        0xd2, 0xad, 0x02, 0x30, 0x5a, 0x48, 0xdc, 0x3b, 0x85, 0xca, 0xec, 0x41, 0x61, 0x9c, 0xa9,
        0x0d, 0x7d, 0x11, 0x5b, 0x00, 0x6c, 0x43, 0xb4, 0xf6, 0x1c, 0xdd, 0xb9, 0x69, 0x2a, 0x79,
        0xc1, 0xf1, 0xa2, 0x27, 0xe8, 0x09, 0xb4, 0xb1, 0xb7, 0xc4, 0x44, 0x92, 0x0e, 0xc5, 0xf5,
        0x55, 0x0c, 0x48, 0x1a, 0xcf, 0xa1, 0xd2,
    ];
    // Root-signed IDevID ML-DSA certificate (partition 0x02, after ECC cert).
    pub use crate::mldsa_idevid_cert::MLDSA_IDEVID_CERT;

    /// Build the primary flash initial contents, populating the emulated
    /// external OTP partition with the ECC IDevID cert when requested,
    /// and optionally seeding the logging partition with pre-formatted entries.
    pub fn build_primary_flash_initial_contents(
        flash_image: Option<Vec<u8>>,
        ecc_cert: Option<&[u8]>,
        mldsa_cert: Option<&[u8]>,
        seeded_log_entries: Option<&[&[u8]]>,
    ) -> Option<Vec<u8>> {
        #[cfg(not(feature = "fpga_realtime"))]
        let otp_part = &caliptra_mcu_config_emulator::flash::EMULATED_EXT_OTP_PARTITION;
        #[cfg(feature = "fpga_realtime")]
        let otp_part = &caliptra_mcu_config_fpga::flash::EMULATED_EXT_OTP_PARTITION;
        let min_len = otp_part.offset + otp_part.size;
        let mut flash = flash_image.unwrap_or_else(|| vec![0xFFu8; min_len]);
        if flash.len() < min_len {
            flash.resize(min_len, 0xFF);
        }
        // Partitions are laid out sequentially: ECC cert at offset 0, MLDSA cert right after.
        let mut otp_offset = otp_part.offset;
        if let Some(cert) = ecc_cert {
            flash[otp_offset..otp_offset + cert.len()].copy_from_slice(cert);
            otp_offset += cert.len();
        }
        if let Some(cert) = mldsa_cert {
            flash[otp_offset..otp_offset + cert.len()].copy_from_slice(cert);
        }
        if let Some(entries) = seeded_log_entries {
            #[cfg(not(feature = "fpga_realtime"))]
            let log_part = &caliptra_mcu_config_emulator::flash::LOGGING_PARTITION;
            #[cfg(feature = "fpga_realtime")]
            let log_part = &caliptra_mcu_config_fpga::flash::LOGGING_PARTITION;
            flash = caliptra_mcu_testing_common::logging_seed::splice_logging_partition_into_flash_image(
                Some(flash),
                entries,
                log_part.offset,
                log_part.size,
                256, // PAGE_SIZE for both emulator and FPGA flash controllers
            );
        }
        Some(flash)
    }

    pub fn build_test_binaries(params: &TestParams) -> TestBinaries {
        // Get MCU runtime: prefer an explicit override, then prebuilt for the
        // requested feature, and fall back to compilation.
        let mcu_runtime_path = if let Some(runtime_bytes) = params.custom_mcu_runtime.as_ref() {
            let path = target_binary("mcu_runtime_custom_for_builder.bin");
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            std::fs::write(&path, runtime_bytes).expect("Failed to write custom runtime to file");
            path
        } else if let Ok(binaries) = FirmwareBinaries::from_env() {
            let runtime_bytes = if let Some(feature) = params.feature {
                match binaries.test_runtime(feature) {
                    Ok(bytes) => Some(bytes.clone()),
                    Err(_) => None,
                }
            } else {
                Some(binaries.mcu_runtime.clone())
            };
            if let Some(bytes) = runtime_bytes {
                let path = target_binary("mcu_runtime_prebuilt_for_builder.bin");
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                std::fs::write(&path, &bytes).expect("Failed to write prebuilt runtime to file");
                path
            } else if params.rom_only {
                compile_runtime(None, false)
            } else {
                compile_runtime(params.feature, false)
            }
        } else if params.rom_only {
            compile_runtime(None, false)
        } else {
            compile_runtime_with_profile(params.feature, params.example_app, params.profile)
        };

        // When a firmware prefix is provided, create a modified binary that
        // includes the prefix so the SOC manifest digest covers both.
        let (mcu_runtime_for_builder, mcu_runtime_bytes) =
            if let Some(prefix) = &params.firmware_prefix {
                let original = if params.rom_only {
                    // RISC-V "j ." (jump to self) instruction: 0x0000006f.
                    // We provide it as a small byte array.
                    vec![0x6f, 0x00, 0x00, 0x00, 0x6f, 0x00, 0x00, 0x00]
                } else {
                    std::fs::read(&mcu_runtime_path).unwrap()
                };
                let mut prefixed = prefix.to_vec();
                prefixed.extend_from_slice(&original);

                // Write the prefixed binary to a temp file for CaliptraBuilder
                let prefixed_path = mcu_runtime_path.with_extension("prefixed");
                std::fs::write(&prefixed_path, &prefixed).unwrap();
                (prefixed_path, prefixed)
            } else {
                let bytes = std::fs::read(&mcu_runtime_path).unwrap();
                (mcu_runtime_path, bytes)
            };

        // When prebuilt binaries are available, pass the Caliptra ROM/FW paths
        // to the builder so it doesn't try to compile them from scratch.
        let (prebuilt_caliptra_rom, prebuilt_caliptra_fw, prebuilt_vendor_pk_hash) =
            if let Ok(binaries) = FirmwareBinaries::from_env() {
                let rom_path =
                    std::env::temp_dir().join("build_test_binaries_caliptra_rom_prebuilt.bin");
                std::fs::write(&rom_path, &binaries.caliptra_rom)
                    .expect("Failed to write prebuilt Caliptra ROM");
                let is_ocp_lock = params.ocp_lock_en
                    || params.feature.is_some_and(|f| f.contains("ocp-lock"))
                    || params.rom_feature.is_some_and(|f| f.contains("ocp-lock"));
                let fw_data = if is_ocp_lock {
                    &binaries.caliptra_fw_ocp_lock
                } else {
                    &binaries.caliptra_fw
                };
                let fw_path =
                    std::env::temp_dir().join("build_test_binaries_caliptra_fw_prebuilt.bin");
                std::fs::write(&fw_path, fw_data).expect("Failed to write prebuilt Caliptra FW");
                let vendor_pk_hash = hex::encode(
                    binaries
                        .vendor_pk_hash()
                        .expect("Failed to get vendor PK hash from prebuilt binaries"),
                );
                (Some(rom_path), Some(fw_path), Some(vendor_pk_hash))
            } else {
                (None, None, None)
            };

        // When a Caliptra SVN override is requested, force a from-source
        // build of the Caliptra FW (and matching SoC manifest) so the
        // requested SVN is honored rather than a prebuilt SVN-0 image.
        let (prebuilt_caliptra_fw, prebuilt_vendor_pk_hash) = if params.caliptra_svn.is_some() {
            (None, None)
        } else {
            (prebuilt_caliptra_fw, prebuilt_vendor_pk_hash)
        };

        let mut builder = CaliptraBuilder::new(&caliptra_mcu_builder::CaliptraBuildArgs {
            fpga: cfg!(feature = "fpga_realtime"),
            ocp_lock: params
                .feature
                .map(|f| f.contains("ocp-lock"))
                .unwrap_or(false)
                || params.ocp_lock_en,
            caliptra_rom: prebuilt_caliptra_rom,
            caliptra_firmware: prebuilt_caliptra_fw,
            vendor_pk_hash: prebuilt_vendor_pk_hash,
            mcu_firmware: Some(mcu_runtime_for_builder),
            svn: params.caliptra_svn,
            ..Default::default()
        });
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

        let mcu_rom = if params.firmware_prefix.is_some() && params.rom_feature.is_none() {
            if params.fw_manifest_dot_hitless {
                ROM_FW_MANIFEST_DOT_HITLESS.clone()
            } else {
                ROM_FW_MANIFEST_DOT.clone()
            }
        } else if let Some(f) = params.rom_feature {
            std::fs::read(compile_rom(f)).unwrap()
        } else if params.rom_only && params.feature.is_some() {
            std::fs::read(compile_rom(params.feature.unwrap())).unwrap()
        } else {
            std::fs::read(ROM.to_path_buf()).unwrap()
        };
        let soc_manifest = std::fs::read(
            builder
                .get_soc_manifest(None)
                .expect("Failed to build SoC manifest"),
        )
        .unwrap();
        let vendor_pk_hash_u8 = hex::decode(builder.get_vendor_pk_hash().unwrap())
            .expect("Invalid hex string for vendor_pk_hash");

        TestBinaries {
            vendor_pk_hash_u8,
            caliptra_rom,
            caliptra_fw,
            mcu_rom,
            soc_manifest,
            mcu_runtime: mcu_runtime_bytes,
            flash_image: None,
        }
    }

    pub fn start_runtime_hw_model(params: TestParams) -> DefaultHwModel {
        std::env::set_var("CPTRA_EMULATOR_SS_MCI_OFFSET", "0x00000000a8000000");
        let TestBinaries {
            vendor_pk_hash_u8,
            caliptra_rom,
            caliptra_fw,
            mcu_rom,
            soc_manifest,
            mcu_runtime,
            flash_image,
        } = match FirmwareBinaries::from_env() {
            Ok(binaries)
                if params.firmware_prefix.is_none()
                    && params.custom_mcu_runtime.is_none()
                    && (params.rom_feature.is_none()
                        || has_prebuilt_rom(params.rom_feature.unwrap()))
                    && (params.feature.is_none()
                        || has_prebuilt_binaries(params.feature.unwrap())) =>
            {
                prebuilt_binaries(&params, binaries)
            }
            _ => {
                println!("Could not find prebuilt firmware binaries, building firmware...");
                build_test_binaries(&params)
            }
        };

        // Use custom MCU ROM if provided, otherwise use prebuilt/compiled
        let mcu_rom = if let Some(custom_rom) = params.custom_mcu_rom {
            custom_rom
        } else {
            mcu_rom
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
        let network_rom = match caliptra_mcu_builder::network_rom_build(params.network_rom_feature)
        {
            Ok(path) => std::fs::read(path).unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        let network_rom_slice: &[u8] = if params.include_network_rom {
            &network_rom
        } else {
            &[]
        };
        // Set up OTP memory: use custom otp_memory if provided, otherwise auto-generate from dot_enabled
        // and prod_dbg_unlock_keypairs
        let otp_memory = if let Some(custom_otp) = params.otp_memory {
            Some(custom_otp)
        } else if params.dot_enabled || !params.prod_dbg_unlock_keypairs.is_empty() {
            use caliptra_mcu_registers_generated::fuses::VENDOR_NON_SECRET_PROD_PARTITION_BYTE_OFFSET;
            // Create OTP memory large enough to include the vendor non-secret prod partition
            let mut otp = vec![0u8; VENDOR_NON_SECRET_PROD_PARTITION_BYTE_OFFSET + 256];

            if params.dot_enabled {
                // Set dot_initialized to 1 at the start of the vendor non-secret prod partition
                otp[VENDOR_NON_SECRET_PROD_PARTITION_BYTE_OFFSET] = 0x7; // backed by 3 bits
            }

            // Program PK hashes into OTP for prod debug unlock
            if !params.prod_dbg_unlock_keypairs.is_empty() {
                use caliptra_mcu_registers_generated::fuses::{
                    OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_0, OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_1,
                    OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_2, OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_3,
                    OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_4, OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_5,
                    OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_6, OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_7,
                };
                use sha2::{Digest, Sha384};

                let pk_entries = [
                    OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_0,
                    OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_1,
                    OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_2,
                    OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_3,
                    OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_4,
                    OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_5,
                    OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_6,
                    OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_7,
                ];

                for (i, (ecc, mldsa)) in params.prod_dbg_unlock_keypairs.iter().enumerate() {
                    if i >= pk_entries.len() {
                        break;
                    }
                    let mut hasher = Sha384::new();
                    hasher.update(ecc);
                    hasher.update(mldsa);
                    let hash = hasher.finalize();

                    let offset = pk_entries[i].byte_offset;
                    // Write hash to OTP: convert each 4-byte chunk from big-endian (SHA output)
                    // to little-endian (OTP storage format, matching emulator's from_le_bytes read)
                    for (j, chunk) in hash.chunks(4).enumerate() {
                        let word = u32::from_be_bytes(chunk.try_into().unwrap());
                        let byte_pos = offset + j * 4;
                        otp[byte_pos..byte_pos + 4].copy_from_slice(&word.to_le_bytes());
                    }
                }
            }

            Some(otp)
        } else {
            None
        };

        let primary_flash_image = if params.flash_boot || params.seed_primary_flash_image {
            let mut flash = flash_image.unwrap_or_else(|| {
                build_flash_image_bytes(Some(&caliptra_fw), Some(&soc_manifest), Some(&mcu_runtime))
            });
            if params.seed_primary_flash_image && !params.flash_boot {
                write_valid_partition_table_for_runtime_flash_load(&mut flash);
            }
            Some(flash)
        } else {
            None
        };
        // ROM flash boot consumes the bundle directly; recovery boot still receives
        // the individual images while runtime accesses the seeded primary flash.
        let (caliptra_firmware, soc_manifest_bytes, mcu_firmware) = if params.flash_boot {
            (vec![], vec![], vec![])
        } else {
            (caliptra_fw, soc_manifest, mcu_runtime)
        };

        let primary_flash_initial_contents = build_primary_flash_initial_contents(
            primary_flash_image,
            #[cfg(not(feature = "fpga_realtime"))]
            Some(ECC_DEVID_CERT_DER.as_slice()),
            #[cfg(feature = "fpga_realtime")]
            // Initialized in run_imaginary_flash_controller_service
            None,
            #[cfg(not(feature = "fpga_realtime"))]
            Some(MLDSA_IDEVID_CERT.as_slice()),
            #[cfg(feature = "fpga_realtime")]
            // Initialized in run_imaginary_flash_controller_service
            None,
            params.seeded_log_entries,
        );

        caliptra_mcu_hw_model::new(InitParams {
            fuses: Fuses {
                fuse_pqc_key_type: params.vendor_pqc_type.map(|t| t as u32).unwrap_or(0),
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
            vendor_pqc_type: params.vendor_pqc_type,
            i3c_port: params.i3c_port,
            enable_mcu_uart_log: true,
            dot_flash_initial_contents: params.dot_flash_initial_contents,
            lifecycle_controller_state: params.lifecycle_controller_state,
            check_booted_to_runtime: !params.rom_only,
            otp_memory: otp_memory.as_deref(),
            primary_flash_initial_contents,
            flash_boot: params.flash_boot,
            ocp_lock_en: params.ocp_lock_en,
            fips_zeroization: params.fips_zeroization,
            force_fuse_owner_pk_hash: params.force_fuse_owner_pk_hash,
            debug_intent: params.debug_intent,
            prod_dbg_unlock_keypairs: params
                .prod_dbg_unlock_keypairs
                .iter()
                .map(|(ecc, mldsa)| (ecc as &[u8; 96], mldsa as &[u8; 2592]))
                .collect(),
            active_i3c1: params.active_i3c1,
            use_strap_secrets: params.use_strap_secrets,
            ..Default::default()
        })
        .unwrap()
    }

    fn write_valid_partition_table_for_runtime_flash_load(flash: &mut Vec<u8>) {
        if !has_valid_partition_table(flash) {
            let unpartitioned_flash = std::mem::take(flash);
            flash.resize(IMAGE_A_PARTITION.offset + unpartitioned_flash.len(), 0xff);
            flash[IMAGE_A_PARTITION.offset..][..unpartitioned_flash.len()]
                .copy_from_slice(&unpartitioned_flash);
        } else if flash.len() < IMAGE_A_PARTITION.offset {
            flash.resize(IMAGE_A_PARTITION.offset, 0xff);
        }
        let mut file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, flash).unwrap();
        let mut partition_table = PartitionTable {
            active_partition: PartitionId::A as u32,
            partition_a_status: PartitionStatus::Valid as u16,
            partition_b_status: PartitionStatus::Invalid as u16,
            rollback_enable: RollbackEnable::Enabled as u32,
            ..Default::default()
        };
        partition_table.populate_checksum(&StandAloneChecksumCalculator::new());
        write_partition_table(&partition_table, 0, file.path().to_str().unwrap()).unwrap();
        *flash = std::fs::read(file.path()).unwrap();
    }

    fn has_valid_partition_table(flash: &[u8]) -> bool {
        let Ok((partition_table, _)) = PartitionTable::read_from_prefix(flash) else {
            return false;
        };
        partition_table.verify_checksum(&StandAloneChecksumCalculator::new())
    }

    #[test]
    fn runtime_seeded_flash_image_wraps_unpartitioned_image_under_active_partition() {
        let unpartitioned_flash = vec![0x11, 0x22, 0x33, 0x44];
        let mut flash = unpartitioned_flash.clone();

        write_valid_partition_table_for_runtime_flash_load(&mut flash);

        assert!(has_valid_partition_table(&flash));
        assert_eq!(
            &flash[IMAGE_A_PARTITION.offset..IMAGE_A_PARTITION.offset + unpartitioned_flash.len()],
            unpartitioned_flash.as_slice()
        );
    }

    #[test]
    fn runtime_seeded_flash_image_preserves_existing_partition_contents() {
        let image_contents = vec![0xaa, 0xbb, 0xcc, 0xdd];
        let mut flash = image_contents.clone();
        write_valid_partition_table_for_runtime_flash_load(&mut flash);

        let original_len = flash.len();
        write_valid_partition_table_for_runtime_flash_load(&mut flash);

        assert_eq!(flash.len(), original_len);
        assert!(has_valid_partition_table(&flash));
        assert_eq!(
            &flash[IMAGE_A_PARTITION.offset..IMAGE_A_PARTITION.offset + image_contents.len()],
            image_contents.as_slice()
        );
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
        let mut cmd = runtime_command(
            feature,
            rom_path,
            runtime_path,
            i3c_port,
            active_mode,
            device_security_state,
            soc_images,
            streaming_boot_package_path,
            primary_flash_image_path,
            secondary_flash_image_path,
            caliptra_builder,
            hw_revision,
            fuse_soc_manifest_svn,
            fuse_soc_manifest_max_svn,
            fuse_vendor_test_partition,
        );

        cmd.status().unwrap().code().unwrap_or(1)
    }

    #[allow(clippy::too_many_arguments)]
    fn runtime_command(
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
    ) -> Command {
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
            "--test-feature".to_string(),
            feature.to_string(),
        ];

        // map the memory map to the emulator
        emulator_args.extend([
            "--rom-offset".to_string(),
            format!(
                "0x{:x}",
                caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.rom_offset
            ),
            "--rom-size".to_string(),
            format!(
                "0x{:x}",
                caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.rom_size
            ),
            "--dccm-offset".to_string(),
            format!(
                "0x{:x}",
                caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.dccm_offset
            ),
            "--dccm-size".to_string(),
            format!(
                "0x{:x}",
                caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.dccm_size
            ),
            "--sram-offset".to_string(),
            format!(
                "0x{:x}",
                caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.sram_offset
            ),
            "--sram-size".to_string(),
            format!(
                "0x{:x}",
                caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.sram_size
            ),
            "--pic-offset".to_string(),
            format!(
                "0x{:x}",
                caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.pic_offset
            ),
            "--i3c-offset".to_string(),
            format!(
                "0x{:x}",
                caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.i3c_offset
            ),
            "--i3c-size".to_string(),
            format!(
                "0x{:x}",
                caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.i3c_size
            ),
            "--mci-offset".to_string(),
            format!(
                "0x{:x}",
                caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.mci_offset
            ),
            "--mci-size".to_string(),
            format!(
                "0x{:x}",
                caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.mci_size
            ),
            "--mbox-offset".to_string(),
            format!(
                "0x{:x}",
                caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.mbox_offset
            ),
            "--mbox-size".to_string(),
            format!(
                "0x{:x}",
                caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.mbox_size
            ),
            "--soc-offset".to_string(),
            format!(
                "0x{:x}",
                caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.soc_offset
            ),
            "--soc-size".to_string(),
            format!(
                "0x{:x}",
                caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.soc_size
            ),
            "--otp-offset".to_string(),
            format!(
                "0x{:x}",
                caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.otp_offset
            ),
            "--otp-size".to_string(),
            format!(
                "0x{:x}",
                caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.otp_size
            ),
            "--lc-offset".to_string(),
            format!(
                "0x{:x}",
                caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.lc_offset
            ),
            "--lc-size".to_string(),
            format!(
                "0x{:x}",
                caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.lc_size
            ),
        ]);

        let mut caliptra_builder = if let Some(caliptra_builder) = caliptra_builder {
            caliptra_builder
        } else {
            CaliptraBuilder::new(&CaliptraBuildArgs {
                fpga: cfg!(feature = "fpga_realtime"),
                ocp_lock: feature.contains("ocp-lock"),
                mcu_firmware: Some(runtime_path.clone()),
                soc_images,
                ..Default::default()
            })
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
            cmd.args(&emulator_args).current_dir(&*PROJECT_ROOT);
            cmd
        } else {
            println!("No prebuilt emulator available, using cargo run...");
            let mut cargo_args: Vec<String> = vec![
                "run".to_string(),
                "-p".to_string(),
                "caliptra-mcu-emulator".to_string(),
                "--profile".to_string(),
                "test".to_string(),
                "--".to_string(),
            ];
            cargo_args.extend(emulator_args);
            let mut cmd = Command::new("cargo");
            cmd.args(&cargo_args).current_dir(&*PROJECT_ROOT);
            cmd
        }
    }

    struct SpawnedRuntimeOutput {
        text: Mutex<String>,
        available: Condvar,
    }

    pub struct SpawnedRuntime {
        child: Option<Child>,
        output: Arc<SpawnedRuntimeOutput>,
        stdout_thread: Option<thread::JoinHandle<()>>,
        stderr_thread: Option<thread::JoinHandle<()>>,
        tick_thread: Option<thread::JoinHandle<()>>,
        i3c_port: u16,
        i3c_address: DynamicI3cAddress,
        _primary_flash_file: Option<tempfile::NamedTempFile>,
        _secondary_flash_file: Option<tempfile::NamedTempFile>,
    }

    impl SpawnedRuntime {
        pub fn i3c_port(&self) -> u16 {
            self.i3c_port
        }

        pub fn i3c_address(&self) -> DynamicI3cAddress {
            self.i3c_address
        }

        pub fn wait_for_next_output_contains(
            &mut self,
            needle: &str,
            timeout: Duration,
        ) -> Result<(), String> {
            let occurrence = self.output_occurrences(needle) + 1;
            self.wait_for_output_occurrences(needle, occurrence, timeout)?;
            caliptra_mcu_testing_common::set_runtime_started(true);
            Ok(())
        }

        pub fn stop(mut self) -> Result<(), String> {
            self.stop_child(false)
        }

        fn output_occurrences(&self, needle: &str) -> usize {
            self.output.text.lock().unwrap().matches(needle).count()
        }

        fn wait_for_output_occurrences(
            &mut self,
            needle: &str,
            occurrences: usize,
            timeout: Duration,
        ) -> Result<(), String> {
            let start = std::time::Instant::now();
            loop {
                {
                    let output = self.output.text.lock().unwrap();
                    if output.matches(needle).count() >= occurrences {
                        return Ok(());
                    }
                }

                if let Some(status) = self
                    .child
                    .as_mut()
                    .expect("emulator child already consumed")
                    .try_wait()
                    .map_err(|err| format!("failed to poll emulator child: {err}"))?
                {
                    return Err(format!(
                        "emulator exited before output contained {needle:?} {occurrences} time(s): {status}; output tail:\n{}",
                        self.output_tail()
                    ));
                }

                let elapsed = start.elapsed();
                if elapsed >= timeout {
                    return Err(format!(
                        "timed out after {:?} waiting for emulator output to contain {needle:?} {occurrences} time(s); output tail:\n{}",
                        timeout,
                        self.output_tail()
                    ));
                }

                let remaining = timeout - elapsed;
                let wait = remaining.min(Duration::from_secs(1));
                let output = self.output.text.lock().unwrap();
                let _ = self.output.available.wait_timeout(output, wait).unwrap();
            }
        }

        fn output_tail(&self) -> String {
            const TAIL_LEN: usize = 4096;
            let output = self.output.text.lock().unwrap();
            output
                .char_indices()
                .rev()
                .nth(TAIL_LEN)
                .map(|(idx, _)| output[idx..].to_string())
                .unwrap_or_else(|| output.clone())
        }

        fn stop_child(&mut self, allow_killed: bool) -> Result<(), String> {
            caliptra_mcu_testing_common::set_emulator_running(false);

            let Some(mut child) = self.child.take() else {
                return Ok(());
            };

            match child
                .try_wait()
                .map_err(|err| format!("failed to poll emulator child: {err}"))?
            {
                Some(status) if status.success() || allow_killed => {}
                Some(status) => {
                    return Err(format!(
                        "emulator exited unexpectedly with {status}; output tail:\n{}",
                        self.output_tail()
                    ));
                }
                None => {
                    child
                        .kill()
                        .map_err(|err| format!("failed to kill emulator child: {err}"))?;
                    child
                        .wait()
                        .map_err(|err| format!("failed to wait for emulator child: {err}"))?;
                }
            }

            if let Some(handle) = self.stdout_thread.take() {
                let _ = handle.join();
            }
            if let Some(handle) = self.stderr_thread.take() {
                let _ = handle.join();
            }
            if let Some(handle) = self.tick_thread.take() {
                let _ = handle.join();
            }
            Ok(())
        }
    }

    impl Drop for SpawnedRuntime {
        fn drop(&mut self) {
            let _ = self.stop_child(true);
        }
    }

    fn pump_child_output<R: std::io::Read + Send + 'static>(
        reader: R,
        output: Arc<SpawnedRuntimeOutput>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut reader = BufReader::new(reader);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        print!("{line}");
                        let _ = std::io::stdout().flush();
                        let mut text = output.text.lock().unwrap();
                        text.push_str(&line);
                        output.available.notify_all();
                    }
                    Err(err) => {
                        eprintln!("failed to read emulator output: {err}");
                        break;
                    }
                }
            }
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn spawn_runtime(
        feature: &str,
        rom_path: PathBuf,
        runtime_path: PathBuf,
        i3c_port: u16,
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
        primary_flash_file: Option<tempfile::NamedTempFile>,
        secondary_flash_file: Option<tempfile::NamedTempFile>,
    ) -> SpawnedRuntime {
        caliptra_mcu_testing_common::init_emulator_state(EmulatorState::new_arc());
        caliptra_mcu_testing_common::set_emulator_running(true);
        caliptra_mcu_testing_common::set_runtime_started(false);

        let mut cmd = runtime_command(
            feature,
            rom_path,
            runtime_path,
            i3c_port.to_string(),
            active_mode,
            device_security_state,
            soc_images,
            streaming_boot_package_path,
            primary_flash_image_path,
            secondary_flash_image_path,
            caliptra_builder,
            hw_revision,
            fuse_soc_manifest_svn,
            fuse_soc_manifest_max_svn,
            fuse_vendor_test_partition,
        );
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let mut child = cmd.spawn().expect("failed to spawn emulator");
        let output = Arc::new(SpawnedRuntimeOutput {
            text: Mutex::new(String::new()),
            available: Condvar::new(),
        });
        let stdout_thread = child
            .stdout
            .take()
            .map(|stdout| pump_child_output(stdout, output.clone()));
        let stderr_thread = child
            .stderr
            .take()
            .map(|stderr| pump_child_output(stderr, output.clone()));
        let tick_thread = Some(caliptra_mcu_testing_common::spawn_with_emulator_state(
            || {
                let mut ticks = 0u64;
                while caliptra_mcu_testing_common::is_emulator_running() {
                    thread::sleep(Duration::from_millis(1));
                    ticks = ticks.saturating_add(caliptra_mcu_testing_common::TICK_NOTIFY_TICKS);
                    caliptra_mcu_testing_common::update_ticks(ticks);
                }
            },
        ));

        SpawnedRuntime {
            child: Some(child),
            output,
            stdout_thread,
            stderr_thread,
            tick_thread,
            i3c_port,
            // The emulator attaches one I3C target for these tests; the first
            // dynamic address assigned by the shared I3C controller is 0x08.
            i3c_address: DynamicI3cAddress::new(8).unwrap(),
            _primary_flash_file: primary_flash_file,
            _secondary_flash_file: secondary_flash_file,
        }
    }

    pub fn start_attestation_standalone_runtime(feature: &str) -> SpawnedRuntime {
        let feature = feature.replace('_', "-");
        let test_runtime = get_or_compile_runtime(&feature, false);
        let i3c_port = PortPicker::new().random(true).pick().unwrap();
        let mut caliptra_builder =
            create_caliptra_builder_with_prebuilt(test_runtime.clone(), &feature).unwrap_or_else(
                || {
                    CaliptraBuilder::new(&caliptra_mcu_builder::CaliptraBuildArgs {
                        fpga: cfg!(feature = "fpga_realtime"),
                        mcu_firmware: Some(test_runtime.clone()),
                        ..Default::default()
                    })
                },
            );

        let mut flash = if let Some(flash) = FirmwareBinaries::from_env()
            .ok()
            .and_then(|binaries| binaries.test_flash_image(&feature).ok())
        {
            flash
        } else {
            let caliptra_fw = std::fs::read(
                caliptra_builder
                    .get_caliptra_fw()
                    .expect("Failed to build Caliptra firmware"),
            )
            .unwrap();
            let soc_manifest = std::fs::read(
                caliptra_builder
                    .get_soc_manifest(None)
                    .expect("Failed to build SoC manifest"),
            )
            .unwrap();
            let mcu_runtime = std::fs::read(&test_runtime).unwrap();
            build_flash_image_bytes(Some(&caliptra_fw), Some(&soc_manifest), Some(&mcu_runtime))
        };
        write_valid_partition_table_for_runtime_flash_load(&mut flash);

        let primary_flash = build_primary_flash_initial_contents(
            Some(flash),
            Some(ECC_DEVID_CERT_DER.as_slice()),
            Some(MLDSA_IDEVID_CERT.as_slice()),
            None,
        )
        .expect("failed to seed primary flash");
        let mut primary_flash_file =
            tempfile::NamedTempFile::new().expect("failed to create primary flash temp file");
        primary_flash_file
            .write_all(&primary_flash)
            .expect("failed to write primary flash temp file");
        primary_flash_file
            .flush()
            .expect("failed to flush primary flash temp file");
        let primary_flash_path = primary_flash_file.path().to_path_buf();

        // Mirror the firmware-update "fast" strategy: pre-populate the staging
        // (secondary) flash with the full update image so the PLDM transfer can
        // be truncated to a token payload. See `hitless_update_pldm_package`.
        let secondary_flash_file = FirmwareBinaries::from_env()
            .ok()
            .and_then(|binaries| binaries.test_update_flash_image(&feature).ok())
            .map(|update_flash| {
                let mut contents = update_flash.clone();
                if contents.len() < STAGING_PARTITION.offset {
                    contents.resize(STAGING_PARTITION.offset, 0);
                }
                contents.extend_from_slice(&update_flash);
                let mut file = tempfile::NamedTempFile::new()
                    .expect("failed to create secondary flash temp file");
                file.write_all(&contents)
                    .expect("failed to write secondary flash temp file");
                file.flush().expect("failed to flush secondary flash file");
                file
            });
        let secondary_flash_path = secondary_flash_file
            .as_ref()
            .map(|f| f.path().to_path_buf());

        spawn_runtime(
            &feature,
            ROM.to_path_buf(),
            test_runtime,
            i3c_port,
            true,
            DeviceLifecycle::Production,
            None,
            None,
            Some(primary_flash_path),
            secondary_flash_path,
            Some(caliptra_builder),
            Some("2.1.0".to_string()),
            None,
            None,
            None,
            Some(primary_flash_file),
            secondary_flash_file,
        )
    }

    /// Get prebuilt emulator from EmulatorBinaries if available.
    /// Returns the path to the emulator binary, or None if not available.
    /// Uses the CPTRA_EMULATOR_BUNDLE environment variable.
    fn get_prebuilt_emulator(feature: &str) -> Option<PathBuf> {
        let binaries = EmulatorBinaries::from_env().ok()?;
        let emulator_bytes = binaries.emulator().ok()?;

        // Write prebuilt emulator to target directory
        let output = target_binary("emulator");
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
        let caliptra_fw = if feature.contains("ocp-lock") {
            &binaries.caliptra_fw_ocp_lock
        } else {
            &binaries.caliptra_fw
        };
        std::fs::write(&caliptra_fw_path, caliptra_fw).ok()?;

        // Get SoC manifest for this feature, or default
        let soc_manifest_bytes = binaries
            .test_soc_manifest(feature)
            .ok()
            .unwrap_or_else(|| binaries.soc_manifest.clone());
        let soc_manifest_path = target_dir.join(format!("soc_manifest_{}_prebuilt.bin", feature));
        std::fs::write(&soc_manifest_path, soc_manifest_bytes).ok()?;

        let vendor_pk_hash = binaries.vendor_pk_hash().map(hex::encode);

        let caliptra_builder = CaliptraBuilder::new(&CaliptraBuildArgs {
            fpga: cfg!(feature = "fpga_realtime"),
            ocp_lock: feature.contains("ocp-lock"),
            caliptra_rom: Some(caliptra_rom_path),
            caliptra_firmware: Some(caliptra_fw_path),
            soc_manifest: Some(soc_manifest_path),
            vendor_pk_hash,
            mcu_firmware: Some(runtime_path),
            ..Default::default()
        });

        Some(caliptra_builder)
    }

    fn run_test(feature: &str, example_app: bool) {
        use std::io::Write;

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let feature = feature.replace("_", "-");
        let test_runtime = get_or_compile_runtime(&feature, example_app);
        let i3c_port = PortPicker::new().random(true).pick().unwrap().to_string();

        // Try to create CaliptraBuilder with prebuilt binaries
        let caliptra_builder =
            create_caliptra_builder_with_prebuilt(test_runtime.clone(), &feature);

        // Seed the primary flash with IDevID certs in the emulated external OTP
        // partition so that the SPDM responder has valid certificates for
        // signature verification (matches what start_runtime_hw_model does for
        // in-process tests).
        let primary_flash_file = build_primary_flash_initial_contents(
            None,
            Some(ECC_DEVID_CERT_DER.as_slice()),
            Some(MLDSA_IDEVID_CERT.as_slice()),
            None,
        )
        .map(|data| {
            let mut f =
                tempfile::NamedTempFile::new().expect("Failed to create primary flash temp file");
            f.write_all(&data).unwrap();
            f.flush().unwrap();
            f
        });
        let flash_path = primary_flash_file.as_ref().map(|f| f.path().to_path_buf());

        let rom_feature = match feature.as_str() {
            "test-ocp-lock" => "ocp-lock",
            _ => "",
        };
        let mcu_rom_path = if rom_feature.is_empty() {
            ROM.to_path_buf()
        } else {
            get_or_compile_rom(rom_feature)
        };
        let device_lifecycle = if feature == "test-get-caliptra-idev-csr" {
            DeviceLifecycle::Manufacturing
        } else {
            DeviceLifecycle::Production
        };

        let test = run_runtime(
            &feature,
            mcu_rom_path,
            test_runtime,
            i3c_port,
            true, // active mode is always true
            device_lifecycle,
            None,
            None,
            flash_path,
            None,
            caliptra_builder,
            None,
            None,
            None,
            None,
        );
        assert_eq!(0, test);

        // primary_flash_file (NamedTempFile) is dropped here, after run_runtime completes
        drop(primary_flash_file);

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn run_imaginary_flash_controller_service(hw: &mut DefaultHwModel) {
        #[cfg(feature = "fpga_realtime")]
        {
            use crate::test::{
                build_primary_flash_initial_contents, ECC_DEVID_CERT_DER, MLDSA_IDEVID_CERT,
            };
            let primary_flash_initial_contents = build_primary_flash_initial_contents(
                hw.primary_flash_initial_contents().map(Vec::from),
                Some(&ECC_DEVID_CERT_DER),
                Some(&MLDSA_IDEVID_CERT),
                None,
            );
            let mci_ptr = hw.base.mmio.mci().unwrap().ptr as u64;
            crate::test_fpga_flash_ctrl::test::run_imaginary_flash_controller_service_with_init(
                mci_ptr,
                primary_flash_initial_contents,
            );
        }
        #[cfg(not(feature = "fpga_realtime"))]
        {
            let _ = hw; // suppress unused variable warning
        }
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
    #[test]
    #[ignore = "manufacturing-only CSR extraction helper"]
    fn test_get_caliptra_idev_csr() {
        run_test("test_get_caliptra_idev_csr", true);
    }
    run_test!(test_caliptra_crypto, example_app);
    run_test!(test_caliptra_mailbox, example_app);
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
    run_test!(test_log_flash_circular);
    run_test!(test_log_flash_linear);
    #[cfg(not(feature = "fpga_realtime"))]
    run_test!(test_log_flash_usermode, example_app);
    run_test!(test_mctp_ctrl_cmds);
    run_test!(test_mctp_user_loopback, example_app);
    run_test!(test_pldm_discovery);
    run_test!(test_pldm_fw_update);
    run_test!(test_doe_spdm_responder_conformance, nightly);
    run_test!(test_doe_spdm_tdisp_ide_validator, nightly);
    run_test!(test_mci, example_app);
    run_test!(test_mcu_mbox_driver);
    run_test!(test_mcu_mbox_soc_requester_loopback, example_app);
    run_test!(test_mbox_sram, example_app);
    run_test!(test_ocp_lock, example_app);
    run_test!(test_external_otp, example_app);
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
        println!("Compiling test firmware {}", &feature);
        let test_runtime = caliptra_mcu_builder::runtime_build_with_apps(&CaliptraBuildArgs {
            features: Some(feature),
            output_name: Some(name),
            example_app: true,
            svn: Some(image_svn),
            ..Default::default()
        })
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

    #[ignore] // TODO: fix this, probably an issue with fuse writing in the hw model
    #[test]
    fn test_mcu_svn_gt_fuse() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let result = test_mcu_svn(100, 30);
        assert_eq!(0, result.unwrap_or_default());

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[ignore] // TODO: fix this, probably an issue with fuse writing in the hw model
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
