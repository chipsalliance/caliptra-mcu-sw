// Licensed under the Apache-2.0 license

//! Integration test for network-based boot.
//!
//! The MCU ROM uses the NetworkImageProvider to download firmware images
//! (caliptra FW, SoC manifest, MCU runtime) from the Network CoP via the
//! boot-source protocol. The Network CoP fetches the images over TFTP.

#[cfg(test)]
mod test {
    use super::super::fault_injection::{
        FaultInjectingTapDevice, FaultPlan, FaultStats, PacketKind,
    };
    use crate::test::{
        build_test_binaries, has_prebuilt_binaries, prebuilt_binaries, start_runtime_hw_model,
        write_valid_partition_table_for_runtime_flash_load, TestBinaries, TestParams, TEST_LOCK,
    };
    use caliptra_mcu_builder::flash_image::{
        build_flash_image_bytes, calculate_checksum, generate_image_info, FirmwareImage, FlashImage,
    };
    use caliptra_mcu_config_emulator::flash::IMAGE_A_PARTITION;
    use caliptra_mcu_emulator_periph::LinuxTapDevice;
    use caliptra_mcu_error::McuError;
    use caliptra_mcu_flash_image::{
        ImageHeaderV3, CALIPTRA_FMC_RT_IDENTIFIER, MCU_RT_IDENTIFIER, SOC_MANIFEST_IDENTIFIER,
    };
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_romtime::McuRomBootStatus;
    use std::mem::offset_of;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use zerocopy::IntoBytes;

    const TAP_INTERFACE: &str = "tap0";
    const TAP_IP_ADDR: &str = "192.168.100.1";
    const TFTP_BOOT_FILENAME: &str = "toc.bin";

    #[derive(Clone, Copy)]
    enum ContentFault {
        None,
        MalformedToc,
        CorruptMcuRuntime,
        UnboundedMcuRuntimeSize,
    }

    #[derive(Clone, Copy)]
    enum ExpectedOutcome {
        BootComplete,
        Fatal(McuError),
    }

    /// Build a TFTP TOC and write individual firmware files to the TFTP root.
    ///
    /// The TOC uses `TFTP_IMAGE_MAGIC_NUMBER` and each entry contains the
    /// TFTP filename the Network CoP will use to download the image.
    fn write_tftp_content(
        tftp_dir: &std::path::Path,
        caliptra_fw: &[u8],
        soc_manifest: &[u8],
        mcu_runtime: &[u8],
        fault: ContentFault,
    ) {
        let files: &[(&str, u32, &[u8])] = &[
            ("caliptra_fw.bin", CALIPTRA_FMC_RT_IDENTIFIER, caliptra_fw),
            ("soc_manifest.bin", SOC_MANIFEST_IDENTIFIER, soc_manifest),
            ("mcu_rt.bin", MCU_RT_IDENTIFIER, mcu_runtime),
        ];

        let mut images = Vec::new();
        for (fname, identifier, data) in files {
            images.push(
                FirmwareImage::new(*identifier, data, Some(fname.as_bytes()))
                    .expect("failed to create FirmwareImage"),
            );
            let mut file_data = data.to_vec();
            if matches!(fault, ContentFault::CorruptMcuRuntime) && *identifier == MCU_RT_IDENTIFIER
            {
                file_data[0] ^= 0xff;
            }
            std::fs::write(tftp_dir.join(fname), file_data).expect("Failed to write firmware file");
        }

        let mut image_info = generate_image_info(images.clone());
        if matches!(fault, ContentFault::UnboundedMcuRuntimeSize) {
            let header = image_info
                .iter_mut()
                .find(|header| header.identifier == MCU_RT_IDENTIFIER)
                .expect("MCU runtime TOC entry not found");
            header.size = u32::MAX;
            header.image_header_checksum = calculate_checksum(
                &header.as_bytes()[..offset_of!(ImageHeaderV3, image_header_checksum)],
            );
        }
        let flash_image = FlashImage::new(&images, &image_info);
        let mut toc = flash_image.to_toc_bytes();
        if matches!(fault, ContentFault::MalformedToc) {
            toc[0] ^= 0xff;
        }
        std::fs::write(tftp_dir.join(TFTP_BOOT_FILENAME), toc).expect("Failed to write TOC file");
    }

    fn get_test_binaries(params: &TestParams<'_>) -> TestBinaries {
        let check_feature = params.feature.or(params.rom_feature).unwrap_or("");
        if has_prebuilt_binaries(check_feature) {
            let binaries = caliptra_mcu_builder::FirmwareBinaries::from_env()
                .expect("CPTRA_FIRMWARE_BUNDLE not set");
            return prebuilt_binaries(params, binaries);
        }
        build_test_binaries(params)
    }

    fn run_network_boot(
        faults: Option<(FaultPlan, Arc<FaultStats>)>,
        content_fault: ContentFault,
        expected_outcome: ExpectedOutcome,
    ) -> bool {
        run_network_boot_with_feature(faults, content_fault, expected_outcome, "network-boot")
    }

    fn run_network_boot_with_feature(
        faults: Option<(FaultPlan, Arc<FaultStats>)>,
        content_fault: ContentFault,
        expected_outcome: ExpectedOutcome,
        network_rom_feature: &'static str,
    ) -> bool {
        run_network_boot_internal(
            faults,
            content_fault,
            expected_outcome,
            network_rom_feature,
            false,
        )
    }

    fn run_network_boot_internal(
        faults: Option<(FaultPlan, Arc<FaultStats>)>,
        content_fault: ContentFault,
        expected_outcome: ExpectedOutcome,
        network_rom_feature: &'static str,
        flash_fallback: bool,
    ) -> bool {
        use caliptra_mcu_xtask::network::{server, server::ServerOptions, tap};

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // --- Prerequisites ---
        if !tap::has_sudo_access() {
            eprintln!("SKIP: No passwordless sudo access");
            return false;
        }
        if !tap::interface_exists(TAP_INTERFACE) {
            println!("TAP interface {} not found, setting up...", TAP_INTERFACE);
            if let Err(e) = tap::setup(TAP_INTERFACE, TAP_IP_ADDR, true) {
                eprintln!("Failed to set up TAP interface: {}", e);
                return false;
            }
        }
        if !server::is_installed() {
            eprintln!("SKIP: dnsmasq not installed");
            return false;
        }
        if server::is_running() {
            let _ = server::stop();
        }

        // --- Build firmware via the common test infrastructure ---
        let feature = if flash_fallback {
            "test-flash-based-boot"
        } else {
            "test-network-boot"
        };
        let rom_feature = if flash_fallback {
            "test-flash-network-fallback"
        } else {
            "test-network-boot"
        };
        let build_params = TestParams {
            feature: Some(feature),
            rom_feature: Some(rom_feature),
            network_rom_feature: Some(network_rom_feature),
            ..Default::default()
        };
        let binaries = get_test_binaries(&build_params);
        let primary_flash_image = if flash_fallback {
            let mut flash = binaries.flash_image.clone().unwrap_or_else(|| {
                build_flash_image_bytes(
                    Some(&binaries.caliptra_fw),
                    Some(&binaries.soc_manifest),
                    Some(&binaries.mcu_runtime),
                    None,
                )
            });
            write_valid_partition_table_for_runtime_flash_load(&mut flash);
            let header_size = core::mem::size_of::<caliptra_mcu_flash_image::FlashHeaderV3>();
            flash[IMAGE_A_PARTITION.offset..IMAGE_A_PARTITION.offset + header_size].fill(0);
            Some(flash)
        } else {
            None
        };

        // --- Write TFTP content (TOC + firmware files) ---
        let tftp_dir = std::env::temp_dir().join("network-boot-tftp-test");
        std::fs::create_dir_all(&tftp_dir).expect("Failed to create TFTP directory");

        write_tftp_content(
            &tftp_dir,
            &binaries.caliptra_fw,
            &binaries.soc_manifest,
            &binaries.mcu_runtime,
            content_fault,
        );

        // --- Start dnsmasq with DHCP + TFTP ---
        let server_options = ServerOptions {
            interface: TAP_INTERFACE.to_string(),
            enable_tftp: true,
            tftp_root: Some(tftp_dir.clone()),
            boot_file: TFTP_BOOT_FILENAME.to_string(),
            ..Default::default()
        };
        if let Err(e) = server::start(&server_options) {
            eprintln!("Failed to start dnsmasq: {}", e);
            let _ = std::fs::remove_dir_all(&tftp_dir);
            return false;
        }

        // --- Open TAP device ---
        let tap_device = match LinuxTapDevice::open(TAP_INTERFACE) {
            Ok(tap) => {
                let tap: Box<dyn caliptra_mcu_emulator_periph::TapDevice> =
                    if let Some((plan, stats)) = faults {
                        Box::new(FaultInjectingTapDevice::new(Box::new(tap), plan, stats))
                    } else {
                        Box::new(tap)
                    };
                Arc::new(Mutex::new(tap))
            }
            Err(e) => {
                eprintln!("Failed to open TAP device: {}", e);
                let _ = server::stop();
                let _ = std::fs::remove_dir_all(&tftp_dir);
                return false;
            }
        };

        // --- Launch emulator with network boot ---
        // network_boot: true ensures BMC only streams caliptra firmware;
        // soc_manifest and mcu_runtime come from the Network CoP via TFTP.
        let mut hw = start_runtime_hw_model(TestParams {
            include_network_rom: true,
            rom_only: true,
            rom_feature: Some(rom_feature),
            feature: Some(feature),
            network_rom_feature: Some(network_rom_feature),
            flash_boot: flash_fallback,
            network_boot: !flash_fallback,
            primary_flash_image,
            network_tap_device: Some(tap_device),
            ..Default::default()
        });

        assert!(hw.has_network_cpu(), "Network CPU should be present");

        // Network boot involves DHCP, TFTP TOC fetch, then 3 TFTP image
        // downloads via the boot-source protocol — needs generous cycles.
        const MAX_CYCLES: u64 = 5_000_000_000;
        const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);
        let deadline = std::time::Instant::now() + TIMEOUT;
        let mut last_net_len: usize = 0;
        let expected_checkpoint: u16 = McuRomBootStatus::ColdBootFlowComplete.into();

        hw.step_until(|m| {
            // Print new network CPU output as it arrives.
            if let Some(net_output) = m.network_uart_output() {
                if net_output.len() > last_net_len {
                    print!("{}", &net_output[last_net_len..]);
                    last_net_len = net_output.len();
                }
            }

            m.mci_fw_fatal_error().is_some()
                || m.mci_boot_checkpoint() == expected_checkpoint
                || m.cycle_count() >= MAX_CYCLES
                || std::time::Instant::now() >= deadline
        });

        let checkpoint = hw.mci_boot_checkpoint();
        let fatal = hw.mci_fw_fatal_error();
        let timed_out = std::time::Instant::now() >= deadline;

        // --- Cleanup ---
        let _ = server::stop();
        let _ = std::fs::remove_dir_all(&tftp_dir);

        assert!(
            !timed_out,
            "Test timed out after {:?} (checkpoint={})",
            TIMEOUT, checkpoint
        );
        match expected_outcome {
            ExpectedOutcome::BootComplete => {
                assert!(fatal.is_none(), "MCU ROM hit a fatal error: {:?}", fatal);
                assert_eq!(
                    checkpoint, expected_checkpoint,
                    "Expected checkpoint == ColdBootFlowComplete ({}), got {}",
                    expected_checkpoint, checkpoint,
                );
            }
            ExpectedOutcome::Fatal(expected) => {
                assert_eq!(
                    fatal,
                    Some(expected.into()),
                    "Unexpected MCU ROM fatal error"
                );
            }
        }

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        true
    }

    #[test]
    #[cfg_attr(feature = "fpga_realtime", ignore)]
    fn test_network_boot() {
        let _ = run_network_boot(None, ContentFault::None, ExpectedOutcome::BootComplete);
    }

    #[test]
    #[cfg_attr(feature = "fpga_realtime", ignore)]
    fn test_flash_boot_falls_back_to_user_selected_network() {
        let _ = run_network_boot_internal(
            None,
            ContentFault::None,
            ExpectedOutcome::BootComplete,
            "network-boot",
            true,
        );
    }

    #[test]
    #[cfg_attr(feature = "fpga_realtime", ignore)]
    fn test_network_boot_recovers_from_dhcp_and_tftp_packet_faults() {
        let stats = Arc::new(FaultStats::default());
        let plan = FaultPlan::new()
            .drop_packets(PacketKind::DhcpV4, 1)
            .delay_packets(PacketKind::DhcpV4, 1, Duration::from_millis(25))
            .drop_packets(PacketKind::Tftp, 1)
            .delay_packets(PacketKind::Tftp, 1, Duration::from_millis(25));

        if !run_network_boot(
            Some((plan, stats.clone())),
            ContentFault::None,
            ExpectedOutcome::BootComplete,
        ) {
            return;
        }

        assert_eq!(stats.dropped(PacketKind::DhcpV4), 1);
        assert_eq!(stats.delayed(PacketKind::DhcpV4), 1);
        assert_eq!(stats.dropped(PacketKind::Tftp), 1);
        assert_eq!(stats.delayed(PacketKind::Tftp), 1);
    }

    #[test]
    #[cfg_attr(feature = "fpga_realtime", ignore)]
    fn test_network_boot_rejects_malformed_toc() {
        let _ = run_network_boot(
            None,
            ContentFault::MalformedToc,
            ExpectedOutcome::Fatal(McuError::ROM_COLD_BOOT_NETWORK_INITIATE_ERROR),
        );
    }

    #[test]
    #[cfg_attr(feature = "fpga_realtime", ignore)]
    fn test_network_boot_rejects_corrupted_runtime_image() {
        let _ = run_network_boot(
            None,
            ContentFault::CorruptMcuRuntime,
            ExpectedOutcome::Fatal(McuError::ROM_SOC_CALIPTRA_FATAL_ERROR_BEFORE_FW_READY),
        );
    }

    #[test]
    #[cfg_attr(feature = "fpga_realtime", ignore)]
    fn test_network_boot_rejects_unbounded_runtime_size() {
        let _ = run_network_boot(
            None,
            ContentFault::UnboundedMcuRuntimeSize,
            ExpectedOutcome::Fatal(McuError::ROM_COLD_BOOT_LOAD_IMAGE_ERROR),
        );
    }

    #[test]
    #[cfg_attr(feature = "fpga_realtime", ignore)]
    fn test_network_boot_dhcp_timeout() {
        let stats = Arc::new(FaultStats::default());
        let plan = FaultPlan::new().drop_all(PacketKind::DhcpV4);
        if !run_network_boot_with_feature(
            Some((plan, stats.clone())),
            ContentFault::None,
            ExpectedOutcome::Fatal(McuError::ROM_COLD_BOOT_NETWORK_INITIATE_ERROR),
            "test-network-boot-timeouts",
        ) {
            return;
        }
        assert!(stats.dropped(PacketKind::DhcpV4) > 0);
    }

    #[test]
    #[cfg_attr(feature = "fpga_realtime", ignore)]
    fn test_network_boot_tftp_toc_timeout() {
        let stats = Arc::new(FaultStats::default());
        let plan = FaultPlan::new().drop_tftp_transfer(1);
        if !run_network_boot_with_feature(
            Some((plan, stats.clone())),
            ContentFault::None,
            ExpectedOutcome::Fatal(McuError::ROM_COLD_BOOT_NETWORK_INITIATE_ERROR),
            "test-network-boot-timeouts",
        ) {
            return;
        }
        assert!(stats.dropped(PacketKind::Tftp) > 0);
    }

    #[test]
    #[cfg_attr(feature = "fpga_realtime", ignore)]
    fn test_network_boot_tftp_image_timeout() {
        let stats = Arc::new(FaultStats::default());
        let plan = FaultPlan::new().drop_tftp_transfer(2);
        if !run_network_boot_with_feature(
            Some((plan, stats.clone())),
            ContentFault::None,
            ExpectedOutcome::Fatal(McuError::ROM_COLD_BOOT_LOAD_IMAGE_ERROR),
            "test-network-boot-timeouts",
        ) {
            return;
        }
        assert!(stats.dropped(PacketKind::Tftp) > 0);
    }
}
