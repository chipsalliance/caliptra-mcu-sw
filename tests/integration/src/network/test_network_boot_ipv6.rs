// Licensed under the Apache-2.0 license

//! Integration test for network-based boot over IPv6.
//!
//! The MCU ROM uses the NetworkImageProvider to download firmware images
//! (caliptra FW, SoC manifest, MCU runtime) from the Network CoP via the
//! boot-source protocol. The Network CoP fetches the images over stateful
//! DHCPv6 + TFTP/IPv6 using Boot File URL (Option 59).

#[cfg(test)]
mod test {
    use crate::test::{
        build_test_binaries, has_prebuilt_binaries, prebuilt_binaries, start_runtime_hw_model,
        TestBinaries, TestParams, TEST_LOCK,
    };
    use caliptra_mcu_builder::flash_image::{generate_image_info, FirmwareImage, FlashImage};
    use caliptra_mcu_emulator_periph::LinuxTapDevice;
    use caliptra_mcu_flash_image::{
        CALIPTRA_FMC_RT_IDENTIFIER, MCU_RT_IDENTIFIER, SOC_MANIFEST_IDENTIFIER,
    };
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_romtime::McuRomBootStatus;
    use std::sync::{Arc, Mutex};

    const TAP_INTERFACE: &str = "tap0";
    const TAP_IP_ADDR: &str = "192.168.100.1";
    const TAP_IPV6_SERVER: &str = "fd00:1234:5678::1";
    const TFTP_BOOT_FILENAME: &str = "toc.bin";

    /// Build a TFTP TOC and write individual firmware files to the TFTP root.
    ///
    /// The TOC uses `TFTP_IMAGE_MAGIC_NUMBER` and each entry contains the
    /// TFTP filename the Network CoP will use to download the image.
    fn write_tftp_content(
        tftp_dir: &std::path::Path,
        caliptra_fw: &[u8],
        soc_manifest: &[u8],
        mcu_runtime: &[u8],
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
            std::fs::write(tftp_dir.join(fname), data).expect("Failed to write firmware file");
        }

        let image_info = generate_image_info(images.clone());
        let flash_image = FlashImage::new(&images, &image_info);
        std::fs::write(
            tftp_dir.join(TFTP_BOOT_FILENAME),
            flash_image.to_toc_bytes(),
        )
        .expect("Failed to write TOC file");
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

    #[test]
    #[cfg_attr(feature = "fpga_realtime", ignore)]
    fn test_network_boot_ipv6() {
        use caliptra_mcu_xtask::network::{server, server::ServerOptions, tap};

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // --- Prerequisites ---
        if !tap::has_sudo_access() {
            eprintln!("SKIP: No passwordless sudo access");
            return;
        }
        if !tap::interface_exists(TAP_INTERFACE) {
            println!("TAP interface {} not found, setting up...", TAP_INTERFACE);
            if let Err(e) = tap::setup(TAP_INTERFACE, TAP_IP_ADDR, true) {
                eprintln!("Failed to set up TAP interface: {}", e);
                return;
            }
        }
        if !server::is_installed() {
            eprintln!("SKIP: dnsmasq not installed");
            return;
        }
        if server::is_running() {
            let _ = server::stop();
        }

        // --- Build firmware via the common test infrastructure ---
        // Use test-network-boot-ipv6 network ROM feature so the Network CoP
        // uses stateful DHCPv6 + TFTP/IPv6.
        let build_params = TestParams {
            feature: Some("test-network-boot"),
            rom_feature: Some("test-network-boot"),
            network_rom_feature: Some("test-network-boot-ipv6"),
            ..Default::default()
        };
        let binaries = get_test_binaries(&build_params);

        // --- Write TFTP content (TOC + firmware files) ---
        let tftp_dir = std::env::temp_dir().join("network-boot-ipv6-tftp-test");
        std::fs::create_dir_all(&tftp_dir).expect("Failed to create TFTP directory");

        write_tftp_content(
            &tftp_dir,
            &binaries.caliptra_fw,
            &binaries.soc_manifest,
            &binaries.mcu_runtime,
        );

        // --- Start dnsmasq with stateful DHCPv6 + TFTP ---
        let boot_file_url = format!("tftp://[{}]/{}", TAP_IPV6_SERVER, TFTP_BOOT_FILENAME);
        let server_options = ServerOptions {
            interface: TAP_INTERFACE.to_string(),
            enable_tftp: true,
            tftp_root: Some(tftp_dir.clone()),
            boot_file: TFTP_BOOT_FILENAME.to_string(),
            enable_ipv6: true,
            ipv6_slaac: false,
            dhcp6_boot_file_url: Some(boot_file_url),
            ..Default::default()
        };
        if let Err(e) = server::start(&server_options) {
            eprintln!("Failed to start dnsmasq: {}", e);
            let _ = std::fs::remove_dir_all(&tftp_dir);
            return;
        }

        // --- Open TAP device ---
        let tap_device = match LinuxTapDevice::open(TAP_INTERFACE) {
            Ok(tap) => Arc::new(Mutex::new(
                Box::new(tap) as Box<dyn caliptra_mcu_emulator_periph::TapDevice>
            )),
            Err(e) => {
                eprintln!("Failed to open TAP device: {}", e);
                let _ = server::stop();
                let _ = std::fs::remove_dir_all(&tftp_dir);
                return;
            }
        };

        // --- Launch emulator with network boot over IPv6 ---
        let mut hw = start_runtime_hw_model(TestParams {
            include_network_rom: true,
            rom_only: true,
            rom_feature: Some("test-network-boot"),
            feature: Some("test-network-boot"),
            network_rom_feature: Some("test-network-boot-ipv6"),
            network_boot: true,
            network_tap_device: Some(tap_device),
            ..Default::default()
        });

        assert!(hw.has_network_cpu(), "Network CPU should be present");

        // DHCPv6 (RA delay + Solicit/Reply) is slower than DHCPv4,
        // allow extra cycles and wall-clock time.
        const MAX_CYCLES: u64 = 10_000_000_000;
        const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(900);
        let deadline = std::time::Instant::now() + TIMEOUT;
        let mut last_net_len: usize = 0;

        hw.step_until(|m| {
            // Print new network CPU output as it arrives.
            if let Some(net_output) = m.network_uart_output() {
                if net_output.len() > last_net_len {
                    print!("{}", &net_output[last_net_len..]);
                    last_net_len = net_output.len();
                }
            }

            m.mci_fw_fatal_error().is_some()
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
        assert!(fatal.is_none(), "MCU ROM hit a fatal error: {:?}", fatal);
        let expected: u16 = McuRomBootStatus::ColdBootFlowComplete.into();
        assert_eq!(
            checkpoint, expected,
            "Expected checkpoint == ColdBootFlowComplete ({}), got {}",
            expected, checkpoint,
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
