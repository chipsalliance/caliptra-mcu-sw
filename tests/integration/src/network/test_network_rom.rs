// Licensed under the Apache-2.0 license

//! Integration tests for the Network Coprocessor CPU.
//!
//! These tests verify that the Network Coprocessor can boot and execute code correctly.
//! The Network CPU is a dedicated RISC-V coprocessor that runs alongside the MCU and Caliptra.

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use emulator_periph::LinuxTapDevice;
    use mcu_hw_model::McuHwModel;
    use std::sync::{Arc, Mutex};

    #[test]
    #[cfg_attr(feature = "fpga_realtime", ignore)]
    fn test_network_cpu_rom_start() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Create the hardware model with network ROM using start_runtime_hw_model
        let mut hw = start_runtime_hw_model(TestParams {
            include_network_rom: true,
            rom_only: true, // Don't wait for full runtime boot
            ..Default::default()
        });

        // Verify network CPU was initialized
        assert!(
            hw.has_network_cpu(),
            "Network CPU should be initialized when include_network_rom is true"
        );

        // Run the model until the network CPU prints the ROM start message
        const MAX_CYCLES: u64 = 200_000;
        hw.step_until(|m| {
            if m.cycle_count() >= MAX_CYCLES {
                return true;
            }

            // Check if network CPU has printed the ROM start message
            if let Some(output) = m.network_uart_output() {
                if output.contains("Network Coprocessor ROM Started!") {
                    return true;
                }
            }
            false
        });

        // Check the network CPU UART output
        let output = hw
            .network_uart_output()
            .expect("Network CPU should have UART output");
        println!("Network CPU UART output:\n{}", output);

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Full DHCP test with dnsmasq server
    #[test]
    #[cfg_attr(feature = "fpga_realtime", ignore)]
    fn test_network_rom_dhcp_with_server() {
        use xtask::network::{server, server::ServerOptions, tap};

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        println!("\n=== Integration Test: Network ROM DHCP Discovery ===\n");

        // Check prerequisites
        if !tap::has_sudo_access() {
            eprintln!("SKIP: No passwordless sudo access");
            return;
        }

        if !tap::interface_exists("tap0") {
            println!("TAP interface tap0 not found, setting up...");
            if let Err(e) = tap::setup("tap0", "192.168.100.1", true) {
                eprintln!("Failed to set up TAP interface: {}", e);
                return;
            }
        }

        if !server::is_installed() {
            eprintln!("SKIP: dnsmasq not installed");
            return;
        }

        // Stop any existing dnsmasq
        if server::is_running() {
            println!("Stopping existing dnsmasq...");
            let _ = server::stop();
        }

        // Start dnsmasq (DHCP only, no TFTP needed)
        println!("Starting dnsmasq server...");
        let server_options = ServerOptions {
            interface: "tap0".to_string(),
            enable_tftp: false,
            tftp_root: None,
            boot_file: String::new(),
            ..Default::default()
        };

        if let Err(e) = server::start(&server_options) {
            eprintln!("Failed to start dnsmasq: {}", e);
            return;
        }
        println!("dnsmasq started successfully");

        // Create TAP device for the hardware model
        let tap_device = match LinuxTapDevice::open("tap0") {
            Ok(tap) => Arc::new(Mutex::new(
                Box::new(tap) as Box<dyn emulator_periph::TapDevice>
            )),
            Err(e) => {
                eprintln!("Failed to open TAP device: {}", e);
                let _ = server::stop();
                return;
            }
        };
        println!("TAP device opened successfully");

        // Create the hardware model with network ROM and TAP device
        let mut hw = start_runtime_hw_model(TestParams {
            include_network_rom: true,
            rom_only: true,
            network_tap_device: Some(tap_device),
            network_rom_feature: Some("test-network-rom-dhcp-discover"),
            ..Default::default()
        });

        // Accumulate all UART output from the network CPU
        let mut all_output = String::new();

        // Run until DHCP completes or times out
        // Note: dnsmasq may take 3+ seconds to respond due to ARP checks,
        // so we need many cycles since the emulator runs faster than real time
        const MAX_CYCLES: u64 = 50_000_000;
        hw.step_until(|m| {
            if m.cycle_count() >= MAX_CYCLES {
                return true;
            }

            if let Some(output) = m.network_uart_output() {
                // Check for DHCP success or timeout
                if output.contains("DHCP discovery successful!")
                    || output.contains("DHCP discovery timed out")
                {
                    return true;
                }
            }
            false
        });

        // Stop dnsmasq
        println!("Stopping dnsmasq...");
        let _ = server::stop();

        // Get any remaining output
        if let Some(output) = hw.network_uart_output() {
            all_output.push_str(&output);
        }
        println!("All Network CPU UART output:\n{}", all_output);

        // Verify DHCP discovery ran
        assert!(
            all_output.contains("Starting DHCP discovery"),
            "DHCP discovery should start"
        );

        // Verify we received a DHCP OFFER from dnsmasq
        assert!(
            all_output.contains("DHCP OFFER received!"),
            "Should receive DHCP OFFER from dnsmasq"
        );

        // Verify DHCP discovery succeeded
        assert!(
            all_output.contains("DHCP discovery successful!"),
            "DHCP discovery should succeed"
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Full DHCP test using lwIP stack with dnsmasq server
    #[test]
    #[cfg_attr(feature = "fpga_realtime", ignore)]
    fn test_network_rom_lwip_dhcp_with_server() {
        use xtask::network::{server, server::ServerOptions, tap};

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        println!("\n=== Integration Test: Network ROM lwIP DHCP Discovery ===\n");

        // Check prerequisites
        if !tap::has_sudo_access() {
            eprintln!("SKIP: No passwordless sudo access");
            return;
        }

        if !tap::interface_exists("tap0") {
            println!("TAP interface tap0 not found, setting up...");
            if let Err(e) = tap::setup("tap0", "192.168.100.1", true) {
                eprintln!("Failed to set up TAP interface: {}", e);
                return;
            }
        }

        if !server::is_installed() {
            eprintln!("SKIP: dnsmasq not installed");
            return;
        }

        // Stop any existing dnsmasq
        if server::is_running() {
            println!("Stopping existing dnsmasq...");
            let _ = server::stop();
        }

        // Start dnsmasq (DHCP only, no TFTP needed)
        println!("Starting dnsmasq server...");
        let server_options = ServerOptions {
            interface: "tap0".to_string(),
            enable_tftp: false,
            tftp_root: None,
            boot_file: String::new(),
            ..Default::default()
        };

        if let Err(e) = server::start(&server_options) {
            eprintln!("Failed to start dnsmasq: {}", e);
            return;
        }
        println!("dnsmasq started successfully");

        // Create TAP device for the hardware model
        let tap_device = match LinuxTapDevice::open("tap0") {
            Ok(tap) => Arc::new(Mutex::new(
                Box::new(tap) as Box<dyn emulator_periph::TapDevice>
            )),
            Err(e) => {
                eprintln!("Failed to open TAP device: {}", e);
                let _ = server::stop();
                return;
            }
        };
        println!("TAP device opened successfully");

        // Create the hardware model with network ROM and TAP device
        // Uses the lwIP-based DHCP test feature
        let mut hw = start_runtime_hw_model(TestParams {
            include_network_rom: true,
            rom_only: true,
            network_tap_device: Some(tap_device),
            network_rom_feature: Some("test-network-rom-lwip-dhcp"),
            ..Default::default()
        });

        // Accumulate all UART output from the network CPU
        let mut all_output = String::new();

        // Run until DHCP completes or times out
        const MAX_CYCLES: u64 = 50_000_000;
        hw.step_until(|m| {
            if m.cycle_count() >= MAX_CYCLES {
                return true;
            }

            if let Some(output) = m.network_uart_output() {
                if output.contains("DHCP discovery successful!")
                    || output.contains("DHCP discovery timed out")
                {
                    return true;
                }
            }
            false
        });

        // Stop dnsmasq
        println!("Stopping dnsmasq...");
        let _ = server::stop();

        // Get any remaining output
        if let Some(output) = hw.network_uart_output() {
            all_output.push_str(&output);
        }
        println!("All Network CPU UART output:\n{}", all_output);

        // Verify lwIP DHCP discovery ran
        assert!(
            all_output.contains("Starting DHCP discovery"),
            "DHCP discovery should start"
        );

        // Verify we received a DHCP address via lwIP
        assert!(
            all_output.contains("DHCP OFFER received!"),
            "Should receive DHCP OFFER from dnsmasq via lwIP"
        );

        // Verify DHCP discovery succeeded
        assert!(
            all_output.contains("DHCP discovery successful!"),
            "DHCP discovery should succeed"
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Full DHCPv6 test using lwIP stack with dnsmasq server
    #[test]
    #[cfg_attr(feature = "fpga_realtime", ignore)]
    fn test_network_rom_lwip_dhcpv6_with_server() {
        use xtask::network::{server, server::ServerOptions, tap};

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        println!("\n=== Integration Test: Network ROM lwIP DHCPv6 Discovery ===\n");

        // Check prerequisites
        if !tap::has_sudo_access() {
            eprintln!("SKIP: No passwordless sudo access");
            return;
        }

        if !tap::interface_exists("tap0") {
            println!("TAP interface tap0 not found, setting up...");
            if let Err(e) = tap::setup("tap0", "192.168.100.1", true) {
                eprintln!("Failed to set up TAP interface: {}", e);
                return;
            }
        }

        if !server::is_installed() {
            eprintln!("SKIP: dnsmasq not installed");
            return;
        }

        // Stop any existing dnsmasq
        if server::is_running() {
            println!("Stopping existing dnsmasq...");
            let _ = server::stop();
        }

        // Start dnsmasq with IPv6 SLAAC + stateless DHCPv6 mode
        println!("Starting dnsmasq server with IPv6 SLAAC...");
        let server_options = ServerOptions {
            interface: "tap0".to_string(),
            enable_tftp: false,
            tftp_root: None,
            boot_file: String::new(),
            enable_ipv6: true,
            ipv6_slaac: true,
            ..Default::default()
        };

        if let Err(e) = server::start(&server_options) {
            eprintln!("Failed to start dnsmasq: {}", e);
            return;
        }
        println!("dnsmasq started successfully with IPv6 SLAAC + stateless DHCPv6");

        // Create TAP device for the hardware model
        let tap_device = match LinuxTapDevice::open("tap0") {
            Ok(tap) => Arc::new(Mutex::new(
                Box::new(tap) as Box<dyn emulator_periph::TapDevice>
            )),
            Err(e) => {
                eprintln!("Failed to open TAP device: {}", e);
                let _ = server::stop();
                return;
            }
        };
        println!("TAP device opened successfully");

        // Create the hardware model with network ROM and TAP device
        // Uses the lwIP DHCPv6 test feature
        let mut hw = start_runtime_hw_model(TestParams {
            include_network_rom: true,
            rom_only: true,
            network_tap_device: Some(tap_device),
            network_rom_feature: Some("test-network-rom-lwip-dhcp6"),
            ..Default::default()
        });

        // Accumulate all UART output from the network CPU
        let mut all_output = String::new();

        // Run until DHCPv6 completes or times out
        const MAX_CYCLES: u64 = 50_000_000;
        hw.step_until(|m| {
            if m.cycle_count() >= MAX_CYCLES {
                return true;
            }

            if let Some(output) = m.network_uart_output() {
                if output.contains("DHCPv6 discovery successful!")
                    || output.contains("DHCPv6 discovery timed out")
                {
                    return true;
                }
            }
            false
        });

        // Stop dnsmasq
        println!("Stopping dnsmasq...");
        let _ = server::stop();

        // Get any remaining output
        if let Some(output) = hw.network_uart_output() {
            all_output.push_str(&output);
        }
        println!("All Network CPU UART output:\n{}", all_output);

        // Verify stateless DHCPv6 discovery ran
        assert!(
            all_output.contains("Enabling stateless DHCPv6"),
            "Stateless DHCPv6 should be enabled"
        );

        // Verify we received an IPv6 address via SLAAC
        assert!(
            all_output.contains("IPv6 SLAAC address received!"),
            "Should receive IPv6 address from SLAAC via lwIP"
        );

        // Verify DHCPv6 discovery succeeded
        assert!(
            all_output.contains("DHCPv6 discovery successful!"),
            "DHCPv6 discovery should succeed"
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Full DHCP + TFTP download test using lwIP stack with dnsmasq server
    #[test]
    #[cfg_attr(feature = "fpga_realtime", ignore)]
    fn test_network_rom_lwip_tftp_download() {
        use std::io::Write;
        use xtask::network::{server, server::ServerOptions, tap};

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        println!("\n=== Integration Test: Network ROM lwIP DHCP + TFTP Download ===\n");

        // Check prerequisites
        if !tap::has_sudo_access() {
            eprintln!("SKIP: No passwordless sudo access");
            return;
        }

        if !tap::interface_exists("tap0") {
            println!("TAP interface tap0 not found, setting up...");
            if let Err(e) = tap::setup("tap0", "192.168.100.1", true) {
                eprintln!("Failed to set up TAP interface: {}", e);
                return;
            }
        }

        if !server::is_installed() {
            eprintln!("SKIP: dnsmasq not installed");
            return;
        }

        // Stop any existing dnsmasq
        if server::is_running() {
            println!("Stopping existing dnsmasq...");
            let _ = server::stop();
        }

        // Create temp directory with pattern file for TFTP
        let tftp_dir = std::env::temp_dir().join("lwip-tftp-test");
        std::fs::create_dir_all(&tftp_dir).expect("Failed to create TFTP directory");

        // Generate the pattern file: byte[i] = (i & 0xFF)
        let boot_filename = "pattern.bin";
        let pattern_file = tftp_dir.join(boot_filename);
        {
            let mut f = std::fs::File::create(&pattern_file).expect("Failed to create pattern file");
            let data: Vec<u8> = (0..4096u32).map(|i| (i & 0xFF) as u8).collect();
            f.write_all(&data).expect("Failed to write pattern file");
        }
        println!("Created pattern file: {} ({} bytes)", pattern_file.display(), 4096);

        // Start dnsmasq with DHCP + TFTP enabled
        println!("Starting dnsmasq server with TFTP...");
        let server_options = ServerOptions {
            interface: "tap0".to_string(),
            enable_tftp: true,
            tftp_root: Some(tftp_dir.clone()),
            boot_file: boot_filename.to_string(),
            ..Default::default()
        };

        if let Err(e) = server::start(&server_options) {
            eprintln!("Failed to start dnsmasq: {}", e);
            let _ = std::fs::remove_dir_all(&tftp_dir);
            return;
        }
        println!("dnsmasq started successfully with TFTP");

        // Create TAP device for the hardware model
        let tap_device = match LinuxTapDevice::open("tap0") {
            Ok(tap) => Arc::new(Mutex::new(
                Box::new(tap) as Box<dyn emulator_periph::TapDevice>
            )),
            Err(e) => {
                eprintln!("Failed to open TAP device: {}", e);
                let _ = server::stop();
                let _ = std::fs::remove_dir_all(&tftp_dir);
                return;
            }
        };
        println!("TAP device opened successfully");

        // Create the hardware model with network ROM and TAP device
        let mut hw = start_runtime_hw_model(TestParams {
            include_network_rom: true,
            rom_only: true,
            network_tap_device: Some(tap_device),
            network_rom_feature: Some("test-network-rom-lwip-tftp"),
            ..Default::default()
        });

        // Accumulate all UART output from the network CPU
        let mut all_output = String::new();

        // TFTP needs the network CPU to run through DHCP + TFTP phases.
        const MAX_CYCLES: u64 = 40_000_000;
        hw.step_until(|m| {
            if m.cycle_count() >= MAX_CYCLES {
                return true;
            }

            if let Some(output) = m.network_uart_output() {
                if output.contains("TFTP download successful!")
                    || output.contains("TFTP download timed out")
                    || output.contains("DHCP discovery timed out")
                    || output.contains("VERIFY FAIL")
                    || output.contains("No boot file name")
                    || output.contains("Pattern verification FAILED!")
                    || output.contains("TFTP transfer error!")
                    || output.contains("Unexpected file size")
                    || output.contains("TFTP error")
                    || output.contains("Failed to start TFTP")
                {
                    return true;
                }
            }
            false
        });

        // Stop dnsmasq and clean up
        println!("Stopping dnsmasq...");
        let _ = server::stop();
        let _ = std::fs::remove_dir_all(&tftp_dir);

        // Get any remaining output
        if let Some(output) = hw.network_uart_output() {
            all_output.push_str(&output);
        }
        println!("All Network CPU UART output:\n{}", all_output);

        // Verify DHCP phase worked
        assert!(
            all_output.contains("DHCP OFFER received!"),
            "Should receive DHCP OFFER from dnsmasq"
        );

        // Verify TFTP download started
        assert!(
            all_output.contains("Starting TFTP download"),
            "TFTP download should start"
        );

        // Verify no pattern verification failures
        assert!(
            !all_output.contains("VERIFY FAIL"),
            "Pattern verification should not fail"
        );

        // Verify TFTP download succeeded
        assert!(
            all_output.contains("TFTP download successful!"),
            "TFTP download should succeed"
        );

        // Verify pattern verification passed
        assert!(
            all_output.contains("Pattern verification passed!"),
            "Pattern verification should pass"
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
