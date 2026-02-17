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
}
