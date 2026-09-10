// Licensed under the Apache-2.0 license

//! Integration tests for the lwip-rs DHCPv6 (stateful) + TFTP over IPv6 example
//!
//! These tests require:
//! - TAP interface (tap0) to be set up with IPv6 (fd00:1234:5678::1/64)
//! - Ability to start dnsmasq (requires sudo without password)
//! - dnsmasq configured for stateful DHCPv6 with M flag in RA
//!
//! Run with: cargo test -p tests-integration test_lwip_dhcpv6_tftp -- --ignored --nocapture --test-threads=1

#[cfg(test)]
mod test {
    use caliptra_mcu_xtask::network::{build, server, server::ServerOptions, tap};
    use std::fs;
    use std::io::{self, Write};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::time::Duration;
    use tempfile::TempDir;

    // Mutex to ensure tests don't run in parallel (they share dnsmasq)
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Flush stdout to ensure output appears immediately
    fn flush_stdout() {
        let _ = io::stdout().flush();
    }

    /// Create test TFTP files in the given directory
    fn create_tftp_files(tftp_dir: &Path, boot_filename: &str, size: usize) -> Result<(), String> {
        let boot_file = tftp_dir.join(boot_filename);
        let mut file = fs::File::create(&boot_file)
            .map_err(|e| format!("Failed to create boot file: {}", e))?;

        // Write test content (sequential bytes for verification)
        let content: Vec<u8> = (0..size).map(|i| (i & 0xFF) as u8).collect();
        file.write_all(&content)
            .map_err(|e| format!("Failed to write boot file: {}", e))?;

        println!(
            "Created test boot file: {} ({} bytes)",
            boot_file.display(),
            content.len()
        );

        Ok(())
    }

    /// Verify downloaded file exists and matches expected content
    fn verify_download(filename: &str, expected_size: usize) -> Result<(), String> {
        let download_path = PathBuf::from("/tmp/tftp_downloads").join(filename);

        if !download_path.exists() {
            return Err(format!(
                "Downloaded file not found: {}",
                download_path.display()
            ));
        }

        let metadata = fs::metadata(&download_path)
            .map_err(|e| format!("Failed to get file metadata: {}", e))?;

        if metadata.len() != expected_size as u64 {
            return Err(format!(
                "Downloaded file size mismatch: expected {}, got {}",
                expected_size,
                metadata.len()
            ));
        }

        // Verify content (sequential bytes)
        let content = fs::read(&download_path)
            .map_err(|e| format!("Failed to read downloaded file: {}", e))?;

        for (i, byte) in content.iter().enumerate() {
            if *byte != (i & 0xFF) as u8 {
                return Err(format!(
                    "Content mismatch at byte {}: expected {}, got {}",
                    i,
                    i & 0xFF,
                    byte
                ));
            }
        }

        println!("Download verified: {} bytes", metadata.len());

        Ok(())
    }

    /// Integration test for DHCPv6 (stateful) + TFTP over IPv6 example
    ///
    /// This test is ignored by default because it requires:
    /// - Root privileges (sudo without password)
    /// - TAP interface with IPv6 configured
    /// - Network configuration
    #[test]
    fn test_lwip_dhcpv6_tftp_example() {
        // Acquire lock to prevent parallel execution with other lwip tests
        let _lock = TEST_LOCK.lock().unwrap();

        println!("\n=== Integration Test: lwIP DHCPv6 (Stateful) + TFTP/IPv6 Example ===\n");
        flush_stdout();

        // Check prerequisites using xtask utilities
        if !tap::has_sudo_access() {
            eprintln!("SKIP: No passwordless sudo access");
            eprintln!("Either run 'sudo -v' first or configure NOPASSWD in sudoers");
            return;
        }

        if let Err(error) = tap::setup("tap0", "192.168.100.1", true) {
            eprintln!("SKIP: Failed to configure TAP interface: {}", error);
            return;
        }

        if !server::is_installed() {
            eprintln!("SKIP: dnsmasq not installed");
            eprintln!("Run: cargo xtask network server install");
            return;
        }

        // Stop any existing dnsmasq
        if server::is_running() {
            println!("Stopping existing dnsmasq...");
            server::stop().expect("Failed to stop existing server");
        }

        // Create temp directory for TFTP files
        let tftp_dir = TempDir::new().expect("Failed to create temp directory");
        let tftp_path = tftp_dir.path().to_path_buf();
        println!("TFTP root: {}", tftp_path.display());
        flush_stdout();

        const BOOT_FILE: &str = "test_boot.bin";
        const FILE_SIZE: usize = 256;

        // Create test files
        create_tftp_files(&tftp_path, BOOT_FILE, FILE_SIZE).expect("Failed to create TFTP files");

        // Start dnsmasq with IPv6 enabled (stateful DHCPv6 mode)
        println!("Starting dnsmasq server with stateful DHCPv6...");
        let boot_file_url = format!("tftp://[fd00:1234:5678::1]/{}", BOOT_FILE);
        let server_options = ServerOptions {
            interface: "tap0".to_string(),
            tftp_root: Some(tftp_path.clone()),
            boot_file: BOOT_FILE.to_string(),
            // IPv6: stateful DHCPv6 (default ipv6_slaac=false sends M flag via RA)
            enable_ipv6: true,
            ipv6_slaac: false,
            // Send Boot File URL via DHCPv6 Option 59 (RFC 5970)
            dhcp6_boot_file_url: Some(boot_file_url.clone()),
            ..Default::default()
        };

        if let Err(e) = server::start(&server_options) {
            eprintln!("Failed to start dnsmasq: {}", e);
            panic!("Server startup failed: {}", e);
        }
        println!("dnsmasq started with stateful DHCPv6 (M flag in RA)");
        println!(
            "  DHCPv6 range: {} - {}",
            server_options.dhcp6_range_start, server_options.dhcp6_range_end
        );
        println!("  DHCPv6 Boot File URL: {}", boot_file_url);

        // Clean up any previous downloads
        let _ = fs::remove_file(format!("/tmp/tftp_downloads/{}", BOOT_FILE));

        // Run the IPv6 example application
        println!("\nRunning IPv6 example application...");
        let result = build::run_example_with_timeout(
            "caliptra-mcu-lwip-rs-example-ipv6",
            false,                         // debug build
            Some(Duration::from_secs(90)), // longer timeout for DHCPv6 (RA delay + Solicit)
            "tap0",
        );

        // Stop dnsmasq regardless of result
        println!("\nStopping dnsmasq...");
        let _ = server::stop();

        // Check result
        match result {
            Ok(output) => {
                println!("\n--- Example stdout ---");
                for line in String::from_utf8_lossy(&output.stdout).lines() {
                    println!("{}", line);
                }
                flush_stdout();

                if !output.stderr.is_empty() {
                    println!("\n--- Example stderr ---");
                    for line in String::from_utf8_lossy(&output.stderr).lines() {
                        println!("{}", line);
                    }
                    flush_stdout();
                }

                if !output.status.success() {
                    panic!("Example exited with non-zero status: {:?}", output.status);
                }

                // Verify the example received and parsed Option 59
                let stdout_str = String::from_utf8_lossy(&output.stdout);
                assert!(
                    stdout_str.contains("Boot File URL (Option 59)"),
                    "Example output should contain Boot File URL from Option 59"
                );
                assert!(
                    stdout_str.contains(BOOT_FILE),
                    "Example output should reference the boot file name"
                );

                // Verify download
                verify_download(BOOT_FILE, FILE_SIZE).expect("Download verification failed");

                println!("\n=== Test PASSED ===\n");
                flush_stdout();
            }
            Err(e) => {
                panic!("Example failed: {}", e);
            }
        }
    }
}
