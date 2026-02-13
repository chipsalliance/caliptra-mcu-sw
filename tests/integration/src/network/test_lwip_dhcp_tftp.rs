// Licensed under the Apache-2.0 license

//! Integration tests for the lwip-rs DHCP+TFTP example application
//!
//! These tests require:
//! - TAP interface (tap0) to be set up
//! - Ability to start dnsmasq (requires sudo without password)
//!
//! Run with: cargo test -p tests-integration test_lwip_dhcp_tftp -- --ignored --nocapture --test-threads=1
//! (--test-threads=1 is needed because tests share the dnsmasq server)

#[cfg(test)]
mod test {
    use std::fs;
    use std::io::{self, Write};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;
    use xtask::network::{build, server, server::ServerOptions, tap};

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

    /// Integration test for DHCP + TFTP example
    ///
    /// This test is ignored by default because it requires:
    /// - Root privileges (sudo without password)
    /// - TAP interface to be set up
    /// - Network configuration
    #[test]
    fn test_lwip_dhcp_tftp_example() {
        // Acquire lock to prevent parallel execution with other lwip tests
        let _lock = TEST_LOCK.lock().unwrap();

        println!("\n=== Integration Test: lwIP DHCP + TFTP Example ===\n");
        flush_stdout();

        // Check prerequisites using xtask utilities
        if !tap::has_sudo_access() {
            eprintln!("SKIP: No passwordless sudo access");
            eprintln!("Either run 'sudo -v' first or configure NOPASSWD in sudoers");
            return;
        }

        if !tap::interface_exists("tap0") {
            eprintln!("SKIP: TAP interface tap0 not found");
            eprintln!("Run: cargo xtask network tap setup");
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

        // Start dnsmasq using xtask server module
        println!("Starting dnsmasq server...");
        let server_options = ServerOptions {
            interface: "tap0".to_string(),
            tftp_root: Some(tftp_path.clone()),
            boot_file: BOOT_FILE.to_string(),
            ..Default::default()
        };

        if let Err(e) = server::start(&server_options) {
            eprintln!("Failed to start dnsmasq: {}", e);
            panic!("Server startup failed: {}", e);
        }
        println!("dnsmasq started successfully");

        // Clean up any previous downloads
        let _ = fs::remove_file(format!("/tmp/tftp_downloads/{}", BOOT_FILE));

        // Run the example using xtask build module
        println!("\nRunning example application...");
        let result = build::run_example_with_timeout(
            "lwip-rs-example",
            false, // debug build
            Some(Duration::from_secs(60)),
            "tap0",
        );

        // Stop dnsmasq regardless of result
        println!("\nStopping dnsmasq...");
        let _ = server::stop();

        // Check result
        match result {
            Ok(output) => {
                println!("\n--- Example stdout ---");
                // Print each line separately to ensure proper formatting
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

    /// Test that verifies server can start and stop
    #[test]
    fn test_lwip_server_lifecycle() {
        // Acquire lock to prevent parallel execution with other lwip tests
        let _lock = TEST_LOCK.lock().unwrap();

        println!("\n=== Test: Server Lifecycle ===\n");
        flush_stdout();

        if !tap::has_sudo_access() {
            eprintln!("SKIP: No passwordless sudo access");
            return;
        }

        if !tap::interface_exists("tap0") {
            eprintln!("SKIP: TAP interface tap0 not found");
            return;
        }

        if !server::is_installed() {
            eprintln!("SKIP: dnsmasq not installed");
            return;
        }

        // Stop any existing
        if server::is_running() {
            server::stop().expect("Failed to stop existing server");
        }

        // Create temp directory
        let tftp_dir = TempDir::new().expect("Failed to create temp directory");

        // Start using xtask
        println!("Starting server...");
        flush_stdout();
        let options = ServerOptions {
            tftp_root: Some(tftp_dir.path().to_path_buf()),
            ..Default::default()
        };
        server::start(&options).expect("Failed to start server");
        assert!(server::is_running(), "Server should be running after start");

        // Stop using xtask
        println!("Stopping server...");
        flush_stdout();
        server::stop().expect("Failed to stop server");

        // Give it time
        thread::sleep(Duration::from_millis(500));
        assert!(
            !server::is_running(),
            "Server should not be running after stop"
        );

        println!("\n=== Test PASSED ===\n");
        flush_stdout();
    }
}
