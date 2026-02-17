// Licensed under the Apache-2.0 license

//! DHCP/TFTP server (dnsmasq) management

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const PID_FILE: &str = "/tmp/dnsmasq-lwip-test.pid";
const LOG_FILE: &str = "/tmp/dnsmasq-lwip-test.log";
const LEASE_FILE: &str = "/tmp/dnsmasq-lwip-test.leases";

/// Server configuration options
#[derive(Debug, Clone)]
pub struct ServerOptions {
    /// Network interface to bind to
    pub interface: String,

    // DHCPv4 options
    /// Start of DHCPv4 address range
    pub dhcp4_range_start: String,
    /// End of DHCPv4 address range
    pub dhcp4_range_end: String,
    /// DHCPv4 lease time
    pub dhcp4_lease_time: String,
    /// TFTP server address (option 66)
    pub tftp_server_addr: String,
    /// Boot file name (option 67)
    pub boot_file: String,

    // DHCPv6 options
    /// Enable IPv6 (DHCPv6 + RA)
    pub enable_ipv6: bool,
    /// Start of DHCPv6 address range
    pub dhcp6_range_start: String,
    /// End of DHCPv6 address range
    pub dhcp6_range_end: String,
    /// DHCPv6 prefix length
    pub dhcp6_prefix_len: u8,
    /// DHCPv6 lease time
    pub dhcp6_lease_time: String,

    // TFTP options
    /// Enable TFTP server
    pub enable_tftp: bool,
    /// TFTP root directory (required when enable_tftp is true)
    pub tftp_root: Option<PathBuf>,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            interface: "tap0".to_string(),

            // DHCPv4 defaults
            dhcp4_range_start: "192.168.100.100".to_string(),
            dhcp4_range_end: "192.168.100.200".to_string(),
            dhcp4_lease_time: "1h".to_string(),
            tftp_server_addr: "192.168.100.1".to_string(),
            boot_file: "bootfile.bin".to_string(),

            // DHCPv6 defaults
            enable_ipv6: true,
            dhcp6_range_start: "fd00:1234:5678::100".to_string(),
            dhcp6_range_end: "fd00:1234:5678::1ff".to_string(),
            dhcp6_prefix_len: 64,
            dhcp6_lease_time: "1h".to_string(),

            // TFTP defaults
            enable_tftp: true,
            tftp_root: None,
        }
    }
}

/// Install dnsmasq server
pub fn install() -> Result<()> {
    println!("Installing dnsmasq...");

    // Check if already installed
    if Command::new("which")
        .arg("dnsmasq")
        .output()?
        .status
        .success()
    {
        println!("  dnsmasq is already installed");
        return Ok(());
    }

    // Detect package manager and install
    if Command::new("which")
        .arg("apt-get")
        .output()?
        .status
        .success()
    {
        println!("  Using apt-get to install dnsmasq...");
        let status = Command::new("sudo").args(["apt-get", "update"]).status()?;
        if !status.success() {
            bail!("Failed to update apt");
        }

        let status = Command::new("sudo")
            .args(["apt-get", "install", "-y", "dnsmasq"])
            .status()?;
        if !status.success() {
            bail!("Failed to install dnsmasq");
        }
    } else if Command::new("which").arg("dnf").output()?.status.success() {
        println!("  Using dnf to install dnsmasq...");
        let status = Command::new("sudo")
            .args(["dnf", "install", "-y", "dnsmasq"])
            .status()?;
        if !status.success() {
            bail!("Failed to install dnsmasq");
        }
    } else if Command::new("which")
        .arg("pacman")
        .output()?
        .status
        .success()
    {
        println!("  Using pacman to install dnsmasq...");
        let status = Command::new("sudo")
            .args(["pacman", "-S", "--noconfirm", "dnsmasq"])
            .status()?;
        if !status.success() {
            bail!("Failed to install dnsmasq");
        }
    } else {
        bail!(
            "Could not detect package manager. Please install dnsmasq manually:\n\
             - Debian/Ubuntu: sudo apt-get install dnsmasq\n\
             - Fedora/RHEL: sudo dnf install dnsmasq\n\
             - Arch: sudo pacman -S dnsmasq"
        );
    }

    println!("  dnsmasq installed successfully!");
    Ok(())
}

/// Start DHCP/TFTP server with the given options
pub fn start(options: &ServerOptions) -> Result<()> {
    println!("Starting DHCP/TFTP server on {}...", options.interface);

    // Check if already running
    if is_running() {
        println!("  Server is already running (PID file exists)");
        return Ok(());
    }

    // Check if dnsmasq is installed
    if !Command::new("which")
        .arg("dnsmasq")
        .output()?
        .status
        .success()
    {
        bail!("dnsmasq is not installed. Run: cargo xtask server install");
    }

    // Setup TFTP directory (only if TFTP is enabled)
    let tftp_dir = if options.enable_tftp {
        let dir = options.tftp_root.as_ref().ok_or_else(|| {
            anyhow::anyhow!("tftp_root must be specified when enable_tftp is true")
        })?;
        // Create directory first
        fs::create_dir_all(dir)?;
        // Convert to canonical (absolute, clean) path for dnsmasq
        let abs_dir = dir.canonicalize()?;
        println!("  TFTP root: {}", abs_dir.display());

        // Create sample boot file
        let bootfile = abs_dir.join(&options.boot_file);
        if !bootfile.exists() {
            println!("  Creating sample boot file...");
            fs::write(&bootfile, b"Sample boot file for TFTP testing\n")?;
        }
        Some(abs_dir)
    } else {
        None
    };

    // Build dnsmasq arguments
    let mut args = vec![
        format!("--interface={}", options.interface),
        "--bind-interfaces".to_string(),
        "--except-interface=lo".to_string(),
        // Disable DNS server (port 53) to avoid conflicts with systemd-resolved
        "--port=0".to_string(),
        // Disable pre-allocation ping/ARP check for faster DHCP response
        "--no-ping".to_string(),
        // DHCPv4
        format!(
            "--dhcp-range={},{},{}",
            options.dhcp4_range_start, options.dhcp4_range_end, options.dhcp4_lease_time
        ),
    ];

    // Only add TFTP-related DHCP options if TFTP is enabled and boot_file is non-empty
    // Empty --dhcp-option=67, causes dnsmasq to segfault on some systems
    if options.enable_tftp && !options.boot_file.is_empty() {
        args.push(format!("--dhcp-option=66,{}", options.tftp_server_addr)); // TFTP server
        args.push(format!("--dhcp-option=67,{}", options.boot_file)); // Boot file name
    }

    // DHCPv6 options (if enabled)
    if options.enable_ipv6 {
        args.push(format!(
            "--dhcp-range={},{},{},{}",
            options.dhcp6_range_start,
            options.dhcp6_range_end,
            options.dhcp6_prefix_len,
            options.dhcp6_lease_time
        ));
        args.push("--enable-ra".to_string());
    }

    // TFTP options (if enabled)
    if let Some(ref dir) = tftp_dir {
        args.push("--enable-tftp".to_string());
        args.push(format!("--tftp-root={}", dir.display()));
    }

    // Daemon settings - use --no-daemon to avoid fork-related crashes on WSL2
    // We spawn the process in background ourselves
    args.extend([
        "--no-daemon".to_string(),
        format!("--pid-file={}", PID_FILE),
        format!("--log-facility={}", LOG_FILE),
        format!("--dhcp-leasefile={}", LEASE_FILE),
        "--user=root".to_string(),
        "--log-dhcp".to_string(),
        "--log-queries".to_string(),
    ]);

    // Convert to &str references
    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    println!("  Starting dnsmasq...");

    // Start dnsmasq with sudo in background (since we use --no-daemon)
    // Use setsid to detach from controlling terminal to prevent terminal corruption
    let child = Command::new("sudo")
        .arg("setsid")
        .arg("--fork")
        .arg("dnsmasq")
        .args(&args_ref)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("Failed to start dnsmasq")?;

    let pid = child.id();

    // Write PID file ourselves since dnsmasq with --no-daemon doesn't write it immediately
    fs::write(PID_FILE, format!("{}", pid)).ok();

    // Brief delay to allow dnsmasq to fully start
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Verify dnsmasq is running
    if let Some(running_pid) = get_dnsmasq_pid() {
        println!("  Server started (PID: {})", running_pid);
    } else {
        // Try to read from our PID file
        println!("  Server started (PID: {})", pid);
    }
    println!(
        "\n  DHCP range: {} - {}",
        options.dhcp4_range_start, options.dhcp4_range_end
    );
    println!("  TFTP server: {}", options.tftp_server_addr);
    println!("  Boot file: {}", options.boot_file);

    Ok(())
}

/// Stop DHCP/TFTP server
pub fn stop() -> Result<()> {
    println!("Stopping DHCP/TFTP server...");

    if !is_running() {
        println!("  Server is not running");
        return Ok(());
    }

    // Get dnsmasq PID and kill it
    if let Some(pid) = get_dnsmasq_pid() {
        println!("  Killing dnsmasq (PID: {})...", pid);
        let _ = Command::new("sudo").args(["kill", &pid]).status();
    }

    // Also try pkill as backup
    let _ = Command::new("sudo")
        .args(["pkill", "-x", "dnsmasq"])
        .status();

    // Clean up files
    let _ = fs::remove_file(PID_FILE);
    let _ = fs::remove_file(LEASE_FILE);

    println!("  Server stopped");

    Ok(())
}

/// Show server status
pub fn status() -> Result<()> {
    println!("\nDHCP/TFTP Server Status");
    println!("{}", "=".repeat(40));

    if is_running() {
        if let Some(pid) = get_dnsmasq_pid() {
            println!("Status: Running (PID: {})", pid);
        } else {
            println!("Status: Running");
        }

        // Show leases if any
        if let Ok(leases) = fs::read_to_string(LEASE_FILE) {
            if !leases.is_empty() {
                println!("\nActive Leases:");
                for line in leases.lines() {
                    println!("  {}", line);
                }
            }
        }
    } else {
        println!("Status: Not running");
    }

    Ok(())
}

/// Check if dnsmasq is installed
#[allow(dead_code)] // Used by tests-integration
pub fn is_installed() -> bool {
    Command::new("which")
        .arg("dnsmasq")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if server is running
pub fn is_running() -> bool {
    // First check if PID file exists and process is alive
    if let Ok(pid_str) = fs::read_to_string(PID_FILE) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            if std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                return true;
            }
        }
    }

    // Fallback: check if dnsmasq is running using pgrep
    if let Ok(output) = Command::new("pgrep").arg("-x").arg("dnsmasq").output() {
        if output.status.success() && !output.stdout.is_empty() {
            return true;
        }
    }
    false
}

/// Get the PID of the running dnsmasq process
fn get_dnsmasq_pid() -> Option<String> {
    // First try the PID file
    if let Ok(pid_str) = fs::read_to_string(PID_FILE) {
        let pid = pid_str.trim();
        if !pid.is_empty() {
            // Verify process exists
            if std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                return Some(pid.to_string());
            }
        }
    }

    // Fallback to pgrep
    if let Ok(output) = Command::new("pgrep").arg("-x").arg("dnsmasq").output() {
        if output.status.success() {
            let pids = String::from_utf8_lossy(&output.stdout);
            return pids.lines().next().map(|s| s.to_string());
        }
    }
    None
}
