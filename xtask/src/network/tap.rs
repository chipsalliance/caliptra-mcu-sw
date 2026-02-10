// Licensed under the Apache-2.0 license

//! TAP interface management

use anyhow::{bail, Context, Result};
use std::process::Command;

/// IPv6 ULA prefix for the TAP network
const IPV6_PREFIX: &str = "fd00:1234:5678::1/64";

/// Setup TAP interface with IP addresses
pub fn setup(interface: &str, ipv4: &str, enable_ipv6: bool) -> Result<()> {
    println!("Setting up TAP interface: {}", interface);

    // Check if interface already exists
    if interface_exists(interface) {
        println!(
            "  Interface {} already exists, skipping creation",
            interface
        );
    } else {
        // Create TAP interface
        println!("  Creating TAP interface...");
        run_sudo("ip", &["tuntap", "add", "dev", interface, "mode", "tap"])?;
    }

    // Get current user for ownership
    let user = get_current_user();

    // Set ownership so non-root user can use it
    println!("  Setting ownership to user: {}", user);
    run_sudo(
        "ip",
        &[
            "tuntap", "add", "dev", interface, "mode", "tap", "user", &user,
        ],
    )
    .ok(); // Ignore error if already created

    // Bring up interface
    println!("  Bringing up interface...");
    run_sudo("ip", &["link", "set", "dev", interface, "up"])?;

    // Configure IPv4
    let ipv4_cidr = format!("{}/24", ipv4);
    println!("  Configuring IPv4: {}", ipv4_cidr);

    // Remove existing address first (ignore errors)
    run_sudo("ip", &["addr", "flush", "dev", interface]).ok();
    run_sudo("ip", &["addr", "add", &ipv4_cidr, "dev", interface])?;

    // Configure IPv6 if enabled
    if enable_ipv6 {
        println!("  Configuring IPv6: {}", IPV6_PREFIX);

        // Enable IPv6 on the interface
        let sysctl_path = format!("/proc/sys/net/ipv6/conf/{}/disable_ipv6", interface);
        run_sudo("sh", &["-c", &format!("echo 0 > {}", sysctl_path)]).ok();

        run_sudo("ip", &["-6", "addr", "add", IPV6_PREFIX, "dev", interface])?;
    }

    println!("  TAP interface {} is ready!", interface);

    // Show the configuration
    status(interface)?;

    Ok(())
}

/// Teardown TAP interface
pub fn teardown(interface: &str) -> Result<()> {
    println!("Tearing down TAP interface: {}", interface);

    if !interface_exists(interface) {
        println!("  Interface {} does not exist, nothing to do", interface);
        return Ok(());
    }

    // Bring down and delete interface
    println!("  Bringing down interface...");
    run_sudo("ip", &["link", "set", "dev", interface, "down"]).ok();

    println!("  Deleting interface...");
    run_sudo("ip", &["tuntap", "del", "dev", interface, "mode", "tap"])?;

    println!("  TAP interface {} removed", interface);

    Ok(())
}

/// Show TAP interface status
pub fn status(interface: &str) -> Result<()> {
    println!("\nTAP Interface Status: {}", interface);
    println!("{}", "=".repeat(40));

    if !interface_exists(interface) {
        println!("Interface {} does not exist", interface);
        return Ok(());
    }

    // Show interface details
    let output = Command::new("ip")
        .args(["addr", "show", "dev", interface])
        .output()
        .context("Failed to run ip command")?;

    if output.status.success() {
        println!("{}", String::from_utf8_lossy(&output.stdout));
    } else {
        println!("Failed to get interface status");
    }

    Ok(())
}

/// Check if network interface exists
pub fn interface_exists(interface: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{}", interface)).exists()
}

/// Check if passwordless sudo is available
#[allow(dead_code)] // Utility for tests
pub fn has_sudo_access() -> bool {
    Command::new("sudo")
        .args(["-n", "true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Get current user (the one who invoked the command)
fn get_current_user() -> String {
    std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "root".to_string())
}

/// Run a command with sudo
fn run_sudo(cmd: &str, args: &[&str]) -> Result<()> {
    let status = Command::new("sudo")
        .arg(cmd)
        .args(args)
        .status()
        .with_context(|| format!("Failed to execute: sudo {} {}", cmd, args.join(" ")))?;

    if !status.success() {
        bail!("Command failed: sudo {} {}", cmd, args.join(" "));
    }

    Ok(())
}
