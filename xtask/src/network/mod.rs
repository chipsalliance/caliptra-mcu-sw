// Licensed under the Apache-2.0 license

//! Network stack development tools
//!
//! Provides utilities for:
//! - Building network applications (lwip-rs, examples)
//! - Managing TAP interfaces
//! - Managing DHCP/TFTP servers (dnsmasq)
//! - Running example applications

use anyhow::Result;
use clap::Subcommand;
use std::path::PathBuf;

pub mod build;
pub mod server;
pub mod tap;

#[derive(Clone, Subcommand)]
pub enum NetworkCommands {
    /// Build network applications
    Build {
        /// Build in release mode
        #[arg(short, long)]
        release: bool,

        /// Build only lwip-rs library
        #[arg(long)]
        lib_only: bool,
    },

    /// Manage TAP network interface
    Tap {
        #[command(subcommand)]
        action: TapCommands,
    },

    /// Manage DHCP/TFTP server (dnsmasq)
    Server {
        #[command(subcommand)]
        action: ServerCommands,
    },

    /// Run a network application
    Run {
        /// Package name to run
        #[arg(short, long, default_value = "lwip-rs-example")]
        package: String,

        /// Build in release mode before running
        #[arg(short, long)]
        release: bool,
    },

    /// Full setup: tap + server start (uses sudo)
    Setup {
        /// TFTP root directory
        #[arg(short, long)]
        tftp_root: PathBuf,
    },

    /// Full teardown: server stop + tap teardown (uses sudo)
    Teardown,

    /// Build Network Coprocessor ROM
    RomBuild,
}

#[derive(Clone, Subcommand)]
pub enum TapCommands {
    /// Create and configure TAP interface (uses sudo)
    Setup {
        /// TAP interface name
        #[arg(short, long, default_value = "tap0")]
        interface: String,

        /// IPv4 address for TAP interface
        #[arg(long, default_value = "192.168.100.1")]
        ipv4: String,

        /// Enable IPv6
        #[arg(long, default_value = "true")]
        ipv6: bool,
    },

    /// Remove TAP interface (uses sudo)
    Teardown {
        /// TAP interface name
        #[arg(short, long, default_value = "tap0")]
        interface: String,
    },

    /// Show TAP interface status
    Status {
        /// TAP interface name
        #[arg(short, long, default_value = "tap0")]
        interface: String,
    },
}

#[derive(Clone, Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum ServerCommands {
    /// Install dnsmasq (DHCP/TFTP server)
    Install,

    /// Start DHCP/TFTP server (uses sudo)
    Start {
        /// TAP interface to bind to
        #[arg(short, long, default_value = "tap0")]
        interface: String,

        /// TFTP root directory
        #[arg(short, long)]
        tftp_root: PathBuf,

        /// Start of DHCPv4 address range
        #[arg(long)]
        dhcp4_range_start: Option<String>,

        /// End of DHCPv4 address range
        #[arg(long)]
        dhcp4_range_end: Option<String>,

        /// DHCPv4 lease time (e.g., "1h", "30m")
        #[arg(long)]
        dhcp4_lease_time: Option<String>,

        /// TFTP server address (DHCP option 66)
        #[arg(long)]
        tftp_server_addr: Option<String>,

        /// Boot file name (DHCP option 67)
        #[arg(long)]
        boot_file: Option<String>,

        /// Enable IPv6 (DHCPv6 + RA)
        #[arg(long)]
        enable_ipv6: Option<bool>,

        /// Start of DHCPv6 address range
        #[arg(long)]
        dhcp6_range_start: Option<String>,

        /// End of DHCPv6 address range
        #[arg(long)]
        dhcp6_range_end: Option<String>,

        /// DHCPv6 prefix length
        #[arg(long)]
        dhcp6_prefix_len: Option<u8>,

        /// DHCPv6 lease time
        #[arg(long)]
        dhcp6_lease_time: Option<String>,

        /// Enable TFTP server
        #[arg(long)]
        enable_tftp: Option<bool>,
    },

    /// Stop DHCP/TFTP server (uses sudo)
    Stop,

    /// Show server status
    Status,
}

/// Execute network commands
pub fn run(cmd: NetworkCommands) -> Result<()> {
    match cmd {
        NetworkCommands::Build { release, lib_only } => {
            build::build(release, lib_only)?;
        }

        NetworkCommands::Tap { action } => match action {
            TapCommands::Setup {
                interface,
                ipv4,
                ipv6,
            } => {
                tap::setup(&interface, &ipv4, ipv6)?;
            }
            TapCommands::Teardown { interface } => {
                tap::teardown(&interface)?;
            }
            TapCommands::Status { interface } => {
                tap::status(&interface)?;
            }
        },

        NetworkCommands::Server { action } => match action {
            ServerCommands::Install => {
                server::install()?;
            }
            ServerCommands::Start {
                interface,
                tftp_root,
                dhcp4_range_start,
                dhcp4_range_end,
                dhcp4_lease_time,
                tftp_server_addr,
                boot_file,
                enable_ipv6,
                dhcp6_range_start,
                dhcp6_range_end,
                dhcp6_prefix_len,
                dhcp6_lease_time,
                enable_tftp,
            } => {
                let mut options = server::ServerOptions {
                    interface: interface.clone(),
                    tftp_root: Some(tftp_root),
                    ..Default::default()
                };

                // Override defaults with any provided options
                if let Some(v) = dhcp4_range_start {
                    options.dhcp4_range_start = v;
                }
                if let Some(v) = dhcp4_range_end {
                    options.dhcp4_range_end = v;
                }
                if let Some(v) = dhcp4_lease_time {
                    options.dhcp4_lease_time = v;
                }
                if let Some(v) = tftp_server_addr {
                    options.tftp_server_addr = v;
                }
                if let Some(v) = boot_file {
                    options.boot_file = v;
                }
                if let Some(v) = enable_ipv6 {
                    options.enable_ipv6 = v;
                }
                if let Some(v) = dhcp6_range_start {
                    options.dhcp6_range_start = v;
                }
                if let Some(v) = dhcp6_range_end {
                    options.dhcp6_range_end = v;
                }
                if let Some(v) = dhcp6_prefix_len {
                    options.dhcp6_prefix_len = v;
                }
                if let Some(v) = dhcp6_lease_time {
                    options.dhcp6_lease_time = v;
                }
                if let Some(v) = enable_tftp {
                    options.enable_tftp = v;
                }

                server::start(&options)?;
            }
            ServerCommands::Stop => {
                server::stop()?;
            }
            ServerCommands::Status => {
                server::status()?;
            }
        },

        NetworkCommands::Run { package, release } => {
            build::run_example(&package, release)?;
        }

        NetworkCommands::Setup { tftp_root } => {
            println!("=== Full Setup ===");
            tap::setup("tap0", "192.168.100.1", true)?;

            let server_options = server::ServerOptions {
                tftp_root: Some(tftp_root),
                ..Default::default()
            };
            server::start(&server_options)?;
            println!("\nSetup complete! You can now run: cargo xtask network run");
        }

        NetworkCommands::Teardown => {
            println!("=== Full Teardown ===");
            server::stop()?;
            tap::teardown("tap0")?;
            println!("\nTeardown complete!");
        }

        NetworkCommands::RomBuild => {
            mcu_builder::network_rom_build()?;
        }
    }

    Ok(())
}
