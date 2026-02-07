// Licensed under the Apache-2.0 license

//! DHCP + TFTP Boot Test Application
//!
//! This application demonstrates lwIP functionality through Rust bindings:
//! 1. Initialize TAP network interface
//! 2. Obtain IP address via DHCP
//! 3. Download boot file via TFTP
//!
//! Prerequisites:
//!   - TAP interface created (tap0)
//!   - DHCP/TFTP server running (dnsmasq)
//!   - Set PRECONFIGURED_TAPIF=tap0

use std::env;
use std::ffi::c_void;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lwip_rs::sys;
use lwip_rs::{init, DhcpClient, Ipv4Addr, LwipError, NetIf, TftpClient, TftpStorageOps};

// Simple error wrapper since LwipError doesn't implement std::error::Error in no_std mode
#[derive(Debug)]
struct AppError(String);

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for AppError {}

impl From<LwipError> for AppError {
    fn from(e: LwipError) -> Self {
        AppError(format!("{}", e))
    }
}

/// Application state machine
#[derive(Debug, Clone, Copy, PartialEq)]
enum AppState {
    DhcpWait,
    DhcpDone,
    TftpStart,
    TftpInProgress,
    TftpDone,
    Error,
    Exit,
}

/// DHCP timeout in seconds
const DHCP_TIMEOUT_SECS: u64 = 30;

/// Signal handler flag
static SHOULD_EXIT: AtomicBool = AtomicBool::new(false);

// === TFTP Storage Implementation ===

static FILE_HANDLE: Mutex<Option<File>> = Mutex::new(None);

/// Open callback for file storage
fn storage_open(filename: &str) -> *mut c_void {
    let basename = Path::new(filename)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("download.bin");

    let output_dir = "/tmp/tftp_downloads";
    let _ = std::fs::create_dir_all(output_dir);

    let output_path = format!("{}/{}", output_dir, basename);

    match File::create(&output_path) {
        Ok(file) => {
            let mut handle = FILE_HANDLE.lock().unwrap();
            *handle = Some(file);
            1 as *mut c_void
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Write callback for file storage
fn storage_write(_handle: *mut c_void, data: &[u8]) -> bool {
    let mut file_handle = FILE_HANDLE.lock().unwrap();
    if let Some(ref mut file) = *file_handle {
        file.write_all(data).is_ok()
    } else {
        false
    }
}

/// Close callback for file storage
fn storage_close(_handle: *mut c_void) {
    let mut file_handle = FILE_HANDLE.lock().unwrap();
    *file_handle = None;
}

static STORAGE_OPS: TftpStorageOps = TftpStorageOps {
    open: storage_open,
    write: storage_write,
    close: storage_close,
};

fn main() {
    println!("========================================");
    println!("  DHCP + TFTP Boot Application (Rust)");
    println!("========================================");
    println!();

    // Setup signal handler
    ctrlc_handler();

    // Check environment
    if env::var("PRECONFIGURED_TAPIF").is_err() {
        eprintln!("[ERROR] PRECONFIGURED_TAPIF not set");
        eprintln!("  Run: export PRECONFIGURED_TAPIF=tap0");
        std::process::exit(1);
    }

    // Run the application
    if let Err(e) = run_app() {
        eprintln!("[ERROR] Application failed: {}", e);
        std::process::exit(1);
    }

    println!();
    println!("Application finished.");
}

fn run_app() -> Result<(), AppError> {
    // Initialize lwIP
    println!("[DHCP-TFTP] Initializing lwIP...");
    init();

    // Create network interface
    println!("[DHCP-TFTP] Adding TAP network interface...");
    let mut netif = NetIf::new_tap(Ipv4Addr::any(), Ipv4Addr::any(), Ipv4Addr::any())?;

    // Setup callbacks
    netif.set_status_callback(|_nif| {
        // Status change notification happens at C level
    });

    // Set as default and bring up
    netif.set_default();

    // Create IPv6 link-local address
    println!("[DHCP-TFTP] Creating IPv6 link-local address...");
    netif.create_ipv6_linklocal();

    // Bring interface up
    netif.set_up();
    netif.set_link_up();

    // Print MAC and link-local
    let mac = netif.mac_addr();
    println!(
        "[DHCP-TFTP] MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );

    if let Some(ip6) = netif.ipv6_addr(0) {
        println!("[DHCP-TFTP] IPv6 Link-local: {}", ip6);
    }

    println!("[DHCP-TFTP] Network interface initialized");

    // Start DHCP
    println!("[DHCP-TFTP] Starting DHCP client...");
    let mut dhcp = DhcpClient::new(&mut netif);
    dhcp.start()?;

    let dhcp_start_time = Instant::now();
    let mut state = AppState::DhcpWait;
    println!("[DHCP-TFTP] DHCP discovery started, waiting for response...");

    // TFTP client (created when needed)
    let mut tftp: Option<TftpClient> = None;
    let mut boot_file = String::new();
    let mut tftp_server = Ipv4Addr::any();

    // Main loop
    while !SHOULD_EXIT.load(Ordering::Relaxed)
        && state != AppState::Exit
        && state != AppState::Error
    {
        // Poll network
        netif.poll();
        sys::check_timeouts();

        match state {
            AppState::DhcpWait => {
                if dhcp.has_address() {
                    // Got address!
                    let ip = netif.ipv4_addr();
                    let mask = netif.ipv4_netmask();
                    let gw = netif.ipv4_gateway();

                    println!("[DHCP-TFTP] DHCP complete!");
                    println!("[DHCP-TFTP] IPv4 Address: {}", ip);
                    println!("[DHCP-TFTP] IPv4 Netmask: {}", mask);
                    println!("[DHCP-TFTP] IPv4 Gateway: {}", gw);

                    // Get boot file
                    if let Some(bf) = dhcp.boot_file() {
                        boot_file = bf;
                        println!("[DHCP-TFTP] Boot file: {}", boot_file);
                    } else {
                        println!("[DHCP-TFTP] No boot file specified");
                    }

                    // Get TFTP server
                    tftp_server = dhcp.tftp_server();
                    if !tftp_server.is_any() {
                        println!("[DHCP-TFTP] TFTP Server (siaddr): {}", tftp_server);
                    } else {
                        tftp_server = gw;
                        println!("[DHCP-TFTP] TFTP Server: using gateway");
                    }

                    state = AppState::DhcpDone;
                } else {
                    // Check timeout
                    if dhcp_start_time.elapsed() > Duration::from_secs(DHCP_TIMEOUT_SECS) {
                        eprintln!("[DHCP-TFTP] DHCP timeout!");
                        state = AppState::Error;
                    }
                }
            }

            AppState::DhcpDone => {
                state = AppState::TftpStart;
            }

            AppState::TftpStart => {
                if boot_file.is_empty() {
                    println!("[DHCP-TFTP] No boot file to download");
                    state = AppState::TftpDone;
                } else {
                    println!("[DHCP-TFTP] Starting TFTP download of '{}'...", boot_file);

                    let mut client = TftpClient::new(&STORAGE_OPS)?;
                    client.get(tftp_server, &boot_file)?;
                    println!("[DHCP-TFTP] TFTP transfer started");
                    tftp = Some(client);
                    state = AppState::TftpInProgress;
                }
            }

            AppState::TftpInProgress => {
                if let Some(ref client) = tftp {
                    if client.is_complete() {
                        if client.has_error() {
                            let (code, msg) = client.error().unwrap();
                            eprintln!("[DHCP-TFTP] TFTP error {}: {}", code, msg);
                            state = AppState::Error;
                        } else {
                            state = AppState::TftpDone;
                        }
                    }
                }
            }

            AppState::TftpDone => {
                let bytes = tftp.as_ref().map(|t| t.bytes_received()).unwrap_or(0);
                println!("[DHCP-TFTP] === Transfer Complete ===");
                println!(
                    "[DHCP-TFTP] File saved to: /tmp/tftp_downloads/{}",
                    boot_file.split('/').last().unwrap_or(&boot_file)
                );
                println!("[DHCP-TFTP] Total bytes: {}", bytes);
                state = AppState::Exit;
            }

            _ => {}
        }
    }

    // Cleanup
    if SHOULD_EXIT.load(Ordering::Relaxed) {
        println!("[DHCP-TFTP] Signal received, exiting...");
    }

    println!("[DHCP-TFTP] Cleaning up...");
    drop(tftp);
    drop(dhcp);
    drop(netif);

    if state == AppState::Error {
        Err(AppError("Application encountered an error".to_string()))
    } else {
        Ok(())
    }
}

fn ctrlc_handler() {
    // Simple signal handling - just set flag
    // In production, use the signal crate
    std::thread::spawn(|| {
        let _ = std::io::stdin().read_line(&mut String::new());
    });
}
