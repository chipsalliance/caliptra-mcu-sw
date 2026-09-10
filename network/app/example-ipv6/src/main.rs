// Licensed under the Apache-2.0 license

//! DHCPv6 (Stateful) + TFTP over IPv6 Boot Example Application
//!
//! Demonstrates lwIP stateful DHCPv6 and TFTP over IPv6.
//! Requires TAP interface and dnsmasq server with IPv6 enabled.
//!
//! Flow:
//! 1. Create TAP netif with link-local IPv6
//! 2. Enable stateful DHCPv6 (waits for RA with M flag)
//! 3. Acquire a global IPv6 address via Solicit→Advertise→Request→Reply
//! 4. Download a file via TFTP over IPv6 from the TAP host

use std::env;
use std::ffi::c_void;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lwip_rs::sys;
use lwip_rs::Ipv4Addr;
use lwip_rs::{init, Dhcp6Client, Ipv6Addr, LwipError, NetIf, TftpClient, TftpStorageOps};

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

#[derive(Debug, Clone, Copy, PartialEq)]
enum AppState {
    Dhcp6Wait,
    Dhcp6Done,
    TftpStart,
    TftpInProgress,
    TftpDone,
    Error,
    Exit,
}

const DHCP6_TIMEOUT_SECS: u64 = 45;

static SHOULD_EXIT: AtomicBool = AtomicBool::new(false);
static FILE_HANDLE: Mutex<Option<File>> = Mutex::new(None);

fn storage_open(filename: &str) -> *mut c_void {
    let basename = Path::new(filename)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("download.bin");

    let output_dir = std::env::temp_dir().join("tftp_downloads");
    let _ = std::fs::create_dir_all(&output_dir);

    match File::create(output_dir.join(basename)) {
        Ok(file) => {
            *FILE_HANDLE.lock().unwrap() = Some(file);
            1 as *mut c_void
        }
        Err(_) => std::ptr::null_mut(),
    }
}

fn storage_write(_handle: *mut c_void, data: &[u8]) -> bool {
    FILE_HANDLE
        .lock()
        .unwrap()
        .as_mut()
        .map(|f| f.write_all(data).is_ok())
        .unwrap_or(false)
}

fn storage_close(_handle: *mut c_void) {
    *FILE_HANDLE.lock().unwrap() = None;
}

static STORAGE_OPS: TftpStorageOps = TftpStorageOps {
    open: storage_open,
    write: storage_write,
    close: storage_close,
};

/// The boot file name to download via TFTP.
/// Passed via BOOT_FILE env var or defaults to "test_boot.bin".
fn boot_filename() -> String {
    env::var("BOOT_FILE").unwrap_or_else(|_| "test_boot.bin".to_string())
}

fn main() {
    println!("========================================");
    println!("  DHCPv6 + TFTP/IPv6 Application (Rust)");
    println!("========================================");
    println!();

    ctrlc_handler();

    if env::var("PRECONFIGURED_TAPIF").is_err() {
        eprintln!("[ERROR] PRECONFIGURED_TAPIF not set");
        std::process::exit(1);
    }

    if let Err(e) = run_app() {
        eprintln!("[ERROR] Application failed: {}", e);
        std::process::exit(1);
    }

    println!("\nApplication finished.");
}

fn run_app() -> Result<(), AppError> {
    println!("[DHCPv6] Initializing lwIP...");
    init();

    println!("[DHCPv6] Adding TAP network interface...");
    let mut netif = NetIf::new_tap(Ipv4Addr::any(), Ipv4Addr::any(), Ipv4Addr::any())?;

    netif.set_status_callback(|_nif| {});
    netif.set_default();

    println!("[DHCPv6] Creating IPv6 link-local address...");
    netif.create_ipv6_linklocal();
    netif.set_up();
    netif.set_link_up();

    let mac = netif.mac_addr();
    println!(
        "[DHCPv6] MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );

    if let Some(ip6) = netif.ipv6_addr(0) {
        println!("[DHCPv6] IPv6 Link-local: {}", ip6);
    }

    println!("[DHCPv6] Network interface initialized");

    println!("[DHCPv6] Starting stateful DHCPv6 client...");
    let mut dhcp6 = Dhcp6Client::new(&mut netif);
    dhcp6.start()?;

    let dhcp6_start_time = Instant::now();
    let mut state = AppState::Dhcp6Wait;
    println!("[DHCPv6] Waiting for RA with M flag and DHCPv6 address assignment...");

    let mut tftp: Option<TftpClient> = None;
    let mut boot_file = String::new();
    let mut tftp_server = Ipv6Addr::new([0; 8]);

    while !SHOULD_EXIT.load(Ordering::Relaxed)
        && state != AppState::Exit
        && state != AppState::Error
    {
        netif.poll();
        sys::check_timeouts();

        match state {
            AppState::Dhcp6Wait => {
                if dhcp6.has_address(&netif) {
                    if let Some(addr) = dhcp6.global_address(&netif) {
                        println!("[DHCPv6] DHCPv6 complete!");
                        println!("[DHCPv6] Global IPv6 Address: {}", addr);
                    }

                    // Print all IPv6 addresses
                    for i in 0..3 {
                        if netif.ipv6_addr_valid(i) {
                            if let Some(addr) = netif.ipv6_addr(i) {
                                println!("[DHCPv6] IPv6 addr[{}]: {}", i, addr);
                            }
                        }
                    }

                    // Extract boot file info from Option 59
                    if let Some(url) = dhcp6.boot_file_url() {
                        println!("[DHCPv6] Boot File URL (Option 59): {}", url);
                    }
                    if let Some((server, path)) = dhcp6.parse_boot_file_url() {
                        println!("[DHCPv6] TFTP Server: {}", server);
                        println!("[DHCPv6] Boot File Path: {}", path);
                        tftp_server = server;
                        boot_file = path.to_string();
                    } else {
                        // Fallback: use env var or default
                        println!("[DHCPv6] No Boot File URL in DHCPv6, using defaults");
                        tftp_server = Ipv6Addr::new([0xfd00, 0x1234, 0x5678, 0, 0, 0, 0, 1]);
                        boot_file = boot_filename();
                    }

                    state = AppState::Dhcp6Done;
                } else if dhcp6_start_time.elapsed() > Duration::from_secs(DHCP6_TIMEOUT_SECS) {
                    eprintln!("[DHCPv6] DHCPv6 timeout!");
                    state = AppState::Error;
                }
            }

            AppState::Dhcp6Done => {
                state = AppState::TftpStart;
            }

            AppState::TftpStart => {
                if boot_file.is_empty() {
                    println!("[DHCPv6] No boot file to download");
                    state = AppState::TftpDone;
                } else {
                    println!(
                        "[DHCPv6] Starting TFTP download of '{}' from [{}]...",
                        boot_file, tftp_server
                    );
                    let mut client = TftpClient::new(&STORAGE_OPS)?;
                    client.get_v6(tftp_server, &boot_file)?;
                    println!("[DHCPv6] TFTP transfer started");
                    tftp = Some(client);
                    state = AppState::TftpInProgress;
                }
            }

            AppState::TftpInProgress => {
                if let Some(ref client) = tftp {
                    if client.is_complete() {
                        if client.has_error() {
                            let (code, msg) = client.error().unwrap();
                            eprintln!("[DHCPv6] TFTP error {}: {}", code, msg);
                            state = AppState::Error;
                        } else {
                            state = AppState::TftpDone;
                        }
                    }
                }
            }

            AppState::TftpDone => {
                let bytes = tftp.as_ref().map(|t| t.bytes_received()).unwrap_or(0);
                println!("[DHCPv6] === Transfer Complete ===");
                println!(
                    "[DHCPv6] File saved to: /tmp/tftp_downloads/{}",
                    boot_file.split('/').last().unwrap_or(&boot_file)
                );
                println!("[DHCPv6] Total bytes: {}", bytes);
                state = AppState::Exit;
            }

            _ => {}
        }
    }

    if SHOULD_EXIT.load(Ordering::Relaxed) {
        println!("[DHCPv6] Signal received, exiting...");
    }

    println!("[DHCPv6] Cleaning up...");
    drop(tftp);
    drop(dhcp6);
    drop(netif);

    if state == AppState::Error {
        Err(AppError("Application encountered an error".to_string()))
    } else {
        Ok(())
    }
}

fn ctrlc_handler() {
    std::thread::spawn(|| {
        let _ = std::io::stdin().read_line(&mut String::new());
    });
}
