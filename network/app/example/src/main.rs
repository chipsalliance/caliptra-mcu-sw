// Licensed under the Apache-2.0 license

//! DHCP + TFTP Boot Example Application
//!
//! Demonstrates lwIP functionality: TAP interface, DHCP, and TFTP download.
//! Requires TAP interface and DHCP/TFTP server (dnsmasq).

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
    DhcpWait,
    DhcpDone,
    TftpStart,
    TftpInProgress,
    TftpDone,
    Error,
    Exit,
}

const DHCP_TIMEOUT_SECS: u64 = 30;
static SHOULD_EXIT: AtomicBool = AtomicBool::new(false);
static FILE_HANDLE: Mutex<Option<File>> = Mutex::new(None);

fn storage_open(filename: &str) -> *mut c_void {
    let basename = Path::new(filename)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("download.bin");

    let output_dir = "/tmp/tftp_downloads";
    let _ = std::fs::create_dir_all(output_dir);

    match File::create(format!("{}/{}", output_dir, basename)) {
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

fn main() {
    println!("========================================");
    println!("  DHCP + TFTP Boot Application (Rust)");
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
    println!("[DHCP-TFTP] Initializing lwIP...");
    init();

    println!("[DHCP-TFTP] Adding TAP network interface...");
    let mut netif = NetIf::new_tap(Ipv4Addr::any(), Ipv4Addr::any(), Ipv4Addr::any())?;

    netif.set_status_callback(|_nif| {});
    netif.set_default();

    println!("[DHCP-TFTP] Creating IPv6 link-local address...");
    netif.create_ipv6_linklocal();
    netif.set_up();
    netif.set_link_up();

    let mac = netif.mac_addr();
    println!(
        "[DHCP-TFTP] MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );

    if let Some(ip6) = netif.ipv6_addr(0) {
        println!("[DHCP-TFTP] IPv6 Link-local: {}", ip6);
    }

    println!("[DHCP-TFTP] Network interface initialized");

    println!("[DHCP-TFTP] Starting DHCP client...");
    let mut dhcp = DhcpClient::new(&mut netif);
    dhcp.start()?;

    let dhcp_start_time = Instant::now();
    let mut state = AppState::DhcpWait;
    println!("[DHCP-TFTP] DHCP discovery started, waiting for response...");

    let mut tftp: Option<TftpClient> = None;
    let mut boot_file = String::new();
    let mut tftp_server = Ipv4Addr::any();

    while !SHOULD_EXIT.load(Ordering::Relaxed)
        && state != AppState::Exit
        && state != AppState::Error
    {
        netif.poll();
        sys::check_timeouts();

        match state {
            AppState::DhcpWait => {
                if dhcp.has_address() {
                    let ip = netif.ipv4_addr();
                    let mask = netif.ipv4_netmask();
                    let gw = netif.ipv4_gateway();

                    println!("[DHCP-TFTP] DHCP complete!");
                    println!("[DHCP-TFTP] IPv4 Address: {}", ip);
                    println!("[DHCP-TFTP] IPv4 Netmask: {}", mask);
                    println!("[DHCP-TFTP] IPv4 Gateway: {}", gw);

                    if let Some(bf) = dhcp.boot_file() {
                        boot_file = bf;
                        println!("[DHCP-TFTP] Boot file: {}", boot_file);
                    } else {
                        println!("[DHCP-TFTP] No boot file specified");
                    }

                    tftp_server = dhcp.tftp_server();
                    if !tftp_server.is_any() {
                        println!("[DHCP-TFTP] TFTP Server (siaddr): {}", tftp_server);
                    } else {
                        tftp_server = gw;
                        println!("[DHCP-TFTP] TFTP Server: using gateway");
                    }

                    state = AppState::DhcpDone;
                } else if dhcp_start_time.elapsed() > Duration::from_secs(DHCP_TIMEOUT_SECS) {
                    eprintln!("[DHCP-TFTP] DHCP timeout!");
                    state = AppState::Error;
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
    std::thread::spawn(|| {
        let _ = std::io::stdin().read_line(&mut String::new());
    });
}
