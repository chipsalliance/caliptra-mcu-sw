/*++

Licensed under the Apache-2.0 license.

File Name:

    lwip_tftp_test.rs

Abstract:

    DHCP + TFTP download test using lwIP stack (lwip-rs).

    This module performs a full DHCP handshake to obtain an IP address and
    boot file information, then downloads the boot file via TFTP. The boot
    file contains an increasing pattern (byte i = i & 0xFF) which is
    verified inline in the write callback without buffering the entire file.

--*/

use lwip_rs::netif_baremetal::{BaremetalCallbacks, BaremetalNetIf};
use lwip_rs::tftp_baremetal::{BaremetalTftpClient, BaremetalTftpOps};
use lwip_rs::BaremetalSysCallbacks;
use network_drivers::EthernetDriver;
use network_drivers::{exit_emulator, println, MacAddr};
use network_hil::ethernet::Ethernet;

/// Expected size of the TFTP test file (must match the integration test).
const EXPECTED_FILE_SIZE: usize = 4096;

/// Tracks verification state across write callbacks.
struct VerifyState {
    /// Next expected byte offset in the file.
    offset: usize,
    /// Whether a verification error has been detected.
    error: bool,
}

/// Global verification state. Safe because bare-metal is single-threaded.
static mut VERIFY: VerifyState = VerifyState {
    offset: 0,
    error: false,
};

/// Run the lwIP-based DHCP + TFTP download test.
///
/// 1. Initializes lwIP and the bare-metal network interface
/// 2. Runs DHCP to obtain an IP address and boot file name
/// 3. Initiates a TFTP GET of the boot file
/// 4. Verifies the file contents inline (increasing byte pattern)
/// 5. Reports success or failure
pub fn run(_eth: EthernetDriver) {
    println!();
    println!("==========================================");
    println!("  lwIP DHCP + TFTP Download Test Started  ");
    println!("==========================================");
    println!();

    // Get and print MAC address
    let eth = EthernetDriver::new();
    let mac = eth.mac_address();
    println!("MAC address: {}", MacAddr(&mac));

    // Register bare-metal system callbacks and initialize lwIP
    lwip_rs::register_sys_callbacks(BaremetalSysCallbacks {
        sys_now: sys_now_ms,
        sys_init: || {},
        sys_arch_protect: || 0,
        sys_arch_unprotect: |_| {},
        rand: simple_rand,
    });
    lwip_rs::init();
    println!("lwIP stack initialized");

    // Initialize the bare-metal network interface
    static mut NETIF: BaremetalNetIf = BaremetalNetIf::new();
    let netif = unsafe { &mut *core::ptr::addr_of_mut!(NETIF) };
    match netif.init(BaremetalCallbacks {
        transmit: eth_transmit,
        receive: eth_receive,
        mac_addr: eth_mac_addr,
        rx_available: eth_rx_available,
    }) {
        Ok(()) => {}
        Err(e) => {
            println!("Failed to initialize netif: {:?}", e);
            exit_emulator(0x03);
        }
    };
    println!("Network interface initialized");

    // ====================================================================
    // Phase 1: DHCP — obtain IP address and boot file information
    // ====================================================================
    println!("Starting DHCP discovery...");
    if let Err(e) = netif.dhcp_start() {
        println!("Failed to start DHCP: {:?}", e);
        exit_emulator(0x03);
    }
    println!("DHCP client started, waiting for address...");

    const MAX_DHCP_ITERATIONS: u32 = 500_000;

    for i in 0..MAX_DHCP_ITERATIONS {
        // Advance the software timer by 1ms each iteration
        unsafe { SYS_NOW_COUNTER += 1; }

        netif.poll();

        if netif.dhcp_has_address() {
            let ip = netif.dhcp_offered_ip();
            let netmask = netif.dhcp_offered_netmask();
            let gateway = netif.dhcp_offered_gateway();

            println!();
            println!("DHCP OFFER received!");
            println!("  Offered IP: {}", ip);
            println!("  Netmask:    {}", netmask);
            println!("  Gateway:    {}", gateway);
            println!();
            break;
        }

        if i > 0 && (i % 1000) == 0 {
            let elapsed_ms = sys_now_ms();
            println!("  DHCP still waiting... ({}ms elapsed)", elapsed_ms);
        }

        if i == MAX_DHCP_ITERATIONS - 1 {
            println!("DHCP discovery timed out");
            netif.shutdown();
            exit_emulator(0x02);
        }
    }

    // Get boot file info from DHCP response
    let boot_file = netif.dhcp_boot_file_name();
    let server_ip = netif.dhcp_server_ip();

    if boot_file.is_empty() {
        println!("No boot file name in DHCP response");
        netif.shutdown();
        exit_emulator(0x04);
    }

    // Print boot file info (safe: boot_file is ASCII from dnsmasq)
    print_boot_info(boot_file, server_ip);

    // ====================================================================
    // Phase 2: TFTP — download and verify the boot file
    // ====================================================================
    println!("Starting TFTP download...");

    // Reset verification state
    unsafe {
        VERIFY.offset = 0;
        VERIFY.error = false;
    }

    // Initialize TFTP client
    static mut TFTP: BaremetalTftpClient = BaremetalTftpClient::new();
    let tftp = unsafe { &mut *core::ptr::addr_of_mut!(TFTP) };
    if let Err(e) = tftp.init(BaremetalTftpOps {
        write: tftp_write_verify,
        error: tftp_error,
    }) {
        println!("Failed to initialize TFTP client: {:?}", e);
        netif.shutdown();
        exit_emulator(0x05);
    }

    // Build null-terminated filename on the stack
    // boot_file is a &[u8] without null terminator; we need to append \0
    let mut fname_buf = [0u8; 128];
    let fname_len = core::cmp::min(boot_file.len(), fname_buf.len() - 1);
    fname_buf[..fname_len].copy_from_slice(&boot_file[..fname_len]);
    fname_buf[fname_len] = 0;
    let fname = &fname_buf[..fname_len + 1];

    // Initiate TFTP GET
    if let Err(e) = tftp.get(server_ip, fname) {
        println!("Failed to start TFTP GET: {:?}", e);
        tftp.cleanup();
        netif.shutdown();
        exit_emulator(0x05);
    }
    println!("TFTP GET initiated, downloading...");

    // Poll until download completes.
    const MAX_TFTP_ITERATIONS: u32 = 500_000;

    for i in 0..MAX_TFTP_ITERATIONS {
        // Advance the software timer by 1ms each iteration
        unsafe { SYS_NOW_COUNTER += 1; }

        netif.poll();

        if tftp.is_complete() {
            break;
        }

        if i > 0 && (i % 10000) == 0 {
            println!(
                "  TFTP downloading... ({}ms elapsed, {} bytes)",
                sys_now_ms(),
                tftp.bytes_received(),
            );
        }

        if i == MAX_TFTP_ITERATIONS - 1 {
            println!("TFTP download timed out ({} bytes received)", tftp.bytes_received());
            tftp.cleanup();
            netif.shutdown();
            exit_emulator(0x06);
        }
    }

    // Check results
    let bytes = tftp.bytes_received();
    let has_error = tftp.has_error();
    let verify_error = unsafe { VERIFY.error };

    println!();
    println!("TFTP download complete!");
    println!("  Bytes received: {}", bytes);

    if has_error {
        println!("  TFTP transfer error!");
        tftp.cleanup();
        netif.shutdown();
        exit_emulator(0x07);
    }

    if verify_error {
        println!("  Pattern verification FAILED!");
        tftp.cleanup();
        netif.shutdown();
        exit_emulator(0x08);
    }

    if bytes != EXPECTED_FILE_SIZE {
        println!(
            "  Unexpected file size: {} (expected {})",
            bytes, EXPECTED_FILE_SIZE
        );
        tftp.cleanup();
        netif.shutdown();
        exit_emulator(0x09);
    }

    println!("  Pattern verification passed!");
    println!();
    println!("TFTP download successful!");

    tftp.cleanup();
    netif.shutdown();
    exit_emulator(0x00);
}

// ============================================================================
// TFTP callbacks — verify the increasing pattern inline
// ============================================================================

/// Write callback: verify each byte matches the expected increasing pattern.
///
/// The test file contains bytes where byte[i] = (i & 0xFF).
/// We track the file offset across calls and verify each chunk in-place.
fn tftp_write_verify(data: &[u8]) -> bool {
    unsafe {
        for (j, &byte) in data.iter().enumerate() {
            let expected = ((VERIFY.offset + j) & 0xFF) as u8;
            if byte != expected {
                println!(
                    "  VERIFY FAIL at offset {}: got 0x{:02X}, expected 0x{:02X}",
                    VERIFY.offset + j,
                    byte,
                    expected
                );
                VERIFY.error = true;
                return false;
            }
        }
        VERIFY.offset += data.len();
    }
    true
}

/// Error callback: print the TFTP error.
fn tftp_error(err: i32, msg: &[u8]) {
    if msg.is_empty() {
        println!("  TFTP error: code {}", err);
    } else {
        println!("  TFTP error: code {} (msg_len={})", err, msg.len());
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Print boot file information from DHCP.
fn print_boot_info(boot_file: &[u8], server_ip: lwip_rs::Ipv4Addr) {
    // Print filename as ASCII characters
    print_bytes_as_str("  Boot file: ", boot_file);
    println!("  TFTP server: {}", server_ip);
}

/// Print a byte slice as an ASCII string (best-effort, char by char).
fn print_bytes_as_str(prefix: &str, bytes: &[u8]) {
    // Use a small buffer to format the output
    // Network Coprocessor println! uses UART output directly
    let mut buf = [0u8; 160];
    let prefix_bytes = prefix.as_bytes();
    let mut pos = 0;
    for &b in prefix_bytes {
        if pos < buf.len() {
            buf[pos] = b;
            pos += 1;
        }
    }
    for &b in bytes {
        if pos < buf.len() {
            buf[pos] = if b.is_ascii_graphic() || b == b' ' {
                b
            } else {
                b'?'
            };
            pos += 1;
        }
    }
    // Convert to str and print
    if let Ok(s) = core::str::from_utf8(&buf[..pos]) {
        println!("{}", s);
    }
}

// ============================================================================
// Hardware driver callback functions
// ============================================================================

fn eth_transmit(frame: &[u8]) -> bool {
    let mut eth = EthernetDriver::new();
    eth.transmit(frame).is_ok()
}

fn eth_receive(buffer: &mut [u8]) -> usize {
    let mut eth = EthernetDriver::new();
    if !eth.rx_available() {
        return 0;
    }
    match eth.receive(buffer) {
        Ok(len) => len,
        Err(_) => 0,
    }
}

fn eth_mac_addr() -> [u8; 6] {
    let eth = EthernetDriver::new();
    eth.mac_address()
}

fn eth_rx_available() -> bool {
    let eth = EthernetDriver::new();
    eth.rx_available()
}

/// Global software timer counter, incremented by 1 each poll iteration.
static mut SYS_NOW_COUNTER: u32 = 0;

/// Returns the current system time in milliseconds using a software counter.
fn sys_now_ms() -> u32 {
    unsafe { SYS_NOW_COUNTER }
}

fn simple_rand() -> u32 {
    static mut STATE: u32 = 0x12345678;
    unsafe {
        STATE ^= STATE << 13;
        STATE ^= STATE >> 17;
        STATE ^= STATE << 5;
        STATE
    }
}
