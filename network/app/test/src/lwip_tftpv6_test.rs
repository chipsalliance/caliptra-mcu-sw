/*++

Licensed under the Apache-2.0 license.

File Name:

    lwip_tftpv6_test.rs

Abstract:

    SLAAC + TFTP-over-IPv6 download test using lwIP stack (lwip-rs).

    This module performs IPv6 Stateless Address Autoconfiguration (SLAAC) to
    obtain a global address, then downloads a known file from a TFTP server
    over IPv6. The file contains an increasing pattern (byte i = i & 0xFF)
    which is verified inline in the write callback without buffering.

    Unlike the IPv4 TFTP test, the server address and filename are hardcoded
    because stateless DHCPv6 does not provide boot file information.

--*/

use lwip_rs::netif_baremetal::{BaremetalCallbacks, BaremetalNetIf};
use lwip_rs::tftp_baremetal::{BaremetalTftpClient, BaremetalTftpOps};
use lwip_rs::BaremetalSysCallbacks;
use lwip_rs::Ipv6Addr;
use network_drivers::EthernetDriver;
use network_drivers::TimerDriver;
use network_drivers::{exit_emulator, println, MacAddr};
use network_hil::ethernet::Ethernet;
use network_hil::timers::Timers;

/// Expected size of the TFTP test file (must match the integration test).
const EXPECTED_FILE_SIZE: usize = 4096;

/// TFTP server IPv6 address: fd00:1234:5678::1
/// This is the ULA address assigned to the TAP interface in the test harness.
const TFTP_SERVER_ADDR: Ipv6Addr = {
    // fd00:1234:5678::1 in lwIP's internal format (network byte order per u32 word).
    // On little-endian RISC-V, each u32 word is byte-swapped relative to
    // the standard notation so that the in-memory representation matches
    // network order.
    //
    // For fd00:1234:5678:0000:0000:0000:0000:0001:
    //   Bytes in network order: fd 00 12 34  56 78 00 00  00 00 00 00  00 00 00 01
    //   As LE u32 words:        0x341200fd   0x00007856   0x00000000   0x01000000
    Ipv6Addr::from_raw([0x3412_00fd, 0x0000_7856, 0x0000_0000, 0x0100_0000])
};

/// TFTP boot filename (null-terminated).
const TFTP_FILENAME: &[u8] = b"pattern.bin\0";

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

/// Run the lwIP-based SLAAC + TFTP-over-IPv6 download test.
///
/// 1. Initializes lwIP and the bare-metal network interface with IPv6
/// 2. Waits for SLAAC to assign a global IPv6 address
/// 3. Initiates a TFTP GET over IPv6 to the known server address
/// 4. Verifies the file contents inline (increasing byte pattern)
/// 5. Reports success or failure
pub fn run(_eth: EthernetDriver) {
    println!();
    println!("=============================================");
    println!("  lwIP SLAAC + TFTP IPv6 Download Test Started");
    println!("=============================================");
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

    // Print link-local address (auto-created from MAC during init)
    let ll_addr = netif.link_local_ipv6_addr();
    println!("Link-local IPv6 address: {}", ll_addr);

    // ====================================================================
    // Phase 1: SLAAC — obtain global IPv6 address via Router Advertisement
    // ====================================================================
    println!("Enabling stateless DHCPv6...");
    if let Err(e) = netif.dhcp6_enable_stateless() {
        println!("Failed to enable stateless DHCPv6: {:?}", e);
        exit_emulator(0x04);
    }
    println!("Waiting for SLAAC global address via RA...");

    const MAX_SLAAC_ITERATIONS: u32 = 500_000;

    for i in 0..MAX_SLAAC_ITERATIONS {
        netif.poll();

        if netif.has_global_ipv6_address() {
            let global_addr = netif.global_ipv6_addr();

            println!();
            println!("IPv6 SLAAC address received!");
            println!("  Global IPv6: {}", global_addr);
            println!("  Link-local:  {}", netif.link_local_ipv6_addr());
            println!();
            break;
        }

        if i > 0 && (i % 1000) == 0 {
            let elapsed_ms = sys_now_ms();
            println!("  SLAAC still waiting... ({}ms elapsed)", elapsed_ms);
        }

        if i == MAX_SLAAC_ITERATIONS - 1 {
            println!("SLAAC timed out");
            netif.shutdown();
            exit_emulator(0x02);
        }
    }

    // ====================================================================
    // Phase 2: TFTP over IPv6 — download and verify the boot file
    // ====================================================================
    println!("Starting TFTP IPv6 download...");
    println!("  TFTP server: {}", TFTP_SERVER_ADDR);

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

    // Initiate TFTP GET over IPv6
    if let Err(e) = tftp.get_v6(TFTP_SERVER_ADDR, TFTP_FILENAME) {
        println!("Failed to start TFTP GET: {:?}", e);
        tftp.cleanup();
        netif.shutdown();
        exit_emulator(0x05);
    }
    println!("TFTP GET initiated, downloading...");

    // Poll until download completes.
    const MAX_TFTP_ITERATIONS: u32 = 500_000;

    for i in 0..MAX_TFTP_ITERATIONS {
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
    println!("TFTP IPv6 download successful!");

    tftp.cleanup();
    netif.shutdown();
    exit_emulator(0x00);
}

// ============================================================================
// TFTP callbacks — verify the increasing pattern inline
// ============================================================================

/// Write callback: verify each byte matches the expected increasing pattern.
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

/// Returns the current system time in milliseconds using the hardware timer.
fn sys_now_ms() -> u32 {
    let timer = TimerDriver::new();
    timer.elapsed_ms(0, timer.ticks()) as u32
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
