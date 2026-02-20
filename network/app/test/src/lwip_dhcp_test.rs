/*++

Licensed under the Apache-2.0 license.

File Name:

    lwip_dhcp_test.rs

Abstract:

    DHCP discovery test using lwIP stack (lwip-rs).

    This module uses the lwip-rs bare-metal port to perform a full
    DHCP handshake (DISCOVER → OFFER → REQUEST → ACK) and obtain
    an IP address from a DHCP server (e.g., dnsmasq on a TAP interface).

--*/

use lwip_rs::netif_baremetal::{BaremetalCallbacks, BaremetalNetIf};
use lwip_rs::BaremetalSysCallbacks;
use network_drivers::EthernetDriver;
use network_drivers::{exit_emulator, println, MacAddr};
use network_hil::ethernet::Ethernet;

/// Run the lwIP-based DHCP discovery test.
///
/// This is the main entry point. It initializes lwIP, sets up the
/// bare-metal network interface backed by the EthernetDriver, starts
/// DHCP, and polls until an address is obtained or timeout occurs.
///
/// # Arguments
/// * `_eth` - The Ethernet driver (used via static new() in callbacks)
pub fn run(_eth: EthernetDriver) {
    println!();
    println!("=====================================");
    println!("  lwIP DHCP Discovery Test Started!  ");
    println!("=====================================");
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

    // Caller owns the static netif storage (lwIP holds raw pointers into it)
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

    // Start DHCP client
    println!("Starting DHCP discovery...");
    if let Err(e) = netif.dhcp_start() {
        println!("Failed to start DHCP: {:?}", e);
        exit_emulator(0x03);
    }
    println!("DHCP client started, waiting for address...");

    // Poll loop: process packets until DHCP completes
    const MAX_ITERATIONS: u32 = 500_000;

    for i in 0..MAX_ITERATIONS {
        // Advance the software timer by 1ms each iteration
        unsafe { SYS_NOW_COUNTER += 1; }

        // Process received packets and lwIP timeouts
        netif.poll();

        // Check if DHCP has assigned an address
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
            println!("DHCP discovery successful!");

            netif.shutdown();
            exit_emulator(0x00); // Success
        }

        // Print periodic status (every 1000 iterations)
        if i > 0 && (i % 1000) == 0 {
            let elapsed_ms = sys_now_ms();
            println!("  DHCP still waiting... ({}ms elapsed)", elapsed_ms);
        }
    }

    println!("DHCP discovery timed out");
    netif.shutdown();
    exit_emulator(0x02);
}

// ============================================================================
// Hardware driver callback functions
// These bridge lwIP's bare-metal netif to the EthernetDriver registers.
// ============================================================================

/// Transmit a raw Ethernet frame via the hardware driver.
fn eth_transmit(frame: &[u8]) -> bool {
    let mut eth = EthernetDriver::new();
    eth.transmit(frame).is_ok()
}

/// Receive a raw Ethernet frame from the hardware driver.
/// Returns the number of bytes received, or 0 if no frame is available.
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

/// Get the MAC address from the hardware driver.
fn eth_mac_addr() -> [u8; 6] {
    let eth = EthernetDriver::new();
    eth.mac_address()
}

/// Check if there's a received frame available in the hardware.
fn eth_rx_available() -> bool {
    let eth = EthernetDriver::new();
    eth.rx_available()
}

/// Global software timer counter, incremented by 1 each poll iteration.
static mut SYS_NOW_COUNTER: u32 = 0;

/// Returns the current system time in milliseconds using a software counter.
///
/// Each poll() iteration increments the counter by 1ms, giving deterministic
/// timer behaviour independent of the emulator's mcycle rate.
fn sys_now_ms() -> u32 {
    unsafe { SYS_NOW_COUNTER }
}

/// Simple xorshift32 PRNG for lwIP.
fn simple_rand() -> u32 {
    static mut STATE: u32 = 0x12345678;
    unsafe {
        STATE ^= STATE << 13;
        STATE ^= STATE >> 17;
        STATE ^= STATE << 5;
        STATE
    }
}
