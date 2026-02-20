/*++

Licensed under the Apache-2.0 license.

File Name:

    lwip_dhcpv6_test.rs

Abstract:

    IPv6 SLAAC discovery test using lwIP stack (lwip-rs).

    This module uses the lwip-rs bare-metal port with IPv6 support to perform
    IPv6 Stateless Address Autoconfiguration (SLAAC) and obtain a global IPv6
    address from Router Advertisements (e.g., dnsmasq with --enable-ra on a
    TAP interface).

--*/

use lwip_rs::netif_baremetal::{BaremetalCallbacks, BaremetalNetIf};
use lwip_rs::BaremetalSysCallbacks;
use network_drivers::EthernetDriver;
use network_drivers::TimerDriver;
use network_drivers::{exit_emulator, println, MacAddr};
use network_hil::ethernet::Ethernet;
use network_hil::timers::Timers;

/// Run the lwIP-based IPv6 SLAAC discovery test.
///
/// This is the main entry point. It initializes lwIP, sets up the
/// bare-metal network interface backed by the EthernetDriver, and polls
/// until a global IPv6 address is obtained via SLAAC from Router
/// Advertisements, or timeout occurs.
///
/// # Arguments
/// * `_eth` - The Ethernet driver (used via static new() in callbacks)
pub fn run(_eth: EthernetDriver) {
    println!();
    println!("========================================");
    println!("  lwIP IPv6 SLAAC Discovery Test Started!");
    println!("========================================");
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

    // Print link-local address (auto-created from MAC during init)
    let ll_addr = netif.link_local_ipv6_addr();
    println!("Link-local IPv6 address: {}", ll_addr);

    // Enable stateless DHCPv6 to obtain DNS servers and other config from DHCPv6
    // Address assignment is done via SLAAC from Router Advertisements
    println!("Enabling stateless DHCPv6...");
    if let Err(e) = netif.dhcp6_enable_stateless() {
        println!("Failed to enable stateless DHCPv6: {:?}", e);
        exit_emulator(0x04);
    }
    println!("Stateless DHCPv6 enabled, waiting for SLAAC global address via RA...");

    // Poll loop: process packets until SLAAC completes
    const MAX_ITERATIONS: u32 = 500_000;

    for i in 0..MAX_ITERATIONS {
        // Process received packets and lwIP timeouts
        netif.poll();

        // Check if SLAAC has assigned a global address
        if netif.has_global_ipv6_address() {
            let global_addr = netif.global_ipv6_addr();

            println!();
            println!("IPv6 SLAAC address received!");
            println!("  Global IPv6: {}", global_addr);
            println!("  Link-local:  {}", netif.link_local_ipv6_addr());
            println!();
            println!("DHCPv6 discovery successful!");

            netif.shutdown();
            exit_emulator(0x00); // Success
        }

        // Print periodic status (every 1000 iterations)
        if i > 0 && (i % 1000) == 0 {
            let elapsed_ms = sys_now_ms();
            println!("  SLAAC still waiting... ({}ms elapsed)", elapsed_ms);
        }
    }

    println!("DHCPv6 discovery timed out");
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

/// Returns the current system time in milliseconds using the hardware timer.
///
/// Uses `TimerDriver::elapsed_ms()` to convert the RISC-V `mcycle` tick count
/// into milliseconds since boot. The timer frequency determines the mapping
/// from ticks to real time.
fn sys_now_ms() -> u32 {
    let timer = TimerDriver::new();
    timer.elapsed_ms(0, timer.ticks()) as u32
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
