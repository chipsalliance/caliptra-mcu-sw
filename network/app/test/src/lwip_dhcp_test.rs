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

use caliptra_mcu_network_drivers::EthernetDriver;
use caliptra_mcu_network_drivers::TimerDriver;
use caliptra_mcu_network_drivers::{exit_emulator, println, MacAddr};
use caliptra_mcu_network_hil::ethernet::Ethernet;
use caliptra_mcu_network_hil::timers::Timers;
use lwip_rs::netif_baremetal::{BaremetalCallbacks, BaremetalNetIf};
use lwip_rs::BaremetalSysCallbacks;

pub fn run(eth: EthernetDriver) {
    println!();
    println!("=====================================");
    println!("  lwIP DHCP Discovery Test Started!  ");
    println!("=====================================");
    println!();

    // Get and print MAC address
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
