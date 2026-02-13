/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entry point for Network Coprocessor ROM.
    This ROM implements a simple DHCP discovery application for network boot.

--*/

#![cfg_attr(target_arch = "riscv32", no_std)]
#![no_main]

#[cfg(target_arch = "riscv32")]
use core::panic::PanicInfo;

#[cfg(target_arch = "riscv32")]
use core::arch::global_asm;

use network_drivers::{println, exit_emulator};

// Include the startup assembly code
#[cfg(target_arch = "riscv32")]
global_asm!(include_str!("start.s"));

/// Main entry point called from assembly startup code
#[no_mangle]
pub extern "C" fn main() -> ! {
    use network_drivers::EthernetDriver;

    println!();
    println!("=====================================");
    println!("  Network Coprocessor ROM Started!  ");
    println!("=====================================");
    println!();    

    // Create Ethernet driver
    let eth = EthernetDriver::new();
    
    // Run the appropriate test based on feature flags
    #[cfg(feature = "test-network-rom-dhcp-discover")]
    {
        dhcp_test::run(eth)
    }
    
    #[cfg(not(feature = "test-network-rom-dhcp-discover"))]
    {
        // Default: no test, just print message and exit
        let _ = eth; // Silence unused warning
        println!("No network ROM test enabled.");
        println!("Enable a test feature (e.g., test-network-rom-dhcp-discover)");
        exit_emulator(0x00);
    }
}

/// Exception handler - called when CPU encounters an exception
#[no_mangle]
pub extern "C" fn exception_handler() {
    println!("EXCEPTION: Network ROM encountered an error!");
    exit_emulator(0x01);
}

/// Panic handler for no_std environment
#[cfg(target_arch = "riscv32")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    println!("PANIC: Network ROM panicked!");
    exit_emulator(0x01);
}

// Dummy main for non-RISC-V targets (for cargo check on host)
#[cfg(not(target_arch = "riscv32"))]
#[no_mangle]
pub extern "C" fn main() {
    println!("Network ROM (host build - no-op)");
}
