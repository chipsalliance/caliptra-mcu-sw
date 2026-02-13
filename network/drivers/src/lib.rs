/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    Network Coprocessor peripheral drivers.
    
    This crate contains driver implementations for the Network Coprocessor's
    hardware peripherals. Each driver implements the corresponding HIL trait,
    providing a clean abstraction over the hardware registers.

--*/

#![no_std]

pub mod ethernet;
pub mod system;
pub mod uart;

pub use ethernet::EthernetDriver;
pub use system::exit_emulator;
pub use uart::{print_char, print_str, IpAddr, MacAddr, UartWriter};
