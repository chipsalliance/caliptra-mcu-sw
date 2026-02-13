/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    Hardware Interface Layer (HIL) for Network Coprocessor peripherals.
    
    This crate defines traits that abstract hardware peripherals, allowing
    drivers to be written against these interfaces rather than directly
    against hardware registers. This enables:
    - Testability through mock implementations
    - Portability across different hardware platforms
    - Clean separation between hardware access and protocol logic

--*/

#![no_std]

pub mod ethernet;

pub use ethernet::Ethernet;
