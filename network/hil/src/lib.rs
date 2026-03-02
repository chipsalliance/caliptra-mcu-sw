/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    Hardware Interface Layer (HIL) for Network Coprocessor peripherals.
--*/

#![no_std]

pub mod ethernet;
pub mod timers;

pub use ethernet::Ethernet;
pub use timers::Timers;
