// Licensed under the Apache-2.0 license

//! Shared, polling LPCIP Device 0 enumeration for ROM and runtime on latest/2.2.
//!
//! The caller supplies all configuration in `UsbParams`. There is no default
//! VID/PID: a PHY's identity is not a release USB device identity. Power
//! values describe USB VBUS consumption, not total board power. Remote wakeup
//! and LPM are not implemented or advertised.
//!
//! # Platform prerequisites
//!
//! The reference driver uses ULPI and checks the reference PHY identity.
//! Integrators using a different PHY or controller interface must provide
//! corresponding initialization and driver support.
//! Before `LpcipUsbDriver::initialize`, the platform must release the PHY reset,
//! provide the clocks required by its configuration and enable CSR/SRAM clocks.
//! These board-level operations are not expressible through the LPCIP CSRs.
//! Reference initialization preserves FORCE_NEEDCLK and ULPI SUSPENDM so gateway
//! transactions and enumeration retain the PHY clock. ULPI, VBUS and endpoint
//! cancellation waits are bounded; callers must report returned errors through
//! their platform diagnostics. Neither VBUS nor successful PHY startup is faked.
//!
//! The platform owns MMIO mappings and the exclusive Device 0 SRAM reservation.
//! `UsbParams::enable_hub` selects the hardware-serviced hub and applies the
//! caller's power policy before connecting it. `enable_logs` controls optional
//! bring-up/link diagnostics; callers still report errors independently.
//! The driver does not configure Device 1, recovery images or boot policy.
//! `LpcipUsbDriver::poll` is nonblocking between host transactions;
//! ROM and runtime can schedule it without a persistent compliance-mode loop.
//! `test-host` keeps the enumeration-only test fixture servicing EP0 after
//! configuration for Linux/libusb tests; it does not implement recovery boot.

#![no_std]

#[cfg(hw_rev = "latest")]
mod lpcip;
#[cfg(hw_rev = "latest")]
pub use lpcip::{LpcipUsbDriver, UsbError, UsbParams, UsbPoll};

/// Enumeration-only ROM test entry point, not production recovery boot policy.
#[cfg(all(hw_rev = "latest", feature = "test-enumeration"))]
pub fn enumeration_test(params: UsbParams) -> ! {
    let mut driver = LpcipUsbDriver::new(params);
    if let Err(error) = driver.initialize() {
        caliptra_mcu_romtime::println!("[usb-enumeration-test] initialization failed: {:?}", error);
        caliptra_mcu_romtime::test_exit(1);
    }
    caliptra_mcu_romtime::println!("[usb-enumeration-test] Device 0 ready");
    loop {
        match driver.poll() {
            Ok(UsbPoll::ConfigurationChanged(1)) => {
                caliptra_mcu_romtime::println!("[usb-enumeration-test] configured");
                if !cfg!(feature = "test-host") {
                    caliptra_mcu_romtime::test_exit(0);
                }
            }
            Ok(UsbPoll::Disconnected) => {
                caliptra_mcu_romtime::println!("[usb-enumeration-test] disconnected");
                if !cfg!(feature = "test-host") {
                    caliptra_mcu_romtime::test_exit(1);
                }
            }
            Ok(UsbPoll::Stalled) => {
                caliptra_mcu_romtime::println!(
                    "[usb-enumeration-test] unsupported request stalled"
                );
            }
            Err(error) => {
                caliptra_mcu_romtime::println!(
                    "[usb-enumeration-test] service failed: {:?}",
                    error
                );
                caliptra_mcu_romtime::test_exit(1);
            }
            _ => {}
        }
    }
}
