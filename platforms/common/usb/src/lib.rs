// Licensed under the Apache-2.0 license

//! Shared, polling LPCIP Device 0 enumeration for ROM and runtime on latest/2.2.
//!
//! The caller supplies all configuration in `UsbParams`. There is no default
//! VID/PID: USB3320's PHY identity is not a release USB device identity. Power
//! values describe USB VBUS consumption, not total board power. Remote wakeup
//! and LPM are not implemented or advertised.
//!
//! # Platform prerequisites
//!
//! Before `LpcipUsbDriver::initialize`, the platform must release the external
//! PHY reset, provide its reference/ULPI clock and enable CSR/SRAM clocks.
//! These board-level operations are not expressible through the LPCIP CSRs.
//! Initialization preserves FORCE_NEEDCLK and USB3320 SUSPENDM so that gateway
//! transactions and enumeration retain the PHY clock. ULPI, VBUS and endpoint
//! cancellation waits are bounded; callers must report returned errors through
//! their platform diagnostics. Neither VBUS nor successful PHY startup is faked.
//!
//! The platform owns MMIO mappings and the exclusive Device 0 SRAM reservation.
//! The driver does not configure the internal hub, Device 1, recovery images or
//! boot policy. `LpcipUsbDriver::poll` is nonblocking between host transactions;
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
