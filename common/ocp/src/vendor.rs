// Licensed under the Apache-2.0 license

//! Integrator-provided vendor callbacks for the OCP Recovery Interface.
//!
//! The `VendorHandler` trait lets integrators inject device-specific behavior
//! into the recovery state machine. `NoopVendorHandler` is a zero-cost default
//! for integrators that do not need vendor extensions.

use bitfield::bitfield;

use crate::error::OcpError;
use crate::protocol::device_reset::DeviceReset;
use crate::protocol::hw_status::HwStatus;

bitfield! {
    /// Device capabilities that depend on the vendor/integrator's hardware and
    /// firmware support. Returned by [`VendorHandler::capabilities`] and used
    /// by the state machine to populate PROT_CAP bits 1-3, 8-10.
    ///
    /// Stored as a single `u8` to minimize footprint.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct VendorCapabilities(u8);
    impl Debug;

    /// PROT_CAP bit 1: device supports forced recovery mode.
    pub forced_recovery, set_forced_recovery: 0;
    /// PROT_CAP bit 2: device supports management-only reset.
    pub mgmt_reset, set_mgmt_reset: 1;
    /// PROT_CAP bit 3: device supports full device reset.
    pub device_reset, set_device_reset: 2;
    /// PROT_CAP bit 8: device supports interface isolation.
    pub interface_isolation, set_interface_isolation: 3;
    /// PROT_CAP bit 9: device supports HW_STATUS reporting.
    pub hardware_status, set_hardware_status: 4;
    /// PROT_CAP bit 10: device supports VENDOR command.
    pub vendor_command, set_vendor_command: 5;
}

/// Integrator-provided callbacks for vendor-specific behavior.
///
/// The state machine delegates vendor command handling, heartbeat reporting,
/// hardware status queries, capability reporting, and reset execution to
/// this trait. Integrators implement it to provide device-specific behavior.
pub trait VendorHandler {
    /// Report which optional protocol capabilities the device supports.
    ///
    /// The returned values populate PROT_CAP bits 1-3 and 8-10.
    fn capabilities(&self) -> VendorCapabilities;

    /// Execute a device reset.
    ///
    /// Called when the state machine processes a DEVICE_RESET write with
    /// a non-zero reset control. The integrator performs the actual
    /// hardware reset and returns when complete.
    fn execute_reset(&mut self, reset: &DeviceReset);

    /// Handle a VENDOR command (cmd=0x2C) write.
    ///
    /// `data` is the raw payload from the write command.
    fn handle_vendor_write(&mut self, data: &[u8]) -> Result<(), OcpError>;

    /// Handle a VENDOR command (cmd=0x2C) read.
    ///
    /// Write the response into `buf` and return the number of bytes written.
    fn handle_vendor_read(&self, buf: &mut [u8]) -> Result<usize, OcpError>;

    /// Called when DEVICE_STATUS is being built.
    ///
    /// Allows the integrator to supply vendor status bytes (DEVICE_STATUS
    /// bytes 7-254). Write into `buf` and return the number of bytes
    /// written (0-248).
    fn vendor_device_status(&self, buf: &mut [u8]) -> usize;

    /// Called when DEVICE_STATUS is being built.
    ///
    /// Returns the current heartbeat counter value (DEVICE_STATUS bytes 4-5).
    /// The integrator maintains and increments this counter at the period
    /// advertised in PROT_CAP byte 14. Value must be in 0-4095 (12-bit, wraps).
    fn heartbeat(&self) -> u16;

    /// Called when HW_STATUS (cmd=0x28) is read.
    ///
    /// Returns the current hardware status snapshot. The state machine
    /// serializes the returned `HwStatus` into the wire response.
    fn hw_status(&self) -> Result<HwStatus<'_>, OcpError>;
}

/// A no-op `VendorHandler` that advertises no optional capabilities.
///
/// `capabilities()` returns all-zero (nothing supported). Methods that are
/// only reachable when their corresponding capability bit is set are
/// `unimplemented!()` — the state machine will never call them because
/// `capabilities()` reports them as unsupported.
pub struct NoopVendorHandler;

impl VendorHandler for NoopVendorHandler {
    fn capabilities(&self) -> VendorCapabilities {
        VendorCapabilities(0)
    }

    fn execute_reset(&mut self, _reset: &DeviceReset) {
        unimplemented!("NoopVendorHandler: device_reset capability is not advertised")
    }

    fn handle_vendor_write(&mut self, _data: &[u8]) -> Result<(), OcpError> {
        unimplemented!("NoopVendorHandler: vendor_command capability is not advertised")
    }

    fn handle_vendor_read(&self, _buf: &mut [u8]) -> Result<usize, OcpError> {
        unimplemented!("NoopVendorHandler: vendor_command capability is not advertised")
    }

    fn vendor_device_status(&self, _buf: &mut [u8]) -> usize {
        0
    }

    fn heartbeat(&self) -> u16 {
        0
    }

    fn hw_status(&self) -> Result<HwStatus<'_>, OcpError> {
        unimplemented!("NoopVendorHandler: hardware_status capability is not advertised")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_capabilities_all_zero() {
        let handler = NoopVendorHandler;
        let caps = handler.capabilities();
        assert!(!caps.forced_recovery());
        assert!(!caps.mgmt_reset());
        assert!(!caps.device_reset());
        assert!(!caps.interface_isolation());
        assert!(!caps.hardware_status());
        assert!(!caps.vendor_command());
    }

    #[test]
    fn noop_passive_methods_return_defaults() {
        let handler = NoopVendorHandler;
        assert_eq!(handler.vendor_device_status(&mut [0u8; 248]), 0);
        assert_eq!(handler.heartbeat(), 0);
    }
}
