// Licensed under the Apache-2.0 license

//! Integrator-provided vendor callbacks for the OCP Recovery Interface.
//!
//! The `VendorHandler` trait lets integrators inject device-specific behavior
//! into the recovery state machine. `NoopVendorHandler` is a zero-cost default
//! for integrators that do not need vendor extensions.

use crate::error::OcpError;
use crate::protocol::hw_status::{CompositeTemperature, HwStatus, HwStatusFlags};

/// Integrator-provided callbacks for vendor-specific behavior.
///
/// The state machine delegates vendor command handling, heartbeat reporting,
/// and hardware status queries to this trait. Integrators implement it to
/// provide device-specific behavior.
pub trait VendorHandler {
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

/// A no-op `VendorHandler` for integrators that do not need vendor extensions
/// or hardware status reporting. All methods return zero/empty defaults.
pub struct NoopVendorHandler;

impl VendorHandler for NoopVendorHandler {
    fn handle_vendor_write(&mut self, _data: &[u8]) -> Result<(), OcpError> {
        Ok(())
    }

    fn handle_vendor_read(&self, _buf: &mut [u8]) -> Result<usize, OcpError> {
        Ok(0)
    }

    fn vendor_device_status(&self, _buf: &mut [u8]) -> usize {
        0
    }

    fn heartbeat(&self) -> u16 {
        0
    }

    fn hw_status(&self) -> Result<HwStatus<'_>, OcpError> {
        HwStatus::new(HwStatusFlags(0), 0, CompositeTemperature::NoData, &[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_vendor_handler_defaults() {
        let mut handler = NoopVendorHandler;
        assert_eq!(handler.handle_vendor_write(&[0x01]), Ok(()));
        assert_eq!(handler.handle_vendor_read(&mut [0u8; 16]), Ok(0));
        assert_eq!(handler.vendor_device_status(&mut [0u8; 248]), 0);
        assert_eq!(handler.heartbeat(), 0);
        let _ = handler.hw_status().unwrap();
    }
}
