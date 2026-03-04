// Licensed under the Apache-2.0 license

//! OCP Recovery Interface state machine types.
//!
//! This module defines the `RecoveryDeviceConfig` static configuration struct
//! and the `RecoveryAction` enum returned by the state machine's command
//! processing loop.

use crate::protocol::device_id::DeviceId;

/// Static device configuration provided at state machine construction time.
///
/// These fields are immutable for the lifetime of the state machine and are
/// used to populate PROT_CAP and DEVICE_ID responses.
pub struct RecoveryDeviceConfig<'a> {
    /// DEVICE_ID response payload.
    pub device_id: DeviceId<'a>,

    /// PROT_CAP major version (byte 8).
    pub major_version: u8,

    /// PROT_CAP minor version (byte 9).
    pub minor_version: u8,

    /// PROT_CAP max response time exponent (byte 13).
    /// Actual time = 2^max_response_time microseconds.
    pub max_response_time: u8,

    /// PROT_CAP heartbeat period exponent (byte 14).
    /// 0 means heartbeat is not supported.
    pub heartbeat_period: u8,
}

/// Actions the integrator must handle after `process_command` returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    /// No integrator action required. The command was fully handled.
    None,

    /// The integrator should activate the recovery image.
    /// After performing activation, the integrator calls
    /// `complete_activation()` to report the result.
    ActivateRecoveryImage,

    /// The integrator should perform a device reset.
    DeviceReset,

    /// The integrator should perform a management-only reset.
    ManagementReset,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::device_id::{DeviceDescriptor, PciVendorDescriptor};

    #[test]
    fn recovery_device_config_can_be_constructed() {
        let desc = DeviceDescriptor::PciVendor(PciVendorDescriptor::new(0x1234, 0x5678, 0, 0, 0));
        let device_id = DeviceId::new(desc, &[]).unwrap();

        let config = RecoveryDeviceConfig {
            device_id,
            major_version: 1,
            minor_version: 1,
            max_response_time: 17,
            heartbeat_period: 0,
        };

        assert_eq!(config.major_version, 1);
        assert_eq!(config.minor_version, 1);
        assert_eq!(config.max_response_time, 17);
        assert_eq!(config.heartbeat_period, 0);
    }
}
