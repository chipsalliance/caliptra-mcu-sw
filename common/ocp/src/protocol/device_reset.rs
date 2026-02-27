// Licensed under the Apache-2.0 license

//! DEVICE_RESET (cmd=0x25) command structure.
//!
//! Spec reference: Section 9.2, "RESET" / Section 7.1-7.3.
//! A 3-byte RW command controlling device reset, forced recovery, and
//! interface mastering. This command is optional (scope A).

use zerocopy::{Immutable, IntoBytes, TryFromBytes};

use crate::error::OcpError;

/// Wire size of a DEVICE_RESET message in bytes, according to the Spec.
pub const MESSAGE_LEN: usize = 3;

// Assure the spec size matches the size of the structure.
const _: () = assert!(MESSAGE_LEN == size_of::<DeviceReset>());

/// Byte 0: Device Reset Control.
///
/// "Write 1, Device Clears" -- the Device resets the field after acting on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable, TryFromBytes)]
#[repr(u8)]
pub enum ResetControl {
    /// No reset requested.
    NoReset = 0x00,
    /// Full device reset (PCIe Fundamental Reset or equivalent). May be bus disruptive.
    ResetDevice = 0x01,
    /// Management-only reset. MUST NOT cause bus re-enumeration.
    /// MUST reset all security components including the attestation subsystem.
    ResetManagement = 0x02,
}

/// Byte 1: Forced Recovery mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable, TryFromBytes)]
#[repr(u8)]
pub enum ForcedRecoveryMode {
    /// No forced recovery.
    None = 0x00,
    /// Enter flashless boot mode on next platform reset.
    FlashlessBoot = 0x0E,
    /// Enter recovery mode on next platform reset.
    EnterRecovery = 0x0F,
}

/// Byte 2: Interface Control.
///
/// Controls target-initiated transactions (e.g. SMBus mastering).
/// Device MUST power on with mastering disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable, TryFromBytes)]
#[repr(u8)]
pub enum InterfaceControl {
    /// Disable interface mastering.
    DisableMastering = 0x00,
    /// Enable interface mastering.
    EnableMastering = 0x01,
}

/// DEVICE_RESET command (3 bytes on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable, TryFromBytes)]
#[repr(C, packed)]
pub struct DeviceReset {
    /// Byte 0: Reset control.
    pub reset_control: ResetControl,
    /// Byte 1: Forced recovery mode selection.
    pub forced_recovery: ForcedRecoveryMode,
    /// Byte 2: Interface mastering control.
    pub interface_control: InterfaceControl,
}

impl DeviceReset {
    pub fn new(
        reset_control: ResetControl,
        forced_recovery: ForcedRecoveryMode,
        interface_control: InterfaceControl,
    ) -> Self {
        Self {
            reset_control,
            forced_recovery,
            interface_control,
        }
    }

    /// Deserialize from a byte slice.
    ///
    /// Returns an error if the slice is shorter than [`MESSAGE_LEN`] or
    /// contains a reserved value in any field.
    pub fn from_message(msg: &[u8]) -> Result<Self, OcpError> {
        if msg.len() < MESSAGE_LEN {
            return Err(OcpError::MessageTooShort);
        }
        if msg.len() > MESSAGE_LEN {
            return Err(OcpError::MessageTooLong);
        }

        DeviceReset::try_read_from_prefix(msg)
            .map(|(s, _)| s)
            .map_err(|_| OcpError::DeviceResetInvalid)
    }

    /// Serialize into the wire representation.
    ///
    /// Returns an error if the buffer is too small.
    /// On success, returns the number of bytes written ([`MESSAGE_LEN`]).
    pub fn to_message(self, buf: &mut [u8]) -> Result<usize, OcpError> {
        self.write_to_prefix(buf)
            .map_err(|_| OcpError::BufferTooSmall)?;
        Ok(MESSAGE_LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_device_reset_to_message() {
        let cmd = DeviceReset::new(
            ResetControl::ResetManagement,
            ForcedRecoveryMode::EnterRecovery,
            InterfaceControl::DisableMastering,
        );
        let mut buf = [0u8; MESSAGE_LEN];
        let len = cmd.to_message(&mut buf).unwrap();

        assert_eq!(len, MESSAGE_LEN);
        assert_eq!(buf[0], 0x02);
        assert_eq!(buf[1], 0x0F);
        assert_eq!(buf[2], 0x00);
    }

    #[test]
    fn no_op_device_reset_to_message() {
        let cmd = DeviceReset::new(
            ResetControl::NoReset,
            ForcedRecoveryMode::None,
            InterfaceControl::DisableMastering,
        );
        let mut buf = [0u8; MESSAGE_LEN];
        cmd.to_message(&mut buf).unwrap();

        assert_eq!(buf, [0x00, 0x00, 0x00]);
    }

    #[test]
    fn from_message_valid() {
        let cmd = DeviceReset::from_message(&[0x02, 0x0F, 0x00]).unwrap();
        assert_eq!(cmd.reset_control, ResetControl::ResetManagement);
        assert_eq!(cmd.forced_recovery, ForcedRecoveryMode::EnterRecovery);
        assert_eq!(cmd.interface_control, InterfaceControl::DisableMastering);
    }

    #[test]
    fn from_message_too_short() {
        assert_eq!(
            DeviceReset::from_message(&[]),
            Err(OcpError::MessageTooShort)
        );
        assert_eq!(
            DeviceReset::from_message(&[0x00]),
            Err(OcpError::MessageTooShort)
        );
        assert_eq!(
            DeviceReset::from_message(&[0x00, 0x00]),
            Err(OcpError::MessageTooShort)
        );
    }

    #[test]
    fn from_message_too_long() {
        assert_eq!(
            DeviceReset::from_message(&[0x00, 0x00, 0x00, 0x00]),
            Err(OcpError::MessageTooLong)
        );
    }

    #[test]
    fn from_message_reserved_byte0() {
        assert_eq!(
            DeviceReset::from_message(&[0x03, 0x00, 0x00]),
            Err(OcpError::DeviceResetInvalid)
        );
    }

    #[test]
    fn from_message_reserved_byte1() {
        assert_eq!(
            DeviceReset::from_message(&[0x00, 0x05, 0x00]),
            Err(OcpError::DeviceResetInvalid)
        );
    }

    #[test]
    fn from_message_reserved_byte2() {
        assert_eq!(
            DeviceReset::from_message(&[0x00, 0x00, 0x02]),
            Err(OcpError::DeviceResetInvalid)
        );
    }

    #[test]
    fn from_message_round_trip() {
        let original = DeviceReset::new(
            ResetControl::ResetDevice,
            ForcedRecoveryMode::FlashlessBoot,
            InterfaceControl::EnableMastering,
        );
        let mut buf = [0u8; MESSAGE_LEN];
        original.to_message(&mut buf).unwrap();
        let parsed = DeviceReset::from_message(&buf).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn to_message_buffer_too_small() {
        let cmd = DeviceReset::new(
            ResetControl::NoReset,
            ForcedRecoveryMode::None,
            InterfaceControl::DisableMastering,
        );
        assert_eq!(
            cmd.to_message(&mut [0u8; MESSAGE_LEN - 1]),
            Err(OcpError::BufferTooSmall)
        );
    }
}
