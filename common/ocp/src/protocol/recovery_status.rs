// Licensed under the Apache-2.0 license

//! RECOVERY_STATUS (cmd=0x27) response structure.
//!
//! Spec reference: Section 9.2, "RECOVERY_STATUS" / Section 7.6.
//! A 2-byte RO command reporting recovery debug status.
//! This command is required (scope R -- recovery interface must be active).

use bitfield::bitfield;
use zerocopy::{Immutable, IntoBytes};

use crate::error::OcpError;

/// Wire size of a RECOVERY_STATUS message in bytes.
pub const MESSAGE_LEN: usize = 2;

// Assure the spec size matches the size of the structure.
const _: () = assert!(MESSAGE_LEN == size_of::<RecoveryStatus>());

/// Byte 0, bits 0-3: Device Recovery Status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
#[repr(u8)]
pub enum DeviceRecoveryStatus {
    /// Not in recovery mode.
    NotInRecovery = 0x0,
    /// Awaiting recovery image.
    AwaitingImage = 0x1,
    /// Booting recovery image.
    BootingImage = 0x2,
    /// Recovery successful.
    Success = 0x3,
    /// Recovery failed.
    Failed = 0xC,
    /// Recovery image authentication error.
    AuthenticationError = 0xD,
    /// Error entering recovery mode (may be administratively disabled).
    ErrorEnteringRecovery = 0xE,
    /// Invalid component address space.
    InvalidCms = 0xF,
}

impl TryFrom<u8> for DeviceRecoveryStatus {
    type Error = OcpError;

    fn try_from(value: u8) -> Result<Self, OcpError> {
        match value {
            0x0 => Ok(Self::NotInRecovery),
            0x1 => Ok(Self::AwaitingImage),
            0x2 => Ok(Self::BootingImage),
            0x3 => Ok(Self::Success),
            0xC => Ok(Self::Failed),
            0xD => Ok(Self::AuthenticationError),
            0xE => Ok(Self::ErrorEnteringRecovery),
            0xF => Ok(Self::InvalidCms),
            _ => Err(OcpError::RecoveryStatusInvalidStatus),
        }
    }
}

bitfield! {
    /// Byte 0 of RECOVERY_STATUS, packing the status nibble and image index.
    #[derive(Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
    pub struct RecoveryStatusByte0(u8);
    impl Debug;

    /// Bits 0-3: Device recovery status code.
    pub u8, status, set_status: 3, 0;
    /// Bits 4-7: Recovery image index (incremented after each successful stage).
    pub u8, image_index, set_image_index: 7, 4;
}

/// RECOVERY_STATUS response (2 bytes on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct RecoveryStatus {
    /// Byte 0: packed status nibble and image index.
    byte0: RecoveryStatusByte0,
    /// Byte 1: Vendor specific status.
    pub vendor_status: u8,
}

impl RecoveryStatus {
    /// Create a new RECOVERY_STATUS response.
    ///
    /// Returns an error if `image_index` exceeds the 4-bit range (0-15).
    pub fn new(
        status: DeviceRecoveryStatus,
        image_index: u8,
        vendor_status: u8,
    ) -> Result<Self, OcpError> {
        if image_index > 0x0F {
            return Err(OcpError::RecoveryStatusImageIndexOutOfRange);
        }
        let mut byte0 = RecoveryStatusByte0(0);
        byte0.set_status(status as u8);
        byte0.set_image_index(image_index);
        Ok(Self {
            byte0,
            vendor_status,
        })
    }

    /// Set the status of the recovery control block.
    pub fn set_status(&mut self, status: DeviceRecoveryStatus) {
        self.byte0.set_status(status as u8);
    }

    /// Byte 0, bits 0-3: Device recovery status.
    pub fn status(&self) -> Result<DeviceRecoveryStatus, OcpError> {
        DeviceRecoveryStatus::try_from(self.byte0.status())
    }

    /// Set the image index.
    pub fn set_image_index(&mut self, index: u8) {
        self.byte0.set_image_index(index);
    }

    /// Byte 0, bits 4-7: Recovery image index (0-15).
    pub fn image_index(&self) -> u8 {
        self.byte0.image_index()
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
    fn awaiting_image_to_message() {
        let resp = RecoveryStatus::new(DeviceRecoveryStatus::AwaitingImage, 0, 0x00).unwrap();
        let mut buf = [0u8; MESSAGE_LEN];
        let len = resp.to_message(&mut buf).unwrap();

        assert_eq!(len, MESSAGE_LEN);
        assert_eq!(buf[0], 0x01);
        assert_eq!(buf[1], 0x00);
    }

    #[test]
    fn success_with_image_index_to_message() {
        let resp = RecoveryStatus::new(DeviceRecoveryStatus::Success, 2, 0x00).unwrap();
        assert_eq!(resp.status().unwrap(), DeviceRecoveryStatus::Success);
        assert_eq!(resp.image_index(), 2);

        let mut buf = [0u8; MESSAGE_LEN];
        resp.to_message(&mut buf).unwrap();
        assert_eq!(buf[0], 0x23);
    }

    #[test]
    fn max_image_index_accepted() {
        let resp = RecoveryStatus::new(DeviceRecoveryStatus::AwaitingImage, 15, 0x00).unwrap();
        assert_eq!(resp.image_index(), 15);

        let mut buf = [0u8; MESSAGE_LEN];
        resp.to_message(&mut buf).unwrap();
        assert_eq!(buf[0], 0xF1);
    }

    #[test]
    fn image_index_out_of_range_rejected() {
        assert_eq!(
            RecoveryStatus::new(DeviceRecoveryStatus::AwaitingImage, 16, 0x00),
            Err(OcpError::RecoveryStatusImageIndexOutOfRange),
        );
    }

    #[test]
    fn vendor_status_preserved() {
        let resp = RecoveryStatus::new(DeviceRecoveryStatus::Failed, 0, 0xAB).unwrap();
        let mut buf = [0u8; MESSAGE_LEN];
        resp.to_message(&mut buf).unwrap();

        assert_eq!(buf[1], 0xAB);
    }

    #[test]
    fn all_status_codes_serialize() {
        let codes = [
            (DeviceRecoveryStatus::NotInRecovery, 0x0u8),
            (DeviceRecoveryStatus::AwaitingImage, 0x1),
            (DeviceRecoveryStatus::BootingImage, 0x2),
            (DeviceRecoveryStatus::Success, 0x3),
            (DeviceRecoveryStatus::Failed, 0xC),
            (DeviceRecoveryStatus::AuthenticationError, 0xD),
            (DeviceRecoveryStatus::ErrorEnteringRecovery, 0xE),
            (DeviceRecoveryStatus::InvalidCms, 0xF),
        ];
        for (status, expected) in codes {
            let resp = RecoveryStatus::new(status, 0, 0).unwrap();
            let mut buf = [0u8; MESSAGE_LEN];
            resp.to_message(&mut buf).unwrap();
            assert_eq!(buf[0] & 0x0F, expected, "mismatch for {:?}", status);
        }
    }

    #[test]
    fn to_message_buffer_too_small() {
        let resp = RecoveryStatus::new(DeviceRecoveryStatus::AwaitingImage, 0, 0x00).unwrap();
        assert_eq!(
            resp.to_message(&mut [0u8; MESSAGE_LEN - 1]),
            Err(OcpError::BufferTooSmall)
        );
    }
}
