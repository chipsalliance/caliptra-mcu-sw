// Licensed under the Apache-2.0 license

//! RECOVERY_CTRL (cmd=0x26) command structure.
//!
//! Spec reference: Section 9.2, "RECOVERY" / Sections 7.4-7.6.
//! A 3-byte RW command controlling recovery image selection and activation.
//! This command is required (scope A).

use zerocopy::{Immutable, IntoBytes, TryFromBytes};

use crate::error::OcpError;

/// Wire size of a RECOVERY_CTRL message in bytes, according to the Spec.
pub const MESSAGE_LEN: usize = 3;

// Assure the spec size matches the size of the structure.
const _: () = assert!(MESSAGE_LEN == size_of::<RecoveryCtrl>());

/// Byte 1: Recovery Image Selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable, TryFromBytes)]
#[repr(u8)]
pub enum ImageSelection {
    /// No operation.
    NoOperation = 0x00,
    /// Use recovery image from memory window (CMS).
    MemoryWindow = 0x01,
    /// Use recovery image stored on Device (local C-image).
    LocalCImage = 0x02,
}

/// Byte 2: Activate Recovery Image (Write 1, Device Clears).
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable, TryFromBytes)]
#[repr(u8)]
pub enum ActivateRecoveryImage {
    /// Do not activate recovery image.
    DoNotActivate = 0x00,
    /// Activate recovery image.
    Activate = 0x0F,
}

/// RECOVERY_CTRL command (3 bytes on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable, TryFromBytes)]
#[repr(C, packed)]
pub struct RecoveryCtrl {
    /// Byte 0: Component Memory Space (CMS) index (0-255). 0 is the default.
    pub cms: u8,
    /// Byte 1: Recovery image selection.
    pub image_selection: ImageSelection,
    /// Byte 2: Activate recovery image.
    pub activate: ActivateRecoveryImage,
}

impl RecoveryCtrl {
    pub fn new(cms: u8, image_selection: ImageSelection, activate: ActivateRecoveryImage) -> Self {
        Self {
            cms,
            image_selection,
            activate,
        }
    }

    /// Deserialize from a byte slice.
    ///
    /// Returns an error if the slice length does not match [`MESSAGE_LEN`]
    /// or contains a reserved value in any field.
    pub fn from_message(msg: &[u8]) -> Result<Self, OcpError> {
        if msg.len() < MESSAGE_LEN {
            return Err(OcpError::MessageTooShort);
        }
        if msg.len() > MESSAGE_LEN {
            return Err(OcpError::MessageTooLong);
        }

        RecoveryCtrl::try_read_from_prefix(msg)
            .map(|(s, _)| s)
            .map_err(|_| OcpError::RecoveryCtrlInvalid)
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
    fn valid_recovery_ctrl_to_message() {
        let cmd = RecoveryCtrl::new(
            0,
            ImageSelection::MemoryWindow,
            ActivateRecoveryImage::Activate,
        );
        let mut buf = [0u8; MESSAGE_LEN];
        let len = cmd.to_message(&mut buf).unwrap();

        assert_eq!(len, MESSAGE_LEN);
        assert_eq!(buf[0], 0x00);
        assert_eq!(buf[1], 0x01);
        assert_eq!(buf[2], 0x0F);
    }

    #[test]
    fn select_local_c_image_without_activation() {
        let cmd = RecoveryCtrl::new(
            0,
            ImageSelection::LocalCImage,
            ActivateRecoveryImage::DoNotActivate,
        );
        let mut buf = [0u8; MESSAGE_LEN];
        cmd.to_message(&mut buf).unwrap();

        assert_eq!(buf, [0x00, 0x02, 0x00]);
    }

    #[test]
    fn nonzero_cms_index() {
        let cmd = RecoveryCtrl::new(
            5,
            ImageSelection::MemoryWindow,
            ActivateRecoveryImage::DoNotActivate,
        );
        let mut buf = [0u8; MESSAGE_LEN];
        cmd.to_message(&mut buf).unwrap();

        assert_eq!(buf[0], 5);
    }

    #[test]
    fn from_message_valid() {
        let cmd = RecoveryCtrl::from_message(&[0x03, 0x01, 0x0F]).unwrap();
        assert_eq!(cmd.cms, 3);
        assert_eq!(cmd.image_selection, ImageSelection::MemoryWindow);
        assert_eq!(cmd.activate, ActivateRecoveryImage::Activate);
    }

    #[test]
    fn from_message_too_short() {
        assert_eq!(
            RecoveryCtrl::from_message(&[]),
            Err(OcpError::MessageTooShort)
        );
        assert_eq!(
            RecoveryCtrl::from_message(&[0x00]),
            Err(OcpError::MessageTooShort)
        );
        assert_eq!(
            RecoveryCtrl::from_message(&[0x00, 0x00]),
            Err(OcpError::MessageTooShort)
        );
    }

    #[test]
    fn from_message_too_long() {
        assert_eq!(
            RecoveryCtrl::from_message(&[0x00, 0x00, 0x00, 0x00]),
            Err(OcpError::MessageTooLong)
        );
    }

    #[test]
    fn from_message_reserved_image_selection() {
        assert_eq!(
            RecoveryCtrl::from_message(&[0x00, 0x03, 0x00]),
            Err(OcpError::RecoveryCtrlInvalid)
        );
        assert_eq!(
            RecoveryCtrl::from_message(&[0x00, 0xFF, 0x00]),
            Err(OcpError::RecoveryCtrlInvalid)
        );
    }

    #[test]
    fn from_message_reserved_activate() {
        assert_eq!(
            RecoveryCtrl::from_message(&[0x00, 0x00, 0x01]),
            Err(OcpError::RecoveryCtrlInvalid)
        );
        assert_eq!(
            RecoveryCtrl::from_message(&[0x00, 0x00, 0x0E]),
            Err(OcpError::RecoveryCtrlInvalid)
        );
        assert_eq!(
            RecoveryCtrl::from_message(&[0x00, 0x00, 0x10]),
            Err(OcpError::RecoveryCtrlInvalid)
        );
    }

    #[test]
    fn from_message_round_trip() {
        let original = RecoveryCtrl::new(
            255,
            ImageSelection::LocalCImage,
            ActivateRecoveryImage::Activate,
        );
        let mut buf = [0u8; MESSAGE_LEN];
        original.to_message(&mut buf).unwrap();
        let parsed = RecoveryCtrl::from_message(&buf).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn to_message_buffer_too_small() {
        let cmd = RecoveryCtrl::new(
            0,
            ImageSelection::NoOperation,
            ActivateRecoveryImage::DoNotActivate,
        );
        assert_eq!(
            cmd.to_message(&mut [0u8; MESSAGE_LEN - 1]),
            Err(OcpError::BufferTooSmall)
        );
    }
}
