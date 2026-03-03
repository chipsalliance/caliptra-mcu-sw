// Licensed under the Apache-2.0 license

//! INDIRECT_FIFO_CTRL (cmd=0x2D) command structure.
//!
//! Spec reference: Section 9.2 / Section 8.2.5, "Indirect FIFO CMS".
//! A 6-byte RW command controlling CMS selection, FIFO reset, and image size
//! for FIFO-based Component Memory Spaces (PROT_CAP bit 12).
//! This command is optional (scope R -- recovery interface must be active).

use crate::error::OcpError;

/// Wire size of an INDIRECT_FIFO_CTRL message in bytes.
pub const MESSAGE_LEN: usize = 6;

/// INDIRECT_FIFO_CTRL command (6 bytes on the wire).
///
/// | Byte | Field            |
/// |------|------------------|
/// | 0    | CMS              |
/// | 1    | Reset            |
/// | 2-5  | Image Size (LE)  |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndirectFifoCtrl {
    /// Byte 0: Component Memory Space index (0-255).
    pub cms: u8,
    /// Byte 1: Reset FIFO (write 1, device clears).
    /// `true` = reset Write Index and Read Index to initial value (FIFO empty).
    /// `false` = idle / no reset.
    pub reset: bool,
    /// Bytes 2-5: Size of the image to be loaded, in 4-byte units (little-endian).
    pub image_size: u32,
}

impl IndirectFifoCtrl {
    /// Create a new INDIRECT_FIFO_CTRL command.
    pub fn new(cms: u8, reset: bool, image_size: u32) -> Self {
        Self {
            cms,
            reset,
            image_size,
        }
    }

    /// Deserialize from a byte slice.
    ///
    /// Returns an error if the slice length does not match [`MESSAGE_LEN`]
    /// or if byte 1 (Reset) contains a reserved value (0x02-0xFF).
    pub fn from_message(msg: &[u8]) -> Result<Self, OcpError> {
        if msg.len() < MESSAGE_LEN {
            return Err(OcpError::MessageTooShort);
        }
        if msg.len() > MESSAGE_LEN {
            return Err(OcpError::MessageTooLong);
        }
        let cms = msg[0];
        let reset = match msg[1] {
            0x00 => false,
            0x01 => true,
            _ => return Err(OcpError::IndirectFifoCtrlInvalidReset),
        };
        let image_size = u32::from_le_bytes([msg[2], msg[3], msg[4], msg[5]]);
        Ok(Self {
            cms,
            reset,
            image_size,
        })
    }

    /// Serialize into the wire representation.
    ///
    /// Returns an error if the buffer is too small.
    /// On success, returns the number of bytes written ([`MESSAGE_LEN`]).
    pub fn to_message(self, buf: &mut [u8]) -> Result<usize, OcpError> {
        if buf.len() < MESSAGE_LEN {
            return Err(OcpError::BufferTooSmall);
        }
        let image_size_bytes = self.image_size.to_le_bytes();
        buf[0] = self.cms;
        buf[1] = if self.reset { 0x01 } else { 0x00 };
        buf[2] = image_size_bytes[0];
        buf[3] = image_size_bytes[1];
        buf[4] = image_size_bytes[2];
        buf[5] = image_size_bytes[3];
        Ok(MESSAGE_LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_message_idle() {
        let cmd = IndirectFifoCtrl::new(3, false, 0x100);
        let mut buf = [0u8; MESSAGE_LEN];
        let len = cmd.to_message(&mut buf).unwrap();

        assert_eq!(len, MESSAGE_LEN);
        assert_eq!(buf[0], 3);
        assert_eq!(buf[1], 0x00);
        assert_eq!(u32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]), 0x100);
    }

    #[test]
    fn to_message_reset() {
        let cmd = IndirectFifoCtrl::new(0, true, 0);
        let mut buf = [0u8; MESSAGE_LEN];
        cmd.to_message(&mut buf).unwrap();

        assert_eq!(buf[0], 0);
        assert_eq!(buf[1], 0x01);
        assert_eq!(u32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]), 0);
    }

    #[test]
    fn zero_image_size_accepted() {
        let cmd = IndirectFifoCtrl::new(0, false, 0);
        assert_eq!(cmd.image_size, 0);
    }

    #[test]
    fn max_image_size_accepted() {
        let cmd = IndirectFifoCtrl::new(0, false, u32::MAX);
        assert_eq!(cmd.image_size, u32::MAX);
    }

    #[test]
    fn little_endian_image_size_encoding() {
        let cmd = IndirectFifoCtrl::new(0, false, 0x04030201);
        let mut buf = [0u8; MESSAGE_LEN];
        cmd.to_message(&mut buf).unwrap();
        assert_eq!(buf[2], 0x01);
        assert_eq!(buf[3], 0x02);
        assert_eq!(buf[4], 0x03);
        assert_eq!(buf[5], 0x04);
    }

    #[test]
    fn from_message_valid_idle() {
        let cmd = IndirectFifoCtrl::from_message(&[5, 0x00, 0x04, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(cmd.cms, 5);
        assert!(!cmd.reset);
        assert_eq!(cmd.image_size, 4);
    }

    #[test]
    fn from_message_valid_reset() {
        let cmd = IndirectFifoCtrl::from_message(&[0, 0x01, 0x00, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(cmd.cms, 0);
        assert!(cmd.reset);
        assert_eq!(cmd.image_size, 0);
    }

    #[test]
    fn from_message_reserved_reset_rejected() {
        for val in [0x02, 0x03, 0x80, 0xFF] {
            assert_eq!(
                IndirectFifoCtrl::from_message(&[0, val, 0x00, 0x00, 0x00, 0x00]),
                Err(OcpError::IndirectFifoCtrlInvalidReset),
            );
        }
    }

    #[test]
    fn from_message_too_short() {
        assert_eq!(
            IndirectFifoCtrl::from_message(&[]),
            Err(OcpError::MessageTooShort)
        );
        assert_eq!(
            IndirectFifoCtrl::from_message(&[0x00]),
            Err(OcpError::MessageTooShort)
        );
        assert_eq!(
            IndirectFifoCtrl::from_message(&[0x00; 5]),
            Err(OcpError::MessageTooShort),
        );
    }

    #[test]
    fn from_message_too_long() {
        assert_eq!(
            IndirectFifoCtrl::from_message(&[0x00; 7]),
            Err(OcpError::MessageTooLong),
        );
    }

    #[test]
    fn from_message_round_trip_idle() {
        let original = IndirectFifoCtrl::new(42, false, 0x0000_1000);
        let mut buf = [0u8; MESSAGE_LEN];
        original.to_message(&mut buf).unwrap();
        let parsed = IndirectFifoCtrl::from_message(&buf).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn from_message_round_trip_reset() {
        let original = IndirectFifoCtrl::new(7, true, 0xABCD_0000);
        let mut buf = [0u8; MESSAGE_LEN];
        original.to_message(&mut buf).unwrap();
        let parsed = IndirectFifoCtrl::from_message(&buf).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn to_message_buffer_too_small() {
        let cmd = IndirectFifoCtrl::new(0, false, 0);
        assert_eq!(
            cmd.to_message(&mut [0u8; MESSAGE_LEN - 1]),
            Err(OcpError::BufferTooSmall)
        );
    }
}
