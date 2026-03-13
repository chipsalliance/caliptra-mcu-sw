// Licensed under the Apache-2.0 license

//! INDIRECT_CTRL (cmd=0x29) command structure.
//!
//! Spec reference: Section 9.2, "INDIRECT" / Indirect Memory Rules.
//! A 6-byte RW command controlling CMS selection and indirect memory offset.
//! This command is optional (scope R -- recovery interface must be active).

use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::error::OcpError;

/// Wire size of an INDIRECT_CTRL message in bytes, according to the spec.
pub const MESSAGE_LEN: usize = 6;

// Assure the spec size matches the size of the structure.
const _: () = assert!(MESSAGE_LEN == size_of::<IndirectCtrl>());

/// INDIRECT_CTRL command (6 bytes on the wire).
///
/// | Byte | Field    |
/// |------|----------|
/// | 0    | CMS      |
/// | 1    | Reserved |
/// | 2-5  | IMO (LE) |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Immutable, IntoBytes, FromBytes)]
#[repr(C, packed)]
pub struct IndirectCtrl {
    /// Byte 0: Component Memory Space index (0-255).
    pub cms: u8,
    //  Byte 1: Reserved and not used.
    reserved: u8,
    /// Bytes 2-5: Indirect Memory Offset (little-endian, 4-byte aligned).
    imo: u32,
}

impl IndirectCtrl {
    /// Create a new INDIRECT_CTRL command.
    ///
    /// Returns an error if `imo` is not 4-byte aligned (bits 1:0 must be zero).
    pub fn new(cms: u8, imo: u32) -> Result<Self, OcpError> {
        if imo & 0x3 != 0 {
            return Err(OcpError::IndirectCtrlImoNotAligned);
        }
        Ok(Self {
            cms,
            reserved: 0,
            imo,
        })
    }

    /// Return the imo of the IndirectCtrl structure.
    pub fn imo(&self) -> u32 {
        // Note: Since the IMO u32 but is unaligned in the packed memory map, copy it to an aligned
        // position for use by consumers.
        self.imo
    }

    /// Deserialize from a byte slice.
    ///
    /// Returns an error if the slice length does not match [`MESSAGE_LEN`].
    /// Byte 1 (reserved) is ignored on read.
    pub fn from_message(msg: &[u8]) -> Result<Self, OcpError> {
        if msg.len() > MESSAGE_LEN {
            return Err(OcpError::MessageTooLong);
        }

        let (s, _) = IndirectCtrl::read_from_prefix(msg).map_err(|_| OcpError::MessageTooShort)?;
        if s.imo & 0x3 != 0 {
            return Err(OcpError::IndirectCtrlImoNotAligned);
        }
        Ok(s)
    }

    /// Serialize into the wire representation.
    ///
    /// Byte 1 (reserved) is written as zero.
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
    fn valid_to_message() {
        let cmd = IndirectCtrl::new(3, 0x100).unwrap();
        let mut buf = [0u8; MESSAGE_LEN];
        let len = cmd.to_message(&mut buf).unwrap();

        assert_eq!(len, MESSAGE_LEN);
        assert_eq!(buf[0], 3);
        assert_eq!(buf[1], 0x00);
        assert_eq!(u32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]), 0x100);
    }

    #[test]
    fn zero_imo_accepted() {
        let cmd = IndirectCtrl::new(0, 0).unwrap();
        assert_eq!(cmd.imo(), 0);
    }

    #[test]
    fn max_aligned_imo_accepted() {
        let cmd = IndirectCtrl::new(0, 0xFFFF_FFFC).unwrap();
        assert_eq!(cmd.imo(), 0xFFFF_FFFC);
    }

    #[test]
    fn misaligned_imo_rejected() {
        assert_eq!(
            IndirectCtrl::new(0, 1),
            Err(OcpError::IndirectCtrlImoNotAligned)
        );
        assert_eq!(
            IndirectCtrl::new(0, 2),
            Err(OcpError::IndirectCtrlImoNotAligned)
        );
        assert_eq!(
            IndirectCtrl::new(0, 3),
            Err(OcpError::IndirectCtrlImoNotAligned)
        );
        assert_eq!(
            IndirectCtrl::new(0, 0xFF),
            Err(OcpError::IndirectCtrlImoNotAligned)
        );
    }

    #[test]
    fn reserved_byte_is_zero_on_serialize() {
        let cmd = IndirectCtrl::new(0xFF, 0x1000).unwrap();
        let mut buf = [0u8; MESSAGE_LEN];
        cmd.to_message(&mut buf).unwrap();
        assert_eq!(buf[1], 0x00);
    }

    #[test]
    fn little_endian_imo_encoding() {
        let cmd = IndirectCtrl::new(0, 0x04030200).unwrap();
        let mut buf = [0u8; MESSAGE_LEN];
        cmd.to_message(&mut buf).unwrap();
        assert_eq!(buf[2], 0x00); // 0x04030200 LE: byte 0 = 0x00
        assert_eq!(buf[3], 0x02);
        assert_eq!(buf[4], 0x03);
        assert_eq!(buf[5], 0x04);
    }

    #[test]
    fn from_message_valid() {
        let cmd = IndirectCtrl::from_message(&[5, 0x00, 0x04, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(cmd.cms, 5);
        assert_eq!(cmd.imo(), 4);
    }

    #[test]
    fn from_message_ignores_reserved_byte() {
        let cmd = IndirectCtrl::from_message(&[0, 0xFF, 0x00, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(cmd.cms, 0);
        assert_eq!(cmd.imo(), 0);
    }

    #[test]
    fn from_message_too_short() {
        assert_eq!(
            IndirectCtrl::from_message(&[]),
            Err(OcpError::MessageTooShort)
        );
        assert_eq!(
            IndirectCtrl::from_message(&[0x00]),
            Err(OcpError::MessageTooShort)
        );
        assert_eq!(
            IndirectCtrl::from_message(&[0x00; 5]),
            Err(OcpError::MessageTooShort),
        );
    }

    #[test]
    fn from_message_too_long() {
        assert_eq!(
            IndirectCtrl::from_message(&[0x00; 7]),
            Err(OcpError::MessageTooLong),
        );
    }

    #[test]
    fn from_message_misaligned_imo_rejected() {
        // IMO = 1 (bits 1:0 = 0b01)
        assert_eq!(
            IndirectCtrl::from_message(&[0, 0x00, 0x01, 0x00, 0x00, 0x00]),
            Err(OcpError::IndirectCtrlImoNotAligned),
        );
        // IMO = 2 (bits 1:0 = 0b10)
        assert_eq!(
            IndirectCtrl::from_message(&[0, 0x00, 0x02, 0x00, 0x00, 0x00]),
            Err(OcpError::IndirectCtrlImoNotAligned),
        );
        // IMO = 3 (bits 1:0 = 0b11)
        assert_eq!(
            IndirectCtrl::from_message(&[0, 0x00, 0x03, 0x00, 0x00, 0x00]),
            Err(OcpError::IndirectCtrlImoNotAligned),
        );
        // IMO = 0xFF (misaligned)
        assert_eq!(
            IndirectCtrl::from_message(&[0, 0x00, 0xFF, 0x00, 0x00, 0x00]),
            Err(OcpError::IndirectCtrlImoNotAligned),
        );
    }

    #[test]
    fn from_message_round_trip() {
        let original = IndirectCtrl::new(42, 0x0000_1000).unwrap();
        let mut buf = [0u8; MESSAGE_LEN];
        original.to_message(&mut buf).unwrap();
        let parsed = IndirectCtrl::from_message(&buf).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn to_message_buffer_too_small() {
        let cmd = IndirectCtrl::new(0, 0).unwrap();
        assert_eq!(
            cmd.to_message(&mut [0u8; MESSAGE_LEN - 1]),
            Err(OcpError::BufferTooSmall)
        );
    }
}
