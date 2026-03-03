// Licensed under the Apache-2.0 license

//! INDIRECT_FIFO_STATUS (cmd=0x2E) response structure.
//!
//! Spec reference: Section 9.2 / Section 8.2.5, "Indirect FIFO CMS".
//! A 20-byte RO command reporting status, region type, indices, FIFO size,
//! and max transfer size for the FIFO CMS selected via INDIRECT_FIFO_CTRL.
//! This command is optional (scope R -- recovery interface must be active).

use bitfield::bitfield;
use zerocopy::{Immutable, IntoBytes, TryFromBytes};

use crate::error::OcpError;

/// Wire size of an INDIRECT_FIFO_STATUS message in bytes, according to the spec.
pub const MESSAGE_LEN: usize = 20;

// Assure the spec size matches the size of the structure.
const _: () = assert!(MESSAGE_LEN == size_of::<IndirectFifoStatus>());

/// Byte 1, bits 0-2: FIFO CMS region type.
///
/// Unlike [`super::indirect_status::CmsRegionType`], the FIFO variant has no
/// polling bit, different access directions, and no 0b110 encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Immutable, IntoBytes, TryFromBytes)]
#[repr(u8)]
pub enum FifoCmsRegionType {
    /// Code space for recovery (Write Only).
    CodeSpace = 0b000,
    /// Log, debug format (Read Only).
    Log = 0b001,
    /// Vendor Defined Region (Write Only).
    VendorWo = 0b100,
    /// Vendor Defined Region (Read Only).
    VendorRo = 0b101,
    /// Unsupported Region (address space out of range).
    Unsupported = 0b111,
}

bitfield! {
    /// Byte 0 of INDIRECT_FIFO_STATUS — FIFO status flags.
    #[derive(Clone, Copy, PartialEq, Eq, Immutable, IntoBytes, TryFromBytes)]
    pub struct FifoStatusFlags(u8);
    impl Debug;

    /// Bit 0: FIFO is empty.
    pub bool, empty, set_empty: 0;
    /// Bit 1: FIFO is full.
    pub bool, full, set_full: 1;
}

/// INDIRECT_FIFO_STATUS response (20 bytes on the wire).
///
/// | Byte  | Field             |
/// |-------|-------------------|
/// | 0     | Status flags      |
/// | 1     | Region type       |
/// | 2-3   | Reserved          |
/// | 4-7   | Write Index (LE)  |
/// | 8-11  | Read Index (LE)   |
/// | 12-15 | FIFO Size (LE)    |
/// | 16-19 | Max Xfer Size (LE)|
#[derive(Debug, Clone, Copy, PartialEq, Eq, Immutable, IntoBytes, TryFromBytes)]
#[repr(C, packed)]
pub struct IndirectFifoStatus {
    /// Byte 0: FIFO status flags.
    status: FifoStatusFlags,
    /// Byte 1: region type (bits 0-2).
    region_type: FifoCmsRegionType,
    /// Bytes 2-3: Reserved
    reserved: u16,
    /// Bytes 4-7: Write Index in 4B units (little-endian).
    pub write_index: u32,
    /// Bytes 8-11: Read Index in 4B units (little-endian).
    pub read_index: u32,
    /// Bytes 12-15: FIFO size in 4B units (little-endian).
    pub fifo_size: u32,
    /// Bytes 16-19: Max transfer size in 4B units (little-endian).
    pub max_transfer_size: u32,
}

impl IndirectFifoStatus {
    /// Create a new INDIRECT_FIFO_STATUS response.
    pub fn new(
        status: FifoStatusFlags,
        region_type: FifoCmsRegionType,
        write_index: u32,
        read_index: u32,
        fifo_size: u32,
        max_transfer_size: u32,
    ) -> Self {
        Self {
            status,
            region_type,
            reserved: 0,
            write_index,
            read_index,
            fifo_size,
            max_transfer_size,
        }
    }

    /// Bit 0: FIFO is empty.
    pub fn empty(&self) -> bool {
        self.status.empty()
    }

    /// Bit 1: FIFO is full.
    pub fn full(&self) -> bool {
        self.status.full()
    }

    /// Byte 1, bits 0-2: FIFO CMS region type.
    pub fn region_type(&self) -> FifoCmsRegionType {
        self.region_type
    }

    /// Serialize into the wire representation.
    ///
    /// Reserved bytes 2-3 are written as zero.
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

    fn status_flags(empty: bool, full: bool) -> FifoStatusFlags {
        let mut f = FifoStatusFlags(0);
        f.set_empty(empty);
        f.set_full(full);
        f
    }

    #[test]
    fn default_all_clear() {
        let status =
            IndirectFifoStatus::new(FifoStatusFlags(0), FifoCmsRegionType::CodeSpace, 0, 0, 0, 0);
        let mut buf = [0xFFu8; MESSAGE_LEN];
        let len = status.to_message(&mut buf).unwrap();
        assert_eq!(len, MESSAGE_LEN);
        assert_eq!(buf, [0u8; 20]);
    }

    #[test]
    fn empty_flag() {
        let status = IndirectFifoStatus::new(
            status_flags(true, false),
            FifoCmsRegionType::CodeSpace,
            0,
            0,
            0,
            0,
        );
        assert!(status.empty());
        assert!(!status.full());
        let mut buf = [0u8; MESSAGE_LEN];
        status.to_message(&mut buf).unwrap();
        assert_eq!(buf[0], 0x01);
    }

    #[test]
    fn full_flag() {
        let status = IndirectFifoStatus::new(
            status_flags(false, true),
            FifoCmsRegionType::CodeSpace,
            0,
            0,
            0,
            0,
        );
        assert!(!status.empty());
        assert!(status.full());
        let mut buf = [0u8; MESSAGE_LEN];
        status.to_message(&mut buf).unwrap();
        assert_eq!(buf[0], 0x02);
    }

    #[test]
    fn both_flags_set() {
        let status = IndirectFifoStatus::new(
            status_flags(true, true),
            FifoCmsRegionType::CodeSpace,
            0,
            0,
            0,
            0,
        );
        let mut buf = [0u8; MESSAGE_LEN];
        status.to_message(&mut buf).unwrap();
        assert_eq!(buf[0], 0x03);
    }

    #[test]
    fn all_region_types_serialize() {
        let types = [
            (FifoCmsRegionType::CodeSpace, 0b000u8),
            (FifoCmsRegionType::Log, 0b001),
            (FifoCmsRegionType::VendorWo, 0b100),
            (FifoCmsRegionType::VendorRo, 0b101),
            (FifoCmsRegionType::Unsupported, 0b111),
        ];
        for (rt, expected) in types {
            let status = IndirectFifoStatus::new(FifoStatusFlags(0), rt, 0, 0, 0, 0);
            assert_eq!(status.region_type(), rt);
            let mut buf = [0u8; MESSAGE_LEN];
            status.to_message(&mut buf).unwrap();
            assert_eq!(buf[1], expected, "mismatch for {:?}", rt);
        }
    }

    #[test]
    fn reserved_bytes_are_zero() {
        let status = IndirectFifoStatus::new(
            FifoStatusFlags(0),
            FifoCmsRegionType::CodeSpace,
            0xFFFF_FFFF,
            0xFFFF_FFFF,
            0xFFFF_FFFF,
            0xFFFF_FFFF,
        );
        let mut buf = [0u8; MESSAGE_LEN];
        status.to_message(&mut buf).unwrap();
        assert_eq!(buf[2], 0x00);
        assert_eq!(buf[3], 0x00);
    }

    #[test]
    fn write_index_little_endian() {
        let status = IndirectFifoStatus::new(
            FifoStatusFlags(0),
            FifoCmsRegionType::CodeSpace,
            0x04030201,
            0,
            0,
            0,
        );
        let mut buf = [0u8; MESSAGE_LEN];
        status.to_message(&mut buf).unwrap();
        assert_eq!(buf[4], 0x01);
        assert_eq!(buf[5], 0x02);
        assert_eq!(buf[6], 0x03);
        assert_eq!(buf[7], 0x04);
    }

    #[test]
    fn read_index_little_endian() {
        let status = IndirectFifoStatus::new(
            FifoStatusFlags(0),
            FifoCmsRegionType::CodeSpace,
            0,
            0x04030201,
            0,
            0,
        );
        let mut buf = [0u8; MESSAGE_LEN];
        status.to_message(&mut buf).unwrap();
        assert_eq!(buf[8], 0x01);
        assert_eq!(buf[9], 0x02);
        assert_eq!(buf[10], 0x03);
        assert_eq!(buf[11], 0x04);
    }

    #[test]
    fn fifo_size_little_endian() {
        let status = IndirectFifoStatus::new(
            FifoStatusFlags(0),
            FifoCmsRegionType::CodeSpace,
            0,
            0,
            0x04030201,
            0,
        );
        let mut buf = [0u8; MESSAGE_LEN];
        status.to_message(&mut buf).unwrap();
        assert_eq!(buf[12], 0x01);
        assert_eq!(buf[13], 0x02);
        assert_eq!(buf[14], 0x03);
        assert_eq!(buf[15], 0x04);
    }

    #[test]
    fn max_transfer_size_little_endian() {
        let status = IndirectFifoStatus::new(
            FifoStatusFlags(0),
            FifoCmsRegionType::CodeSpace,
            0,
            0,
            0,
            0x04030201,
        );
        let mut buf = [0u8; MESSAGE_LEN];
        status.to_message(&mut buf).unwrap();
        assert_eq!(buf[16], 0x01);
        assert_eq!(buf[17], 0x02);
        assert_eq!(buf[18], 0x03);
        assert_eq!(buf[19], 0x04);
    }

    #[test]
    fn full_message_with_all_fields() {
        let status = IndirectFifoStatus::new(
            status_flags(true, false),
            FifoCmsRegionType::VendorWo,
            0x0000_0010,
            0x0000_0004,
            0x0000_0100,
            0x0000_0040,
        );
        let mut buf = [0u8; MESSAGE_LEN];
        status.to_message(&mut buf).unwrap();

        assert_eq!(buf[0], 0x01);
        assert_eq!(buf[1], 0b100);
        assert_eq!(buf[2], 0x00);
        assert_eq!(buf[3], 0x00);
        assert_eq!(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]), 0x10);
        assert_eq!(u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]), 0x04);
        assert_eq!(
            u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
            0x100
        );
        assert_eq!(
            u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]),
            0x40
        );
    }

    #[test]
    fn to_message_buffer_too_small() {
        let status =
            IndirectFifoStatus::new(FifoStatusFlags(0), FifoCmsRegionType::CodeSpace, 0, 0, 0, 0);
        assert_eq!(
            status.to_message(&mut [0u8; MESSAGE_LEN - 1]),
            Err(OcpError::BufferTooSmall)
        );
    }
}
