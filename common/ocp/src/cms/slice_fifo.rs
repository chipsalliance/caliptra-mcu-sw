// Licensed under the Apache-2.0 license

//! Slice-backed [`FifoCmsRegion`](crate::cms::FifoCmsRegion) implementation.
//!
//! Provides a concrete FIFO CMS region backed by a `&mut [u8]` ring buffer suitable
//! for `no_std` environments. The FIFO operates in 4-byte units internally.

use crate::cms::FifoCmsRegion;
use crate::error::{CmsError, OcpError};
use crate::protocol::indirect_fifo_status::{
    FifoCmsRegionType, FifoStatusFlags, IndirectFifoStatus,
};

/// A FIFO CMS region backed by a mutable byte slice used as a ring buffer.
///
/// The ring buffer tracks write and read positions in 4-byte units. The FIFO is
/// considered empty when `write_idx == read_idx` and full when advancing the write
/// index by one would cause it to equal the read index. This means the usable
/// capacity is `(buf.len() / 4) - 1` slots.
#[derive(Debug)]
pub struct SliceFifoRegion<'a> {
    buf: &'a mut [u8],
    region_type: FifoCmsRegionType,
    max_transfer_4b: u32,
    /// Tracks the write index in terms of 4 byte words.
    write_idx: u32,
    /// Tracks the read index in terms of 4 byte words.
    read_idx: u32,
}

impl<'a> SliceFifoRegion<'a> {
    /// Create a new slice-backed FIFO region.
    ///
    /// Returns [`OcpError::InvalidCmsBufferSize`] if `buf` is empty or its length
    /// is not a multiple of 4.
    pub fn new(
        buf: &'a mut [u8],
        region_type: FifoCmsRegionType,
        max_transfer_4b: u32,
    ) -> Result<Self, OcpError> {
        if buf.is_empty() || buf.len() % 4 != 0 {
            return Err(OcpError::InvalidCmsBufferSize);
        }
        Ok(Self {
            buf,
            region_type,
            max_transfer_4b,
            write_idx: 0,
            read_idx: 0,
        })
    }

    fn capacity_4b(&self) -> u32 {
        (self.buf.len() as u32) / 4
    }

    fn is_read_only(&self) -> bool {
        matches!(
            self.region_type,
            FifoCmsRegionType::Log | FifoCmsRegionType::VendorRo
        )
    }

    fn is_write_only(&self) -> bool {
        matches!(
            self.region_type,
            FifoCmsRegionType::CodeSpace | FifoCmsRegionType::VendorWo
        )
    }

    /// Returns true when the FIFO contains no data.
    pub fn is_empty(&self) -> bool {
        self.write_idx == self.read_idx
    }

    /// Returns true when the FIFO has no remaining capacity.
    pub fn is_full(&self) -> bool {
        (self.write_idx + 1) % self.capacity_4b() == self.read_idx
    }

    fn space_available_4b(&self) -> u32 {
        let cap = self.capacity_4b();
        (self.read_idx + cap - self.write_idx - 1) % cap
    }

    /// Push `data` into the FIFO regardless of region type.
    ///
    /// Returns [`CmsError::FifoFull`] if there is not enough space for the
    /// (4-byte-rounded) data.
    pub fn push_data(&mut self, data: &[u8]) -> Result<(), CmsError> {
        let data_4b = ((data.len() as u32) + 3) / 4;
        if data_4b > self.space_available_4b() {
            return Err(CmsError::FifoFull);
        }

        let cap = self.capacity_4b();
        let buf_byte_len = cap as usize * 4;
        for (i, &b) in data.iter().enumerate() {
            let pos = (self.write_idx as usize * 4 + i) % buf_byte_len;
            self.buf[pos] = b;
        }
        self.write_idx = (self.write_idx + data_4b) % cap;
        Ok(())
    }

    /// Pop data from the FIFO into `buf` regardless of region type.
    ///
    /// Returns [`CmsError::FifoEmpty`] if the FIFO contains no data. Otherwise
    /// returns the number of bytes read (up to `buf.len()`).
    pub fn pop_data(&mut self, buf: &mut [u8]) -> Result<usize, CmsError> {
        if self.is_empty() {
            return Err(CmsError::FifoEmpty);
        }
        let cap = self.capacity_4b();
        let occupancy_4b = (self.write_idx + cap - self.read_idx) % cap;
        let available_bytes = occupancy_4b as usize * 4;
        let read_len = buf.len().min(available_bytes);
        let consume_4b = ((read_len as u32) + 3) / 4;

        let buf_byte_len = cap as usize * 4;
        for (i, slot) in buf.iter_mut().enumerate().take(read_len) {
            let pos = (self.read_idx as usize * 4 + i) % buf_byte_len;
            *slot = self.buf[pos];
        }
        self.read_idx = (self.read_idx + consume_4b) % cap;
        Ok(read_len)
    }
}

impl FifoCmsRegion for SliceFifoRegion<'_> {
    fn status(&self) -> IndirectFifoStatus {
        let mut flags = FifoStatusFlags(0);
        flags.set_empty(self.is_empty());
        flags.set_full(self.is_full());
        IndirectFifoStatus::new(
            flags,
            self.region_type,
            self.write_idx,
            self.read_idx,
            self.capacity_4b(),
            self.max_transfer_4b,
        )
    }

    fn push(&mut self, data: &[u8]) -> Result<(), CmsError> {
        if self.is_read_only() {
            return Err(CmsError::ReadOnly);
        }
        self.push_data(data)
    }

    fn pop(&mut self, buf: &mut [u8]) -> Result<usize, CmsError> {
        if self.is_write_only() {
            return Err(CmsError::WriteOnly);
        }
        self.pop_data(buf)
    }

    fn reset(&mut self) {
        self.write_idx = 0;
        self.read_idx = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_data_and_pop_data() {
        let mut backing = [0u8; 32];
        let mut fifo = SliceFifoRegion::new(&mut backing, FifoCmsRegionType::CodeSpace, 2).unwrap();

        fifo.push_data(&[0x01, 0x02, 0x03, 0x04]).unwrap();
        assert!(!fifo.is_empty());

        let mut buf = [0u8; 4];
        let n = fifo.pop_data(&mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf, [0x01, 0x02, 0x03, 0x04]);
        assert!(fifo.is_empty());
    }

    #[test]
    fn push_data_until_full() {
        let mut backing = [0u8; 16]; // 4 slots, usable capacity = 3
        let mut fifo = SliceFifoRegion::new(&mut backing, FifoCmsRegionType::CodeSpace, 1).unwrap();

        fifo.push_data(&[0x01, 0x02, 0x03, 0x04]).unwrap();
        fifo.push_data(&[0x05, 0x06, 0x07, 0x08]).unwrap();
        fifo.push_data(&[0x09, 0x0A, 0x0B, 0x0C]).unwrap();

        assert!(fifo.is_full());
        assert_eq!(
            fifo.push_data(&[0x0D, 0x0E, 0x0F, 0x10]),
            Err(CmsError::FifoFull)
        );
    }

    #[test]
    fn pop_data_until_empty() {
        let mut backing = [0u8; 32];
        let mut fifo = SliceFifoRegion::new(&mut backing, FifoCmsRegionType::CodeSpace, 2).unwrap();

        fifo.push_data(&[0x01, 0x02, 0x03, 0x04]).unwrap();
        fifo.push_data(&[0x05, 0x06, 0x07, 0x08]).unwrap();

        let mut buf = [0u8; 4];
        let n = fifo.pop_data(&mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf, [0x01, 0x02, 0x03, 0x04]);

        let n = fifo.pop_data(&mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf, [0x05, 0x06, 0x07, 0x08]);

        assert!(fifo.is_empty());
        assert_eq!(fifo.pop_data(&mut buf), Err(CmsError::FifoEmpty));
    }

    #[test]
    fn wrap_around_write() {
        let mut backing = [0u8; 16]; // 4 slots
        let mut fifo = SliceFifoRegion::new(&mut backing, FifoCmsRegionType::CodeSpace, 1).unwrap();

        // Fill slots 0, 1, 2 (capacity is 3)
        fifo.push_data(&[0x01, 0x02, 0x03, 0x04]).unwrap();
        fifo.push_data(&[0x05, 0x06, 0x07, 0x08]).unwrap();
        fifo.push_data(&[0x09, 0x0A, 0x0B, 0x0C]).unwrap();
        assert!(fifo.is_full()); // write=3, read=0

        // Consumer advances read index, freeing slots 0 and 1
        let mut drain = [0; 8];
        fifo.pop_data(&mut drain).unwrap();
        assert!(!fifo.is_full());

        // Push wraps: writes to slot 3 (bytes 12-15), write_idx becomes 0
        fifo.push_data(&[0x10, 0x11, 0x12, 0x13]).unwrap();
        assert_eq!(fifo.write_idx, 0);

        // Push again: writes to slot 0 (bytes 0-3), write_idx becomes 1
        fifo.push_data(&[0x20, 0x21, 0x22, 0x23]).unwrap();
        assert_eq!(fifo.write_idx, 1);

        assert!(fifo.is_full()); // write=1, read=2, (1+1)%4 == 2

        // Verify data landed in the right slots
        assert_eq!(fifo.buf[12..16], [0x10, 0x11, 0x12, 0x13]);
        assert_eq!(fifo.buf[0..4], [0x20, 0x21, 0x22, 0x23]);
    }

    #[test]
    fn wrap_around_read() {
        let mut backing = [0u8; 16]; // 4 slots
        backing[8..12].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        backing[12..16].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        backing[0..4].copy_from_slice(&[0x55, 0x66, 0x77, 0x88]);

        let mut fifo = SliceFifoRegion::new(&mut backing, FifoCmsRegionType::CodeSpace, 1).unwrap();
        fifo.read_idx = 2;
        fifo.write_idx = 1;

        let mut buf = [0u8; 4];
        fifo.pop_data(&mut buf).unwrap();
        assert_eq!(buf, [0xAA, 0xBB, 0xCC, 0xDD]);

        fifo.pop_data(&mut buf).unwrap();
        assert_eq!(buf, [0x11, 0x22, 0x33, 0x44]);
        assert_eq!(fifo.read_idx, 0); // wrapped

        fifo.pop_data(&mut buf).unwrap();
        assert_eq!(buf, [0x55, 0x66, 0x77, 0x88]);
        assert!(fifo.is_empty());
    }

    #[test]
    fn reset_clears_indices() {
        let mut backing = [0u8; 32];
        let mut fifo = SliceFifoRegion::new(&mut backing, FifoCmsRegionType::CodeSpace, 2).unwrap();

        fifo.push_data(&[0x01, 0x02, 0x03, 0x04]).unwrap();
        fifo.push_data(&[0x05, 0x06, 0x07, 0x08]).unwrap();
        assert!(!fifo.is_empty());

        fifo.reset();
        assert!(fifo.is_empty());
        assert_eq!(fifo.write_idx, 0);
        assert_eq!(fifo.read_idx, 0);
    }

    #[test]
    fn read_only_rejects_push() {
        let mut backing = [0u8; 32];
        let mut fifo = SliceFifoRegion::new(&mut backing, FifoCmsRegionType::Log, 2).unwrap();
        assert_eq!(fifo.push(&[0x01]), Err(CmsError::ReadOnly));
    }

    #[test]
    fn write_only_rejects_pop() {
        let mut backing = [0u8; 32];
        let mut fifo = SliceFifoRegion::new(&mut backing, FifoCmsRegionType::CodeSpace, 2).unwrap();

        fifo.push_data(&[0x01, 0x02, 0x03, 0x04]).unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(fifo.pop(&mut buf), Err(CmsError::WriteOnly));
    }

    #[test]
    fn empty_buffer_rejected() {
        let mut backing = [0u8; 0];
        assert_eq!(
            SliceFifoRegion::new(&mut backing, FifoCmsRegionType::CodeSpace, 1).unwrap_err(),
            OcpError::InvalidCmsBufferSize,
        );
    }

    #[test]
    fn unaligned_buffer_rejected() {
        let mut backing = [0u8; 7];
        assert_eq!(
            SliceFifoRegion::new(&mut backing, FifoCmsRegionType::CodeSpace, 1).unwrap_err(),
            OcpError::InvalidCmsBufferSize,
        );
    }

    #[test]
    fn status_reports_metadata() {
        let mut backing = [0u8; 64];
        let fifo = SliceFifoRegion::new(&mut backing, FifoCmsRegionType::VendorWo, 4).unwrap();

        let s = fifo.status();
        assert_eq!(s.fifo_size(), 16);
        assert_eq!(s.max_transfer_size(), 4);
        assert_eq!(s.region_type(), FifoCmsRegionType::VendorWo);
    }

    #[test]
    fn multi_slot_push_data() {
        let mut backing = [0u8; 32]; // 8 slots, usable = 7
        let mut fifo = SliceFifoRegion::new(&mut backing, FifoCmsRegionType::CodeSpace, 2).unwrap();

        fifo.push_data(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
            .unwrap();
        assert_eq!(fifo.write_idx, 2);
        assert_eq!(
            fifo.buf[0..8],
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn non_4byte_aligned_push_rounds_up() {
        let mut backing = [0u8; 32];
        let mut fifo = SliceFifoRegion::new(&mut backing, FifoCmsRegionType::CodeSpace, 2).unwrap();

        fifo.push_data(&[0x01, 0x02, 0x03]).unwrap();
        assert_eq!(fifo.write_idx, 1);
    }
}
