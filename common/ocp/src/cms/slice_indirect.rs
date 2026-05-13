// Licensed under the Apache-2.0 license

//! Slice-backed [`IndirectCmsRegion`] implementation.
//!
//! Provides a concrete CMS region backed by a `&mut [u8]` suitable for RAM-resident
//! recovery images, logs, or vendor-defined data in `no_std` environments.

use crate::cms::IndirectCmsRegion;
use crate::error::{CmsError, OcpError};
use crate::protocol::indirect_status::{CmsRegionType, IndirectStatus, StatusFlags};

// The mask to ensure a value matches the 4 byte alignment required for indirect CMS regions.
const ALIGNMENT_MASK: u32 = !0x3;

/// A memory-window CMS region backed by a mutable byte slice.
#[derive(Debug)]
pub struct SliceIndirectRegion<'a> {
    buf: &'a mut [u8],
    region_type: CmsRegionType,
    imo: u32,
    flags: StatusFlags,
}

impl<'a> SliceIndirectRegion<'a> {
    /// Create a new slice-backed indirect region.
    ///
    /// Returns [`OcpError::InvalidCmsBufferSize`] if `buf` is empty or its length
    /// is not a multiple of 4.
    pub fn new(buf: &'a mut [u8], region_type: CmsRegionType) -> Result<Self, OcpError> {
        if buf.is_empty() || buf.len() % 4 != 0 {
            return Err(OcpError::InvalidCmsBufferSize);
        }
        Ok(Self {
            buf,
            region_type,
            imo: 0,
            flags: StatusFlags(0),
        })
    }

    fn size_bytes(&self) -> u32 {
        self.buf.len() as u32
    }

    fn is_read_only(&self) -> bool {
        matches!(
            self.region_type,
            CmsRegionType::Log | CmsRegionType::VendorRo
        )
    }

    fn is_write_only(&self) -> bool {
        matches!(self.region_type, CmsRegionType::VendorWo)
    }

    /// Copy up to `buf.len()` bytes from the backing store starting at `offset`.
    ///
    /// Returns the number of bytes actually copied.
    fn read_at(&self, offset: usize, buf: &mut [u8]) -> usize {
        let size = self.size_bytes() as usize;
        let available = size.saturating_sub(offset);
        let copy_len = buf.len().min(available);
        buf[..copy_len].copy_from_slice(&self.buf[offset..offset + copy_len]);
        copy_len
    }

    fn advance_imo(&mut self, transfer_len: usize) {
        let increment = ((transfer_len as u32) + 3) & ALIGNMENT_MASK;
        let size = self.size_bytes();
        let new_imo = self.imo + increment;
        if new_imo >= size {
            self.imo = 0;
            self.flags.set_overflow_cms(true);
        } else {
            self.imo = new_imo;
        }
    }
}

impl IndirectCmsRegion for SliceIndirectRegion<'_> {
    fn status(&self) -> IndirectStatus {
        IndirectStatus::new(self.flags, self.region_type, false, self.size_bytes())
    }

    fn imo(&self) -> u32 {
        self.imo
    }

    fn set_imo(&mut self, offset: u32) {
        self.imo = offset & ALIGNMENT_MASK;
    }

    fn write(&mut self, data: &[u8]) -> Result<(), CmsError> {
        if self.is_read_only() {
            self.flags.set_read_only_error(true);
            return Err(CmsError::ReadOnly);
        }
        let size = self.size_bytes() as usize;
        let offset = self.imo as usize;
        let copy_len = data.len().min(size - offset);
        self.buf[offset..offset + copy_len].copy_from_slice(&data[..copy_len]);
        self.advance_imo(data.len());
        Ok(())
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, CmsError> {
        if self.is_write_only() {
            self.flags.set_write_only_error(true);
            return Err(CmsError::WriteOnly);
        }
        let copy_len = self.read_at(self.imo as usize, buf);
        self.advance_imo(copy_len);
        Ok(copy_len)
    }

    fn device_read(&self, offset: u32, buf: &mut [u8]) -> usize {
        self.read_at((offset & ALIGNMENT_MASK) as usize, buf)
    }

    fn clear_status(&mut self) {
        self.flags = StatusFlags(0);
    }

    fn reset(&mut self) {
        self.imo = 0;
        self.clear_status();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_and_read_at_offset_zero() {
        let mut backing = [0u8; 64];
        let mut region = SliceIndirectRegion::new(&mut backing, CmsRegionType::CodeSpace).unwrap();

        let data = [0xAA, 0xBB, 0xCC, 0xDD];
        region.write(&data).unwrap();

        region.set_imo(0);
        let mut read_buf = [0u8; 4];
        let n = region.read(&mut read_buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(read_buf, data);
    }

    #[test]
    fn auto_increment_sequential_writes() {
        let mut backing = [0u8; 64];
        let mut region = SliceIndirectRegion::new(&mut backing, CmsRegionType::CodeSpace).unwrap();

        region.write(&[0x01, 0x02, 0x03, 0x04]).unwrap();
        assert_eq!(region.imo(), 4);

        region.write(&[0x05, 0x06, 0x07, 0x08]).unwrap();
        assert_eq!(region.imo(), 8);

        region.set_imo(0);
        let mut buf = [0u8; 8];
        let n = region.read(&mut buf).unwrap();
        assert_eq!(n, 8);
        assert_eq!(buf, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn auto_increment_rounds_up_to_4_byte_boundary() {
        let mut backing = [0u8; 64];
        let mut region = SliceIndirectRegion::new(&mut backing, CmsRegionType::CodeSpace).unwrap();

        region.write(&[0x01, 0x02, 0x03]).unwrap();
        assert_eq!(region.imo(), 4);

        region.write(&[0x0A]).unwrap();
        assert_eq!(region.imo(), 8);
    }

    #[test]
    fn imo_wrap_and_overflow_flag() {
        let mut backing = [0u8; 8];
        let mut region = SliceIndirectRegion::new(&mut backing, CmsRegionType::CodeSpace).unwrap();

        assert!(!region.status().status.overflow_cms());
        region.write(&[0x01, 0x02, 0x03, 0x04]).unwrap();
        assert!(!region.status().status.overflow_cms());
        assert_eq!(region.imo(), 4);

        region.write(&[0x05, 0x06, 0x07, 0x08]).unwrap();
        assert!(region.status().status.overflow_cms());
        assert_eq!(region.imo(), 0);
    }

    #[test]
    fn unaligned_imo_truncated() {
        let mut backing = [0u8; 64];
        let mut region = SliceIndirectRegion::new(&mut backing, CmsRegionType::CodeSpace).unwrap();

        region.set_imo(5);
        assert_eq!(region.imo(), 4);

        region.set_imo(7);
        assert_eq!(region.imo(), 4);

        region.set_imo(8);
        assert_eq!(region.imo(), 8);

        region.set_imo(0);
        assert_eq!(region.imo(), 0);
    }

    #[test]
    fn read_only_region_rejects_writes() {
        let mut backing = [0u8; 64];
        let mut region = SliceIndirectRegion::new(&mut backing, CmsRegionType::Log).unwrap();

        assert_eq!(region.write(&[0x01]), Err(CmsError::ReadOnly));
        assert!(region.status().status.read_only_error());
        assert_eq!(region.imo(), 0);
    }

    #[test]
    fn write_only_region_rejects_reads() {
        let mut backing = [0u8; 64];
        let mut region = SliceIndirectRegion::new(&mut backing, CmsRegionType::VendorWo).unwrap();

        region.write(&[0x01, 0x02, 0x03, 0x04]).unwrap();
        region.set_imo(0);

        let mut buf = [0u8; 4];
        assert_eq!(region.read(&mut buf), Err(CmsError::WriteOnly));
        assert!(region.status().status.write_only_error());
    }

    #[test]
    fn reset_clears_imo_and_status() {
        let mut backing = [0u8; 8];
        let mut region = SliceIndirectRegion::new(&mut backing, CmsRegionType::CodeSpace).unwrap();

        region.write(&[0x01, 0x02, 0x03, 0x04]).unwrap();
        region.write(&[0x05, 0x06, 0x07, 0x08]).unwrap();
        assert!(region.status().status.overflow_cms());
        assert_eq!(region.imo(), 0);

        region.set_imo(4);
        region.reset();
        assert_eq!(region.imo(), 0);
        assert!(!region.status().status.overflow_cms());
    }

    #[test]
    fn clear_status_without_affecting_imo() {
        let mut backing = [0u8; 8];
        let mut region = SliceIndirectRegion::new(&mut backing, CmsRegionType::CodeSpace).unwrap();

        region.write(&[0x01, 0x02, 0x03, 0x04]).unwrap();
        region.write(&[0x05, 0x06, 0x07, 0x08]).unwrap();
        assert!(region.status().status.overflow_cms());
        let imo_before = region.imo();

        region.clear_status();
        assert!(!region.status().status.overflow_cms());
        assert_eq!(region.imo(), imo_before);
    }

    #[test]
    fn status_reports_correct_metadata() {
        let mut backing = [0u8; 64];
        let region = SliceIndirectRegion::new(&mut backing, CmsRegionType::CodeSpace).unwrap();
        let s = region.status();
        assert_eq!(s.cms_region_type().unwrap(), CmsRegionType::CodeSpace);
        assert_eq!(s.region_size(), 64);
        assert!(!s.polling());

        let mut small = [0u8; 4];
        let region2 = SliceIndirectRegion::new(&mut small, CmsRegionType::Log).unwrap();
        let s2 = region2.status();
        assert_eq!(s2.cms_region_type().unwrap(), CmsRegionType::Log);
        assert_eq!(s2.region_size(), 4);
        assert!(!s2.polling());
    }

    #[test]
    fn vendor_rw_allows_read_and_write() {
        let mut backing = [0u8; 16];
        let mut region = SliceIndirectRegion::new(&mut backing, CmsRegionType::VendorRw).unwrap();

        region.write(&[0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
        region.set_imo(0);

        let mut buf = [0u8; 4];
        let n = region.read(&mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf, [0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn vendor_ro_allows_read_rejects_write() {
        let mut backing = [0x11u8; 16];
        let mut region = SliceIndirectRegion::new(&mut backing, CmsRegionType::VendorRo).unwrap();

        assert_eq!(region.write(&[0x01]), Err(CmsError::ReadOnly));

        let mut buf = [0u8; 4];
        let n = region.read(&mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf, [0x11, 0x11, 0x11, 0x11]);
    }

    #[test]
    fn polling_region_metadata_in_status() {
        let mut backing = [0u8; 16];
        let region = SliceIndirectRegion::new(&mut backing, CmsRegionType::CodeSpace).unwrap();
        let s = region.status();
        assert!(!s.polling());
        assert_eq!(s.cms_region_type().unwrap(), CmsRegionType::CodeSpace);
    }

    #[test]
    fn empty_buffer_rejected() {
        let mut backing = [0u8; 0];
        assert_eq!(
            SliceIndirectRegion::new(&mut backing, CmsRegionType::CodeSpace).unwrap_err(),
            OcpError::InvalidCmsBufferSize,
        );
    }

    #[test]
    fn unaligned_buffer_rejected() {
        let mut backing = [0u8; 7];
        assert_eq!(
            SliceIndirectRegion::new(&mut backing, CmsRegionType::CodeSpace).unwrap_err(),
            OcpError::InvalidCmsBufferSize,
        );
    }

    #[test]
    fn multiple_overflow_wraps() {
        let mut backing = [0u8; 8];
        let mut region = SliceIndirectRegion::new(&mut backing, CmsRegionType::CodeSpace).unwrap();

        // Each write is 4 bytes into an 8-byte region, so every second write overflows.
        for i in 0u8..4 {
            region.write(&[i, i, i, i]).unwrap();
        }
        assert!(region.status().status.overflow_cms());
        assert_eq!(region.imo(), 0);

        region.clear_status();
        region.set_imo(0);
        let mut buf = [0u8; 8];
        let n = region.read(&mut buf).unwrap();
        assert_eq!(n, 8);
        // Writes 2 and 3 overwrote the same offsets as writes 0 and 1.
        assert_eq!(buf, [2, 2, 2, 2, 3, 3, 3, 3]);
    }

    #[test]
    fn write_crossing_boundary_only_copies_up_to_end() {
        let mut backing = [0u8; 8];
        let mut region = SliceIndirectRegion::new(&mut backing, CmsRegionType::CodeSpace).unwrap();

        region.set_imo(4);
        // 8 bytes of data starting at offset 4 — only 4 fit before the end.
        region
            .write(&[0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44])
            .unwrap();
        assert!(region.status().status.overflow_cms());
        assert_eq!(region.imo(), 0);

        // Only the first 4 bytes should have been written at offset 4.
        region.set_imo(4);
        region.clear_status();
        let mut buf = [0u8; 4];
        let n = region.read(&mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf, [0xAA, 0xBB, 0xCC, 0xDD]);

        // The beginning of the buffer should be untouched.
        region.set_imo(0);
        let mut buf2 = [0u8; 4];
        let n2 = region.read(&mut buf2).unwrap();
        assert_eq!(n2, 4);
        assert_eq!(buf2, [0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn imo_wraps_to_zero_on_uneven_overflow() {
        let mut backing = [0u8; 16];
        let mut region = SliceIndirectRegion::new(&mut backing, CmsRegionType::CodeSpace).unwrap();

        // Position at offset 8 and write 12 bytes; only 8 bytes fit.
        // Increment rounds to 12 (already aligned), so new_imo would be 20.
        // The spec requires IMO to reset to 0, not 20 % 16 = 4.
        region.set_imo(8);
        region.write(&[0xAA; 12]).unwrap();
        assert!(region.status().status.overflow_cms());
        assert_eq!(region.imo(), 0);

        // Verify same behavior on read path.
        region.clear_status();
        region.set_imo(4);
        let mut buf = [0u8; 16];
        let n = region.read(&mut buf).unwrap();
        assert_eq!(n, 12);
        assert!(region.status().status.overflow_cms());
        assert_eq!(region.imo(), 0);
    }

    #[test]
    fn read_crossing_boundary_only_reads_up_to_end() {
        let mut backing = [0xAA; 8];
        let mut region = SliceIndirectRegion::new(&mut backing, CmsRegionType::CodeSpace).unwrap();

        region.set_imo(4);
        let mut buf = [0u8; 8];
        let n = region.read(&mut buf).unwrap();
        // Only 4 bytes available from offset 4 to end.
        assert_eq!(n, 4);
        assert_eq!(buf[..4], [0xAA, 0xAA, 0xAA, 0xAA]);
    }

    #[test]
    fn empty_write_and_read_are_no_ops() {
        let mut backing = [0u8; 8];
        let mut region = SliceIndirectRegion::new(&mut backing, CmsRegionType::CodeSpace).unwrap();

        region.set_imo(4);
        region.write(&[]).unwrap();
        assert_eq!(region.imo(), 4);

        let mut buf = [0u8; 0];
        let n = region.read(&mut buf).unwrap();
        assert_eq!(n, 0);
        assert_eq!(region.imo(), 4);
    }
}
