// Licensed under the Apache-2.0 license

//! Host-side encoder for the kernel `logging_flash` capsule's on-disk format.
//! Used by integration tests to pre-seed LOGGING_PARTITION via
//! `BootParams::primary_flash_initial_contents`.

/// On-disk size of `usize` as written by the RISC-V 32-bit firmware.
pub const ON_DISK_USIZE: usize = 4;
pub const PAGE_HEADER_SIZE: usize = ON_DISK_USIZE;
pub const ENTRY_HEADER_SIZE: usize = ON_DISK_USIZE;
pub const PAD_BYTE: u8 = 0xFF;

/// Encode `entries` into a buffer exactly `partition_size` bytes long.
///
/// Panics if the encoded entries exceed `partition_size` or if any single
/// entry is larger than `page_size - PAGE_HEADER_SIZE - ENTRY_HEADER_SIZE`.
pub fn encode_logging_partition(
    entries: &[&[u8]],
    partition_size: usize,
    page_size: usize,
) -> Vec<u8> {
    assert!(
        partition_size % page_size == 0,
        "partition_size ({}) must be a multiple of page_size ({})",
        partition_size,
        page_size,
    );
    let num_pages = partition_size / page_size;
    let max_entry = page_size - PAGE_HEADER_SIZE - ENTRY_HEADER_SIZE;

    let mut out = vec![PAD_BYTE; partition_size];

    let mut page = 0usize;
    let mut off = PAGE_HEADER_SIZE;
    write_page_header(&mut out, page, page_size);

    for e in entries {
        assert!(
            e.len() <= max_entry,
            "entry of {} bytes exceeds per-page capacity {}",
            e.len(),
            max_entry,
        );
        let need = ENTRY_HEADER_SIZE + e.len();
        if off + need > page_size {
            page += 1;
            assert!(
                page < num_pages,
                "fixture exceeds LOGGING_PARTITION capacity ({} pages)",
                num_pages,
            );
            off = PAGE_HEADER_SIZE;
            write_page_header(&mut out, page, page_size);
        }
        let p = page * page_size;
        out[p + off..p + off + ENTRY_HEADER_SIZE].copy_from_slice(&(e.len() as u32).to_le_bytes());
        out[p + off + ENTRY_HEADER_SIZE..p + off + ENTRY_HEADER_SIZE + e.len()].copy_from_slice(e);
        off += need;
    }

    out
}

/// Splice an encoded LOGGING_PARTITION into `flash_image` at `partition_offset`.
///
/// When `flash_image` is `None`, allocates a buffer just long enough to cover
/// the end of the partition. The remaining flash capacity is auto-padded with
/// `0xFF` by the flash controller's `initialize_flash_storage`. When `Some`,
/// grows the buffer as needed and overwrites the partition region.
pub fn splice_logging_partition_into_flash_image(
    flash_image: Option<Vec<u8>>,
    entries: &[&[u8]],
    partition_offset: usize,
    partition_size: usize,
    page_size: usize,
) -> Vec<u8> {
    let mut buf = flash_image.unwrap_or_default();
    let end = partition_offset + partition_size;
    if buf.len() < end {
        buf.resize(end, PAD_BYTE);
    }
    let partition = encode_logging_partition(entries, partition_size, page_size);
    buf[partition_offset..end].copy_from_slice(&partition);
    buf
}

fn write_page_header(buf: &mut [u8], logical_page: usize, page_size: usize) {
    // Kernel reconstruct validates `page_id % volume_len == logical_page * page_size`.
    // For an uncycled log the simplest valid encoding is the raw product.
    let page_id = (logical_page * page_size) as u32;
    let p = logical_page * page_size;
    buf[p..p + PAGE_HEADER_SIZE].copy_from_slice(&page_id.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE_SIZE: usize = 256;
    const PARTITION_SIZE: usize = 32 * 1024;
    const PARTITION_OFFSET: usize = 0x03FF_8000;

    #[test]
    fn empty_partition_has_page0_header_only() {
        let buf = encode_logging_partition(&[], PARTITION_SIZE, PAGE_SIZE);
        assert_eq!(buf.len(), PARTITION_SIZE);
        // Page 0 header is zero (page_id = 0 * 256), rest of page 0 is PAD.
        assert_eq!(&buf[..4], &[0u8; 4]);
        assert!(buf[4..PAGE_SIZE].iter().all(|&b| b == PAD_BYTE));
        // Pages with no entries written have no header — all PAD so the
        // kernel reconstruct rejects them via `page_id % volume_len` check.
        assert!(buf[PAGE_SIZE..].iter().all(|&b| b == PAD_BYTE));
    }

    #[test]
    fn single_entry_fits_in_page0() {
        let entries: &[&[u8]] = &[b"hello"];
        let buf = encode_logging_partition(entries, PARTITION_SIZE, PAGE_SIZE);
        // Page 0 header.
        assert_eq!(&buf[..4], &[0u8; 4]);
        // Entry length = 5 LE.
        assert_eq!(&buf[4..8], &[5, 0, 0, 0]);
        assert_eq!(&buf[8..13], b"hello");
        // Tail of page 0 is PAD.
        assert!(buf[13..PAGE_SIZE].iter().all(|&b| b == PAD_BYTE));
    }

    #[test]
    fn entry_too_big_for_remaining_page_starts_new_page() {
        // Each entry takes 4 (header) + N (payload). Choose N so two entries
        // fit on page 0 and the third must spill onto page 1.
        let big = vec![b'a'; 120]; // 124 bytes per entry on disk
        let entries: &[&[u8]] = &[&big[..], &big[..], &big[..]];
        let buf = encode_logging_partition(entries, PARTITION_SIZE, PAGE_SIZE);
        // Page 0: header + 2 entries = 4 + 248 = 252 bytes; remaining 4 bytes padded.
        assert_eq!(&buf[..4], &[0u8; 4]);
        assert_eq!(&buf[4..8], &[120, 0, 0, 0]);
        // Page 1 starts with its own header (page_id = 256).
        let page1 = PAGE_SIZE;
        assert_eq!(&buf[page1..page1 + 4], &(PAGE_SIZE as u32).to_le_bytes());
        assert_eq!(&buf[page1 + 4..page1 + 8], &[120, 0, 0, 0]);
    }

    #[test]
    fn splice_into_none_creates_buffer_ending_at_partition() {
        let buf = splice_logging_partition_into_flash_image(
            None,
            &[b"x"],
            PARTITION_OFFSET,
            PARTITION_SIZE,
            PAGE_SIZE,
        );
        assert_eq!(buf.len(), PARTITION_OFFSET + PARTITION_SIZE);
        // Pre-partition bytes are PAD.
        assert!(buf[..PARTITION_OFFSET].iter().all(|&b| b == PAD_BYTE));
        // Partition starts with page-0 header (zero) then entry.
        assert_eq!(&buf[PARTITION_OFFSET..PARTITION_OFFSET + 4], &[0u8; 4]);
        assert_eq!(
            &buf[PARTITION_OFFSET + 4..PARTITION_OFFSET + 8],
            &[1, 0, 0, 0]
        );
        assert_eq!(buf[PARTITION_OFFSET + 8], b'x');
    }

    #[test]
    fn splice_into_existing_preserves_other_regions() {
        let mut img = vec![0xAAu8; PARTITION_OFFSET + PARTITION_SIZE];
        // Mark a byte before the partition that should survive.
        img[42] = 0x55;
        let buf = splice_logging_partition_into_flash_image(
            Some(img),
            &[b"y"],
            PARTITION_OFFSET,
            PARTITION_SIZE,
            PAGE_SIZE,
        );
        assert_eq!(buf[42], 0x55);
        assert_eq!(&buf[PARTITION_OFFSET..PARTITION_OFFSET + 4], &[0u8; 4]);
        assert_eq!(
            &buf[PARTITION_OFFSET + 4..PARTITION_OFFSET + 8],
            &[1, 0, 0, 0]
        );
        assert_eq!(buf[PARTITION_OFFSET + 8], b'y');
    }
}
