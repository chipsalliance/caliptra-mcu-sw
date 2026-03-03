// Licensed under the Apache-2.0 license

//! Platform Descriptor Store (PDS) parser.
//!
//! Provides a `no_std` parser for the PDS binary format, which stores
//! platform-level data as a linked list of UUID-typed descriptors with
//! variable-size payloads.

#![no_std]

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// PDS header magic number: "PDS1" in little-endian ASCII.
pub const PDS_MAGIC: u32 = 0x50445331;

/// Current PDS header version.
pub const PDS_HEADER_VERSION: u32 = 1;

/// CRC-32/CKSUM polynomial used for header CRC validation.
const CRC_POLY: u32 = 0x04C11DB7;

/// Byte offset where CRC computation begins (after magic, header_size, header_crc).
const CRC_START_OFFSET: usize = 12;

/// Default maximum number of descriptors to traverse before aborting.
pub const DEFAULT_MAX_DESCRIPTORS: usize = 32;

/// UUID type: 16-byte array per RFC 4122.
pub type Uuid = [u8; 16];

/// Errors returned by PDS parsing operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdsError {
    /// Input buffer is too small to contain the expected structure.
    BufferTooSmall,
    /// Magic number does not match PDS_MAGIC.
    InvalidMagic { found: u32, expected: u32 },
    /// Header version is below the minimum supported version.
    InvalidVersion { found: u32, expected: u32 },
    /// Header size field is smaller than the minimum header structure size.
    InvalidHeaderSize { found: u32, expected: u32 },
    /// CRC-32 checksum does not match the computed value.
    InvalidCrc { found: u32, computed: u32 },
    /// Descriptor offset points outside the PDS buffer.
    DescriptorOutOfBounds { offset: u32 },
    /// Descriptor payload range extends beyond the PDS buffer.
    PayloadOutOfBounds { offset: u32, size: u32 },
    /// Descriptor chain contains a loop (visited same offset twice).
    DescriptorLoop { offset: u32 },
    /// Descriptor header_size is smaller than the minimum descriptor header size.
    InvalidDescriptorHeaderSize { found: u32, expected: u32 },
    /// Maximum descriptor traversal count exceeded.
    MaxDescriptorsExceeded,
}

/// PDS Header (version 1).
///
/// All fields are little-endian.
///
/// All fields are naturally aligned at 4-byte boundaries.
/// Parsers should read from flash into a local copy of this struct
/// to guarantee alignment on architectures that require it (e.g., RISC-V).
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct PdsHeaderV1 {
    /// Must be PDS_MAGIC (0x50445331).
    pub magic: u32,
    /// Size of this header structure in bytes.
    pub header_size: u32,
    /// CRC-32 computed over bytes from offset 12 to header_size.
    pub header_crc: u32,
    /// Header format version (currently 1).
    pub version: u32,
    /// Byte offset from PDS start to the first descriptor, or 0 if none.
    pub first_descriptor_offset: u32,
    /// Null-terminated UTF-8 version string.
    pub pds_version_string: [u8; 128],
}

/// PDS Descriptor Header (version 1).
///
/// All fields are little-endian.
///
/// All fields are naturally aligned at 4-byte boundaries.
/// Parsers should read from flash into a local copy of this struct
/// to guarantee alignment on architectures that require it (e.g., RISC-V).
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct PdsDescriptorHeaderV1 {
    /// Size of this descriptor header in bytes.
    pub header_size: u32,
    /// Byte offset from PDS start to the payload data.
    pub payload_offset: u32,
    /// Size of the payload in bytes.
    pub payload_size: u32,
    /// Byte offset from PDS start to the next descriptor, or 0 if last.
    pub next_descriptor_offset: u32,
    /// UUID identifying the descriptor type.
    pub descriptor_type: Uuid,
}

/// A parsed descriptor reference pointing into the original PDS buffer.
#[derive(Debug, Clone, Copy)]
pub struct PdsDescriptor<'a> {
    /// UUID identifying the descriptor type.
    pub descriptor_type: Uuid,
    /// Payload data slice (references the original PDS buffer).
    pub payload: &'a [u8],
}

/// Compute CRC-32/CKSUM over the given data.
fn crc32_cksum(data: &[u8]) -> u32 {
    let mut crc: u32 = 0;
    for &byte in data {
        crc ^= (byte as u32) << 24;
        for _ in 0..8 {
            if crc & 0x8000_0000 != 0 {
                crc = (crc << 1) ^ CRC_POLY;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Parse and validate a PDS binary, returning an iterator over descriptors.
///
/// # Arguments
/// * `data` - The raw PDS binary data.
/// * `max_descriptors` - Maximum number of descriptors to traverse.
///
/// # Errors
/// Returns a `PdsError` if the header is invalid, CRC fails, or the
/// descriptor chain is malformed.
pub fn validate_header(data: &[u8]) -> Result<PdsHeaderV1, PdsError> {
    let header_size = core::mem::size_of::<PdsHeaderV1>() as u32;

    let (header, _) =
        PdsHeaderV1::read_from_prefix(data).map_err(|_| PdsError::BufferTooSmall)?;

    if header.magic != PDS_MAGIC {
        return Err(PdsError::InvalidMagic {
            found: header.magic,
            expected: PDS_MAGIC,
        });
    }

    if header.version < PDS_HEADER_VERSION {
        return Err(PdsError::InvalidVersion {
            found: header.version,
            expected: PDS_HEADER_VERSION,
        });
    }

    if header.header_size < header_size {
        return Err(PdsError::InvalidHeaderSize {
            found: header.header_size,
            expected: header_size,
        });
    }

    let crc_end = header.header_size as usize;
    if crc_end > data.len() {
        return Err(PdsError::BufferTooSmall);
    }

    let crc_data = &data[CRC_START_OFFSET..crc_end];
    let computed_crc = crc32_cksum(crc_data);
    if computed_crc != header.header_crc {
        return Err(PdsError::InvalidCrc {
            found: header.header_crc,
            computed: computed_crc,
        });
    }

    Ok(header)
}

/// Iterate over all descriptors in a validated PDS buffer.
///
/// The caller must first call `validate_header` to ensure the PDS is valid.
///
/// # Arguments
/// * `data` - The raw PDS binary data (already validated).
/// * `header` - A validated PDS header reference.
/// * `max_descriptors` - Maximum number of descriptors to traverse.
/// * `callback` - Called for each descriptor. Return `true` to continue, `false` to stop.
///
/// # Errors
/// Returns a `PdsError` if the descriptor chain is malformed.
pub fn for_each_descriptor<F>(
    data: &[u8],
    header: &PdsHeaderV1,
    max_descriptors: usize,
    mut callback: F,
) -> Result<(), PdsError>
where
    F: FnMut(PdsDescriptor<'_>) -> bool,
{
    let desc_header_size = core::mem::size_of::<PdsDescriptorHeaderV1>() as u32;
    let mut next_offset = header.first_descriptor_offset;
    let mut count = 0usize;
    let mut prev_offset = 0u32;

    while next_offset != 0 {
        if count >= max_descriptors {
            return Err(PdsError::MaxDescriptorsExceeded);
        }

        // Forward-only check (skip for first descriptor)
        if count > 0 && next_offset <= prev_offset {
            return Err(PdsError::DescriptorLoop {
                offset: next_offset,
            });
        }

        let offset = next_offset as usize;
        if offset.checked_add(desc_header_size as usize).map_or(true, |end| end > data.len()) {
            return Err(PdsError::DescriptorOutOfBounds {
                offset: next_offset,
            });
        }

        let (desc, _) = PdsDescriptorHeaderV1::read_from_prefix(&data[offset..])
            .map_err(|_| PdsError::DescriptorOutOfBounds {
                offset: next_offset,
            })?;

        if desc.header_size < desc_header_size {
            return Err(PdsError::InvalidDescriptorHeaderSize {
                found: desc.header_size,
                expected: desc_header_size,
            });
        }

        let payload_start = desc.payload_offset as usize;
        let payload_end = payload_start
            .checked_add(desc.payload_size as usize)
            .ok_or(PdsError::PayloadOutOfBounds {
                offset: desc.payload_offset,
                size: desc.payload_size,
            })?;

        if payload_end > data.len() {
            return Err(PdsError::PayloadOutOfBounds {
                offset: desc.payload_offset,
                size: desc.payload_size,
            });
        }

        let descriptor = PdsDescriptor {
            descriptor_type: desc.descriptor_type,
            payload: &data[payload_start..payload_end],
        };

        if !callback(descriptor) {
            return Ok(());
        }

        prev_offset = next_offset;
        next_offset = desc.next_descriptor_offset;
        count += 1;
    }

    Ok(())
}

/// Find the first descriptor matching the given UUID.
///
/// # Arguments
/// * `data` - The raw PDS binary data (already validated).
/// * `header` - A validated PDS header reference.
/// * `uuid` - The descriptor type UUID to search for.
///
/// # Returns
/// The payload slice if found, or `None` if not found.
pub fn find_descriptor<'a>(
    data: &'a [u8],
    header: &PdsHeaderV1,
    uuid: &Uuid,
) -> Result<Option<&'a [u8]>, PdsError> {
    let desc_header_size = core::mem::size_of::<PdsDescriptorHeaderV1>() as u32;
    let mut next_offset = header.first_descriptor_offset;
    let mut count = 0usize;
    let mut prev_offset = 0u32;

    while next_offset != 0 {
        if count >= DEFAULT_MAX_DESCRIPTORS {
            return Err(PdsError::MaxDescriptorsExceeded);
        }

        if count > 0 && next_offset <= prev_offset {
            return Err(PdsError::DescriptorLoop {
                offset: next_offset,
            });
        }

        let offset = next_offset as usize;
        if offset.checked_add(desc_header_size as usize).map_or(true, |end| end > data.len()) {
            return Err(PdsError::DescriptorOutOfBounds {
                offset: next_offset,
            });
        }

        let (desc, _) = PdsDescriptorHeaderV1::read_from_prefix(&data[offset..])
            .map_err(|_| PdsError::DescriptorOutOfBounds {
                offset: next_offset,
            })?;

        if desc.descriptor_type == *uuid {
            let payload_start = desc.payload_offset as usize;
            let payload_end = payload_start
                .checked_add(desc.payload_size as usize)
                .ok_or(PdsError::PayloadOutOfBounds {
                    offset: desc.payload_offset,
                    size: desc.payload_size,
                })?;

            if payload_end > data.len() {
                return Err(PdsError::PayloadOutOfBounds {
                    offset: desc.payload_offset,
                    size: desc.payload_size,
                });
            }

            return Ok(Some(&data[payload_start..payload_end]));
        }

        prev_offset = next_offset;
        next_offset = desc.next_descriptor_offset;
        count += 1;
    }

    Ok(None)
}

#[cfg(test)]
extern crate alloc;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn build_pds(descriptors: &[(Uuid, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        let header_size = core::mem::size_of::<PdsHeaderV1>();
        let desc_header_size = core::mem::size_of::<PdsDescriptorHeaderV1>();

        // Reserve space for header
        buf.resize(header_size, 0);

        let first_offset = if descriptors.is_empty() {
            0u32
        } else {
            header_size as u32
        };

        // Write descriptors
        for (i, (uuid, payload)) in descriptors.iter().enumerate() {
            let current_offset = buf.len();
            let payload_offset = (current_offset + desc_header_size) as u32;

            let next_offset = if i + 1 < descriptors.len() {
                (current_offset + desc_header_size + payload.len()) as u32
            } else {
                0
            };

            let desc = PdsDescriptorHeaderV1 {
                header_size: desc_header_size as u32,
                payload_offset,
                payload_size: payload.len() as u32,
                next_descriptor_offset: next_offset,
                descriptor_type: *uuid,
            };
            buf.extend_from_slice(desc.as_bytes());
            buf.extend_from_slice(payload);
        }

        // Write header
        let mut header = PdsHeaderV1 {
            magic: PDS_MAGIC,
            header_size: header_size as u32,
            header_crc: 0,
            version: PDS_HEADER_VERSION,
            first_descriptor_offset: first_offset,
            pds_version_string: [0u8; 128],
        };

        // Compute CRC
        let header_bytes = header.as_bytes().to_vec();
        let crc_data = &header_bytes[CRC_START_OFFSET..];
        header.header_crc = crc32_cksum(crc_data);

        buf[..header_size].copy_from_slice(header.as_bytes());

        buf
    }

    #[test]
    fn test_empty_pds() {
        let pds = build_pds(&[]);
        let header = validate_header(&pds).unwrap();
        assert_eq!(header.first_descriptor_offset, 0);

        let mut count = 0;
        for_each_descriptor(&pds, &header, DEFAULT_MAX_DESCRIPTORS, |_| {
            count += 1;
            true
        })
        .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_single_descriptor() {
        let uuid: Uuid = [
            0x53, 0x19, 0xD6, 0xF1, 0x57, 0xB3, 0x4D, 0x1A, 0x96, 0xC6, 0xE0, 0xED, 0xAF, 0x90,
            0x7A, 0x12,
        ];
        let payload = b"hello world";
        let pds = build_pds(&[(uuid, payload)]);

        let header = validate_header(&pds).unwrap();
        let found = find_descriptor(&pds, &header, &uuid).unwrap();
        assert_eq!(found, Some(payload.as_slice()));
    }

    #[test]
    fn test_multiple_descriptors() {
        let uuid1: Uuid = [1; 16];
        let uuid2: Uuid = [2; 16];
        let uuid3: Uuid = [3; 16];

        let pds = build_pds(&[
            (uuid1, b"first"),
            (uuid2, b"second"),
            (uuid3, b"third"),
        ]);

        let header = validate_header(&pds).unwrap();

        assert_eq!(
            find_descriptor(&pds, &header, &uuid1).unwrap(),
            Some(b"first".as_slice())
        );
        assert_eq!(
            find_descriptor(&pds, &header, &uuid2).unwrap(),
            Some(b"second".as_slice())
        );
        assert_eq!(
            find_descriptor(&pds, &header, &uuid3).unwrap(),
            Some(b"third".as_slice())
        );
    }

    #[test]
    fn test_unknown_uuid_returns_none() {
        let uuid: Uuid = [1; 16];
        let unknown: Uuid = [99; 16];

        let pds = build_pds(&[(uuid, b"data")]);
        let header = validate_header(&pds).unwrap();

        assert_eq!(find_descriptor(&pds, &header, &unknown).unwrap(), None);
    }

    #[test]
    fn test_invalid_magic() {
        let mut pds = build_pds(&[]);
        pds[0] = 0xFF; // corrupt magic
        assert!(matches!(
            validate_header(&pds),
            Err(PdsError::InvalidMagic { .. })
        ));
    }

    #[test]
    fn test_invalid_crc() {
        let mut pds = build_pds(&[]);
        // Corrupt version string area to invalidate CRC
        pds[20] = 0xFF;
        assert!(matches!(
            validate_header(&pds),
            Err(PdsError::InvalidCrc { .. })
        ));
    }

    #[test]
    fn test_buffer_too_small() {
        assert!(matches!(
            validate_header(&[0u8; 4]),
            Err(PdsError::BufferTooSmall)
        ));
    }

    #[test]
    fn test_descriptor_count() {
        let uuid: Uuid = [1; 16];
        let pds = build_pds(&[(uuid, b"a"), (uuid, b"b"), (uuid, b"c")]);
        let header = validate_header(&pds).unwrap();

        let mut count = 0;
        for_each_descriptor(&pds, &header, DEFAULT_MAX_DESCRIPTORS, |_| {
            count += 1;
            true
        })
        .unwrap();
        assert_eq!(count, 3);
    }
}
