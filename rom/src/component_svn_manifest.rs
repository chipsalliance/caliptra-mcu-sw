// Licensed under the Apache-2.0 license

//! MCU Component SVN Manifest format and validation. See `docs/src/svn.md`.
//!
//! This module defines the on-disk layout, parsing, and structural
//! validation. Fuse reads and burns happen in the caller.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Magic at the start of the manifest. On disk (little-endian) the bytes
/// are `"VSCM"`; the constant value reads as `"MCSV"` MSB-first.
pub const MCU_COMPONENT_SVN_MANIFEST_MAGIC: u32 = 0x4D43_5356;

/// Currently supported manifest format version.
pub const MCU_COMPONENT_SVN_MANIFEST_VERSION: u16 = 1;

/// Number of `McuComponentSvnEntry` slots. Matches Caliptra's
/// `AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT`.
pub const MCU_COMPONENT_SVN_MANIFEST_ENTRY_COUNT: usize = 127;

/// Total on-disk size of the manifest, in bytes.
pub const MCU_COMPONENT_SVN_MANIFEST_SIZE: usize = 1024;

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
pub struct McuComponentSvnEntry {
    /// Same identifier Caliptra uses in `AuthManifestImageMetadata`.
    pub component_id: u32,
    pub current_svn: u16,
    /// Requested new floor for the mapped `SOC_IMAGE_MIN_SVN[i]` slot
    /// (0 = no update).
    pub min_svn: u16,
}

impl McuComponentSvnEntry {
    /// All-zero entries are treated as empty slots.
    pub fn is_empty(&self) -> bool {
        self.component_id == 0 && self.current_svn == 0 && self.min_svn == 0
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct McuComponentSvnManifest {
    /// Must be [`MCU_COMPONENT_SVN_MANIFEST_MAGIC`].
    pub magic: u32,
    pub format_version: u16,
    pub current_svn: u8,
    /// Requested new floor for `MCU_COMPONENT_SVN_MANIFEST_MIN_SVN`
    /// (0 = no update).
    pub min_svn: u8,
    pub entries: [McuComponentSvnEntry; MCU_COMPONENT_SVN_MANIFEST_ENTRY_COUNT],
}

// `#[repr(C)]` lays the fields out in declaration order with each field
// aligned to its type. McuComponentSvnEntry packs to 8 B (u32 + u16 +
// u16, all 4-byte-aligned at start), and the manifest header packs to
// 8 B (u32 + u16 + u8 + u8), so the entry array starts immediately
// after the header with no padding. These asserts make any future
// field-order change a compile error.
const _: () = assert!(core::mem::size_of::<McuComponentSvnEntry>() == 8);
const _: () =
    assert!(core::mem::size_of::<McuComponentSvnManifest>() == MCU_COMPONENT_SVN_MANIFEST_SIZE);

/// Errors that can result from parsing or validating a manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SvnManifestError {
    /// Byte slice is too short to contain a manifest.
    TooShort,
    MagicMismatch,
    UnsupportedFormatVersion(u16),
    HeaderMinSvnExceedsCurrent {
        min_svn: u8,
        current_svn: u8,
    },
    /// A header SVN does not fit within
    /// `MCU_COMPONENT_SVN_MANIFEST_MIN_SVN`'s one-hot range.
    HeaderSvnExceedsFuseRange {
        value: u8,
        max: u32,
    },
    EntryMinSvnExceedsCurrent {
        index: usize,
        min_svn: u16,
        current_svn: u16,
    },
}

/// One-hot range limits the caller must supply to [`validate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SvnLimits {
    /// Max representable value for `MCU_COMPONENT_SVN_MANIFEST_MIN_SVN`.
    pub manifest_min_svn_max: u32,
}

impl McuComponentSvnManifest {
    /// Parse a manifest from `bytes` if it begins with the manifest
    /// magic. Returns `Ok(None)` when the magic is absent (the manifest
    /// header is optional in the MCU runtime image) and `Err(TooShort)`
    /// when the magic is present but the buffer can't fit the struct.
    pub fn parse_if_present(bytes: &[u8]) -> Result<Option<&Self>, SvnManifestError> {
        let magic = bytes.get(..4).ok_or(SvnManifestError::TooShort)?;
        let magic = u32::from_le_bytes([magic[0], magic[1], magic[2], magic[3]]);
        if magic != MCU_COMPONENT_SVN_MANIFEST_MAGIC {
            return Ok(None);
        }
        let (header, _) = Self::ref_from_prefix(bytes).map_err(|_| SvnManifestError::TooShort)?;
        Ok(Some(header))
    }

    /// Validate structural constraints from `docs/src/svn.md`. Does not
    /// consult OTP; the caller separately compares `current_svn`
    /// against the fuse value.
    pub fn validate(&self, limits: &SvnLimits) -> Result<(), SvnManifestError> {
        if self.magic != MCU_COMPONENT_SVN_MANIFEST_MAGIC {
            return Err(SvnManifestError::MagicMismatch);
        }
        if self.format_version != MCU_COMPONENT_SVN_MANIFEST_VERSION {
            return Err(SvnManifestError::UnsupportedFormatVersion(
                self.format_version,
            ));
        }
        if self.min_svn > self.current_svn {
            return Err(SvnManifestError::HeaderMinSvnExceedsCurrent {
                min_svn: self.min_svn,
                current_svn: self.current_svn,
            });
        }
        if u32::from(self.current_svn) > limits.manifest_min_svn_max {
            return Err(SvnManifestError::HeaderSvnExceedsFuseRange {
                value: self.current_svn,
                max: limits.manifest_min_svn_max,
            });
        }
        if u32::from(self.min_svn) > limits.manifest_min_svn_max {
            return Err(SvnManifestError::HeaderSvnExceedsFuseRange {
                value: self.min_svn,
                max: limits.manifest_min_svn_max,
            });
        }
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.is_empty() {
                continue;
            }
            if entry.min_svn > entry.current_svn {
                return Err(SvnManifestError::EntryMinSvnExceedsCurrent {
                    index: i,
                    min_svn: entry.min_svn,
                    current_svn: entry.current_svn,
                });
            }
            // Per-entry one-hot-range checks against SOC_IMAGE_MIN_SVN[i]
            // are deferred to the fuse-burn step, where SVN_FUSE_MAP
            // supplies the per-slot maximum.
        }
        Ok(())
    }

    /// Iterator over non-empty entries paired with their index.
    pub fn entries_present(&self) -> impl Iterator<Item = (usize, &McuComponentSvnEntry)> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, e)| !e.is_empty())
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec;
    use core::mem::size_of;

    const LIMITS: SvnLimits = SvnLimits {
        manifest_min_svn_max: 10,
    };

    fn empty_manifest() -> McuComponentSvnManifest {
        McuComponentSvnManifest {
            magic: MCU_COMPONENT_SVN_MANIFEST_MAGIC,
            format_version: MCU_COMPONENT_SVN_MANIFEST_VERSION,
            current_svn: 0,
            min_svn: 0,
            entries: [McuComponentSvnEntry::default(); MCU_COMPONENT_SVN_MANIFEST_ENTRY_COUNT],
        }
    }

    #[test]
    fn manifest_size_is_1024_bytes() {
        assert_eq!(
            size_of::<McuComponentSvnManifest>(),
            MCU_COMPONENT_SVN_MANIFEST_SIZE
        );
    }

    #[test]
    fn entry_size_is_8_bytes() {
        assert_eq!(size_of::<McuComponentSvnEntry>(), 8);
    }

    #[test]
    fn header_size_is_8_bytes() {
        // 4 (magic) + 2 (format_version) + 1 (current_svn) + 1 (min_svn)
        let header_size = MCU_COMPONENT_SVN_MANIFEST_SIZE
            - MCU_COMPONENT_SVN_MANIFEST_ENTRY_COUNT * size_of::<McuComponentSvnEntry>();
        assert_eq!(header_size, 8);
    }

    #[test]
    fn magic_on_disk_is_vscm() {
        let m = empty_manifest();
        let bytes = m.as_bytes();
        assert_eq!(&bytes[0..4], b"VSCM");
    }

    #[test]
    fn parse_if_present_returns_none_when_magic_absent() {
        let mut bytes = vec![0u8; MCU_COMPONENT_SVN_MANIFEST_SIZE];
        bytes[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert!(McuComponentSvnManifest::parse_if_present(&bytes)
            .unwrap()
            .is_none());
    }

    #[test]
    fn parse_if_present_returns_some_when_magic_present() {
        let m = empty_manifest();
        let bytes = m.as_bytes();
        let parsed = McuComponentSvnManifest::parse_if_present(bytes)
            .unwrap()
            .unwrap();
        assert_eq!(parsed.magic, MCU_COMPONENT_SVN_MANIFEST_MAGIC);
    }

    #[test]
    fn parse_if_present_too_short_with_magic_errors() {
        // Magic present but slice too short to fit the structure
        let mut bytes = vec![0u8; 16];
        bytes[0..4].copy_from_slice(&MCU_COMPONENT_SVN_MANIFEST_MAGIC.to_le_bytes());
        let result = McuComponentSvnManifest::parse_if_present(&bytes);
        assert_eq!(result.err(), Some(SvnManifestError::TooShort));
    }

    #[test]
    fn parse_if_present_too_short_without_magic_errors() {
        let bytes = [0u8; 3];
        let result = McuComponentSvnManifest::parse_if_present(&bytes);
        assert_eq!(result.err(), Some(SvnManifestError::TooShort));
    }

    #[test]
    fn validate_accepts_well_formed_empty_manifest() {
        let m = empty_manifest();
        assert!(m.validate(&LIMITS).is_ok());
    }

    #[test]
    fn validate_accepts_well_formed_populated_manifest() {
        let mut m = empty_manifest();
        m.current_svn = 5;
        m.min_svn = 3;
        m.entries[0] = McuComponentSvnEntry {
            component_id: 0x1000,
            current_svn: 7,
            min_svn: 2,
        };
        m.entries[42] = McuComponentSvnEntry {
            component_id: 0x2000,
            current_svn: 4,
            min_svn: 4,
        };
        assert!(m.validate(&LIMITS).is_ok());
    }

    #[test]
    fn validate_rejects_bad_magic() {
        let mut m = empty_manifest();
        m.magic = 0;
        assert_eq!(m.validate(&LIMITS), Err(SvnManifestError::MagicMismatch));
    }

    #[test]
    fn validate_rejects_unsupported_format_version() {
        let mut m = empty_manifest();
        m.format_version = 99;
        assert_eq!(
            m.validate(&LIMITS),
            Err(SvnManifestError::UnsupportedFormatVersion(99))
        );
    }

    #[test]
    fn validate_rejects_header_min_svn_above_current_svn() {
        let mut m = empty_manifest();
        m.current_svn = 3;
        m.min_svn = 4;
        assert_eq!(
            m.validate(&LIMITS),
            Err(SvnManifestError::HeaderMinSvnExceedsCurrent {
                min_svn: 4,
                current_svn: 3,
            })
        );
    }

    #[test]
    fn validate_rejects_header_current_svn_above_fuse_range() {
        let mut m = empty_manifest();
        m.current_svn = 11;
        m.min_svn = 0;
        assert_eq!(
            m.validate(&LIMITS),
            Err(SvnManifestError::HeaderSvnExceedsFuseRange { value: 11, max: 10 })
        );
    }

    #[test]
    fn validate_rejects_header_min_svn_above_fuse_range_when_current_in_range() {
        // current_svn within range but min_svn > range is structurally
        // impossible (min_svn <= current_svn). Confirm we don't false-
        // positive on a manifest where current_svn = max.
        let mut m = empty_manifest();
        m.current_svn = 10;
        m.min_svn = 10;
        assert!(m.validate(&LIMITS).is_ok());
    }

    #[test]
    fn validate_rejects_entry_min_svn_above_current_svn() {
        let mut m = empty_manifest();
        m.entries[3] = McuComponentSvnEntry {
            component_id: 0x42,
            current_svn: 5,
            min_svn: 6,
        };
        assert_eq!(
            m.validate(&LIMITS),
            Err(SvnManifestError::EntryMinSvnExceedsCurrent {
                index: 3,
                min_svn: 6,
                current_svn: 5,
            })
        );
    }

    #[test]
    fn validate_ignores_zero_entries() {
        let mut m = empty_manifest();
        // Leave most entries zero, only populate a sparse subset.
        m.entries[0] = McuComponentSvnEntry {
            component_id: 0x1,
            current_svn: 1,
            min_svn: 0,
        };
        m.entries[126] = McuComponentSvnEntry {
            component_id: 0x2,
            current_svn: 1,
            min_svn: 1,
        };
        assert!(m.validate(&LIMITS).is_ok());
    }

    #[test]
    fn entries_present_skips_zero_entries() {
        let mut m = empty_manifest();
        m.entries[5] = McuComponentSvnEntry {
            component_id: 1,
            current_svn: 1,
            min_svn: 0,
        };
        m.entries[100] = McuComponentSvnEntry {
            component_id: 2,
            current_svn: 2,
            min_svn: 1,
        };
        let present: alloc::vec::Vec<_> = m.entries_present().map(|(i, _)| i).collect();
        assert_eq!(present, vec![5, 100]);
    }
}
