// Licensed under the Apache-2.0 license

//! MCU runtime firmware SVN header format and validation. See
//! `docs/src/svn.md`.
//!
//! The header travels inside the (authenticated) MCU runtime image and
//! declares the new `min_svn` floors to commit into OTP. It lives in
//! `romtime` so it can be parsed both by MCU ROM (the OTP writer) and by
//! later stages such as the early runtime image or FMC. This module only
//! defines the on-disk layout, parsing, and structural validation; fuse
//! reads and burns happen in the caller.

use caliptra_mcu_registers_generated::fuses::FuseEntryInfo;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Magic at the start of the header. On disk (little-endian) the bytes
/// are `"VSCM"`; the constant value reads as `"MCSV"` MSB-first.
pub const MCU_COMPONENT_SVN_MANIFEST_MAGIC: u32 = 0x4D43_5356;

/// Currently supported header format version.
pub const MCU_COMPONENT_SVN_MANIFEST_VERSION: u16 = 1;

/// Number of `McuComponentSvnEntry` slots. One slot fewer than
/// Caliptra's `AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT` (127): the space
/// is yielded to the fixed header so the whole structure is exactly
/// 1024 bytes.
pub const MCU_COMPONENT_SVN_MANIFEST_ENTRY_COUNT: usize = 126;

/// Total on-disk size of the header, in bytes (16-byte header + 1008
/// bytes of entries).
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
    /// SVN of this header, enforced against
    /// `MCU_COMPONENT_SVN_MANIFEST_MIN_SVN`.
    pub current_svn: u8,
    /// Requested new floor for `MCU_COMPONENT_SVN_MANIFEST_MIN_SVN`
    /// (0 = no update).
    pub min_svn: u8,
    /// Requested new floor for `CPTRA_CORE_RUNTIME_SVN` (0 = no update).
    /// Burned only when `FW_INFO.fw_svn >= caliptra_runtime_min_svn`.
    pub caliptra_runtime_min_svn: u8,
    /// Requested new floor for `CPTRA_CORE_SOC_MANIFEST_SVN` (0 = no
    /// update) — the shared SoC manifest / MCU Runtime SVN floor.
    /// `FW_INFO` exposes neither running value, so this floor is trusted
    /// from the (authenticated) header.
    pub soc_manifest_min_svn: u8,
    /// Reserved; pads the header to 16 bytes so the structure is exactly
    /// 1024 bytes. Ignored on parse.
    pub reserved: [u8; 6],
    pub entries: [McuComponentSvnEntry; MCU_COMPONENT_SVN_MANIFEST_ENTRY_COUNT],
}

// `#[repr(C)]` lays the fields out in declaration order with each field
// aligned to its type. The header packs to 16 B with no padding (u32 +
// u16 + u8 + u8 + u8 + u8 + [u8; 6]), and the 8-B entries follow
// immediately. These asserts make any future field-order change a
// compile error.
const _: () = assert!(core::mem::size_of::<McuComponentSvnEntry>() == 8);
const _: () =
    assert!(core::mem::size_of::<McuComponentSvnManifest>() == MCU_COMPONENT_SVN_MANIFEST_SIZE);

/// Errors that can result from parsing or validating a header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SvnManifestError {
    /// Byte slice is too short to contain a header.
    TooShort,
    MagicMismatch,
    UnsupportedFormatVersion(u16),
    HeaderMinSvnExceedsCurrent {
        min_svn: u32,
        current_svn: u32,
    },
    /// A header SVN does not fit within its target fuse's one-hot range.
    HeaderSvnExceedsFuseRange {
        value: u32,
        max: u32,
    },
    EntryMinSvnExceedsCurrent {
        index: usize,
        min_svn: u16,
        current_svn: u16,
    },
}

/// One-hot range limits the caller must supply to [`McuComponentSvnManifest::validate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SvnLimits {
    /// Max representable value for `MCU_COMPONENT_SVN_MANIFEST_MIN_SVN`.
    pub manifest_min_svn_max: u32,
    /// Max representable value for `CPTRA_CORE_RUNTIME_SVN`.
    pub caliptra_runtime_min_svn_max: u32,
    /// Max representable value for `CPTRA_CORE_SOC_MANIFEST_SVN`.
    pub soc_manifest_min_svn_max: u32,
}

impl McuComponentSvnManifest {
    /// Parse a header from `bytes` if it begins with the header magic.
    /// Returns `Ok(None)` when the magic is absent (the header is
    /// optional in the MCU runtime image) and `Err(TooShort)` when the
    /// magic is present but the buffer can't fit the struct.
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
    /// consult OTP; the caller separately compares each `current_svn`
    /// against the running firmware and fuse values.
    pub fn validate(&self, limits: &SvnLimits) -> Result<(), SvnManifestError> {
        if self.magic != MCU_COMPONENT_SVN_MANIFEST_MAGIC {
            return Err(SvnManifestError::MagicMismatch);
        }
        if self.format_version != MCU_COMPONENT_SVN_MANIFEST_VERSION {
            return Err(SvnManifestError::UnsupportedFormatVersion(
                self.format_version,
            ));
        }

        // Manifest-self SVN against MCU_COMPONENT_SVN_MANIFEST_MIN_SVN.
        Self::check_svn_pair(
            self.min_svn.into(),
            self.current_svn.into(),
            limits.manifest_min_svn_max,
        )?;
        // Caliptra runtime / SoC manifest floors have no in-header
        // "current" value; just bound them to their fuses' ranges. The
        // Caliptra runtime floor is additionally guarded against
        // `FW_INFO.fw_svn` at burn time.
        Self::check_svn_max(
            self.caliptra_runtime_min_svn.into(),
            limits.caliptra_runtime_min_svn_max,
        )?;
        Self::check_svn_max(
            self.soc_manifest_min_svn.into(),
            limits.soc_manifest_min_svn_max,
        )?;

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

    /// `min_svn <= current_svn` and both fit within `max`.
    fn check_svn_pair(min_svn: u32, current_svn: u32, max: u32) -> Result<(), SvnManifestError> {
        if min_svn > current_svn {
            return Err(SvnManifestError::HeaderMinSvnExceedsCurrent {
                min_svn,
                current_svn,
            });
        }
        Self::check_svn_max(current_svn, max)
    }

    /// `value` fits within `max`.
    fn check_svn_max(value: u32, max: u32) -> Result<(), SvnManifestError> {
        if value > max {
            return Err(SvnManifestError::HeaderSvnExceedsFuseRange { value, max });
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

/// Platform-defined mapping from a SoC `component_id` to a
/// `SOC_IMAGE_MIN_SVN[i]` fuse slot. See `docs/src/svn.md`.
///
/// The map is many-to-one: multiple `component_id` values may share the
/// same fuse slot (typically for components that always update
/// together).
#[derive(Debug, Clone, Copy)]
pub struct SvnFuseMapEntry {
    pub component_id: u32,
    pub fuse_entry: &'static FuseEntryInfo,
}

impl SvnFuseMapEntry {
    /// Look up the fuse slot for `component_id` in `map`. Returns the
    /// first matching entry (the map is many-to-one, so multiple
    /// entries with the same `component_id` are equivalent).
    pub fn lookup(map: &[SvnFuseMapEntry], component_id: u32) -> Option<&'static FuseEntryInfo> {
        map.iter()
            .find(|e| e.component_id == component_id)
            .map(|e| e.fuse_entry)
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
        caliptra_runtime_min_svn_max: 128,
        soc_manifest_min_svn_max: 128,
    };

    fn empty_manifest() -> McuComponentSvnManifest {
        McuComponentSvnManifest {
            magic: MCU_COMPONENT_SVN_MANIFEST_MAGIC,
            format_version: MCU_COMPONENT_SVN_MANIFEST_VERSION,
            current_svn: 0,
            min_svn: 0,
            caliptra_runtime_min_svn: 0,
            soc_manifest_min_svn: 0,
            reserved: [0; 6],
            entries: [McuComponentSvnEntry::default(); MCU_COMPONENT_SVN_MANIFEST_ENTRY_COUNT],
        }
    }

    #[test]
    fn manifest_size_is_expected() {
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
    fn header_size_is_16_bytes() {
        let header_size = MCU_COMPONENT_SVN_MANIFEST_SIZE
            - MCU_COMPONENT_SVN_MANIFEST_ENTRY_COUNT * size_of::<McuComponentSvnEntry>();
        assert_eq!(header_size, 16);
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
        let mut bytes = vec![0u8; 16];
        bytes[0..4].copy_from_slice(&MCU_COMPONENT_SVN_MANIFEST_MAGIC.to_le_bytes());
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
        m.caliptra_runtime_min_svn = 4;
        m.soc_manifest_min_svn = 9;
        m.entries[0] = McuComponentSvnEntry {
            component_id: 0x1000,
            current_svn: 7,
            min_svn: 2,
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
    fn validate_rejects_caliptra_runtime_min_above_range() {
        let mut m = empty_manifest();
        m.caliptra_runtime_min_svn = 200;
        assert_eq!(
            m.validate(&LIMITS),
            Err(SvnManifestError::HeaderSvnExceedsFuseRange {
                value: 200,
                max: 128
            })
        );
    }

    #[test]
    fn validate_rejects_soc_manifest_min_above_range() {
        let mut m = empty_manifest();
        m.soc_manifest_min_svn = 200;
        assert_eq!(
            m.validate(&LIMITS),
            Err(SvnManifestError::HeaderSvnExceedsFuseRange {
                value: 200,
                max: 128
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

    // SvnFuseMapEntry tests use generated fuse entries as stand-in
    // targets; we only exercise the lookup, not OTP access.
    const TEST_FUSE_A: &FuseEntryInfo =
        caliptra_mcu_registers_generated::fuses::SOC_IMAGE_MIN_SVN_0;
    const TEST_FUSE_B: &FuseEntryInfo =
        caliptra_mcu_registers_generated::fuses::SOC_IMAGE_MIN_SVN_1;

    #[test]
    fn svn_fuse_map_lookup_matches_component_id() {
        let map = [
            SvnFuseMapEntry {
                component_id: 0x1000,
                fuse_entry: TEST_FUSE_A,
            },
            SvnFuseMapEntry {
                component_id: 0x2000,
                fuse_entry: TEST_FUSE_B,
            },
        ];
        let got = SvnFuseMapEntry::lookup(&map, 0x2000).unwrap();
        assert_eq!(got.name, TEST_FUSE_B.name);
    }

    #[test]
    fn svn_fuse_map_lookup_missing_returns_none() {
        let map = [SvnFuseMapEntry {
            component_id: 0x1000,
            fuse_entry: TEST_FUSE_A,
        }];
        assert!(SvnFuseMapEntry::lookup(&map, 0xdeadbeef).is_none());
    }

    #[test]
    fn svn_fuse_map_lookup_returns_first_for_many_to_one() {
        // Two component_ids share TEST_FUSE_A; lookup returns the first
        // match, which is equivalent for burn purposes.
        let map = [
            SvnFuseMapEntry {
                component_id: 0x1000,
                fuse_entry: TEST_FUSE_A,
            },
            SvnFuseMapEntry {
                component_id: 0x1001,
                fuse_entry: TEST_FUSE_A,
            },
        ];
        let got = SvnFuseMapEntry::lookup(&map, 0x1001).unwrap();
        assert_eq!(got.name, TEST_FUSE_A.name);
    }
}
