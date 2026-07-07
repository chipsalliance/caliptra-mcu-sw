// Licensed under the Apache-2.0 license

//! Attestation Manifest binary format constants and parsed-view types.

use core::str;

/// Manifest marker (`MCAM` in little-endian bytes), short for MCU Attestation Manifest.
pub const ATTESTATION_MANIFEST_MARKER: u32 = 0x4d41_434d;

/// Initial Attestation Manifest format version.
pub const ATTESTATION_MANIFEST_VERSION: u32 = 1;

/// Size of each serialized component entry.
pub const ATTESTATION_MANIFEST_ENTRY_SIZE: usize = 8;

/// Maximum canonical UTF-8 byte length for each platform-information string.
pub const ATTESTATION_MANIFEST_PLATFORM_INFO_MAX_LEN: usize = 100;

/// Size of the fixed scalar header prefix before the fixed platform-information arrays.
pub const ATTESTATION_MANIFEST_FIXED_HEADER_PREFIX_SIZE: usize = 28;

/// Size of the fixed platform-information region: vendor[100] plus model[100].
pub const ATTESTATION_MANIFEST_FIXED_PLATFORM_INFO_SIZE: usize =
    ATTESTATION_MANIFEST_PLATFORM_INFO_MAX_LEN * 2;

/// Size of the fixed header region before component entries begin.
pub const ATTESTATION_MANIFEST_FIXED_HEADER_SIZE: usize =
    ATTESTATION_MANIFEST_FIXED_HEADER_PREFIX_SIZE + ATTESTATION_MANIFEST_FIXED_PLATFORM_INFO_SIZE;

/// Component is part of the SoC TCB and is measured through the DPE-backed path.
pub const ATTESTATION_FLAG_SOC_TCB_DPE: u32 = 1 << 0;

/// Component is the SoC TCB entry selected as the attestation key target.
pub const ATTESTATION_FLAG_AK_TARGET: u32 = 1 << 1;

/// Attestation flags supported by this format version.
pub const ATTESTATION_FLAGS_SUPPORTED: u32 =
    ATTESTATION_FLAG_SOC_TCB_DPE | ATTESTATION_FLAG_AK_TARGET;

/// MCU Runtime firmware identifier used as the default attestation target.
pub const MCU_RT_FW_ID: u32 = 0x0000_0002;

const HEADER_MARKER_OFFSET: usize = 0;
const HEADER_SIZE_OFFSET: usize = 4;
const HEADER_VERSION_OFFSET: usize = 8;
const HEADER_HEADER_SIZE_OFFSET: usize = 12;
const HEADER_ENTRY_COUNT_OFFSET: usize = 16;
const HEADER_TCB_ENTRY_COUNT_OFFSET: usize = 20;
const HEADER_VENDOR_LEN_OFFSET: usize = 24;
const HEADER_MODEL_LEN_OFFSET: usize = 26;
const HEADER_VENDOR_OFFSET: usize = ATTESTATION_MANIFEST_FIXED_HEADER_PREFIX_SIZE;
const HEADER_MODEL_OFFSET: usize =
    HEADER_VENDOR_OFFSET + ATTESTATION_MANIFEST_PLATFORM_INFO_MAX_LEN;
const ENTRY_FW_ID_OFFSET: usize = 0;
const ENTRY_ATTESTATION_FLAGS_OFFSET: usize = 4;

/// Parsed view of the Attestation Manifest fixed header prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttestationManifestHeader {
    pub marker: u32,
    pub size: u32,
    pub version: u32,
    pub header_size: u32,
    pub entry_count: u32,
    pub tcb_entry_count: u32,
    pub vendor_len: u16,
    pub model_len: u16,
}

/// Parsed view of one Attestation Manifest component entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttestationManifestEntry {
    pub fw_id: u32,
    pub attestation_flags: u32,
}

impl AttestationManifestEntry {
    pub const fn is_tcb(self) -> bool {
        self.attestation_flags & ATTESTATION_FLAG_SOC_TCB_DPE != 0
    }

    pub const fn is_ak_target(self) -> bool {
        self.attestation_flags & ATTESTATION_FLAG_AK_TARGET != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreLayout<'a> {
    pub dpe_fw_ids: &'a [u32],
    pub pcr_fw_ids: &'a [u32],
}

#[derive(Debug, Eq, PartialEq)]
pub enum AttestationManifestError {
    BufferTooSmall,
    InvalidMarker,
    UnsupportedVersion,
    SizeMismatch,
    HeaderSizeMismatch,
    EntryCountOverflow,
    PlatformInfoTooLong,
    InvalidPlatformInfoUtf8,
    NonZeroPlatformInfoUnusedBytes,
    DuplicateFwId,
    UnsupportedAttestationFlags,
    TcbEntryCountMismatch,
    DuplicateAkTarget,
    AkTargetNotTcb,
    StoreLayoutMismatch,
    UnknownFwId,
}

#[derive(Debug)]
pub struct AttestationManifest<'a> {
    bytes: &'a [u8],
    header: AttestationManifestHeader,
    vendor: &'a str,
    model: &'a str,
    entries: &'a [u8],
    ak_target_fw_id: u32,
}

impl<'a> AttestationManifest<'a> {
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub const fn header(&self) -> AttestationManifestHeader {
        self.header
    }

    pub const fn vendor(&self) -> &'a str {
        self.vendor
    }

    pub const fn model(&self) -> &'a str {
        self.model
    }

    pub const fn attestation_target_fw_id(&self) -> u32 {
        self.ak_target_fw_id
    }

    pub fn entries(&self) -> AttestationManifestEntryIter<'a> {
        AttestationManifestEntryIter {
            entries: self.entries,
            offset: 0,
        }
    }

    pub fn lookup(&self, fw_id: u32) -> Result<AttestationManifestEntry, AttestationManifestError> {
        self.entries()
            .find(|entry| entry.fw_id == fw_id)
            .ok_or(AttestationManifestError::UnknownFwId)
    }
}

pub struct AttestationManifestEntryIter<'a> {
    entries: &'a [u8],
    offset: usize,
}

impl Iterator for AttestationManifestEntryIter<'_> {
    type Item = AttestationManifestEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.entries.len() {
            return None;
        }
        let entry = read_entry(self.entries, self.offset).ok()?;
        self.offset += ATTESTATION_MANIFEST_ENTRY_SIZE;
        Some(entry)
    }
}

pub fn parse_and_validate(
    bytes: &[u8],
) -> Result<AttestationManifest<'_>, AttestationManifestError> {
    let header = parse_header(bytes)?;
    validate_header(bytes, header)?;

    let vendor_len = usize::from(header.vendor_len);
    let model_len = usize::from(header.model_len);
    if vendor_len > ATTESTATION_MANIFEST_PLATFORM_INFO_MAX_LEN
        || model_len > ATTESTATION_MANIFEST_PLATFORM_INFO_MAX_LEN
    {
        return Err(AttestationManifestError::PlatformInfoTooLong);
    }

    let header_size = usize::try_from(header.header_size)
        .map_err(|_| AttestationManifestError::HeaderSizeMismatch)?;
    if header_size != ATTESTATION_MANIFEST_FIXED_HEADER_SIZE || header_size > bytes.len() {
        return Err(AttestationManifestError::HeaderSizeMismatch);
    }

    let vendor_bytes = &bytes[HEADER_VENDOR_OFFSET..HEADER_MODEL_OFFSET];
    let model_bytes = &bytes[HEADER_MODEL_OFFSET..header_size];
    let vendor = str::from_utf8(&vendor_bytes[..vendor_len])
        .map_err(|_| AttestationManifestError::InvalidPlatformInfoUtf8)?;
    let model = str::from_utf8(&model_bytes[..model_len])
        .map_err(|_| AttestationManifestError::InvalidPlatformInfoUtf8)?;
    if vendor_bytes[vendor_len..].iter().any(|byte| *byte != 0)
        || model_bytes[model_len..].iter().any(|byte| *byte != 0)
    {
        return Err(AttestationManifestError::NonZeroPlatformInfoUnusedBytes);
    }

    let entry_count = usize::try_from(header.entry_count)
        .map_err(|_| AttestationManifestError::EntryCountOverflow)?;
    let entries_len = entry_count
        .checked_mul(ATTESTATION_MANIFEST_ENTRY_SIZE)
        .ok_or(AttestationManifestError::EntryCountOverflow)?;
    let expected_size = header_size
        .checked_add(entries_len)
        .ok_or(AttestationManifestError::EntryCountOverflow)?;
    if expected_size != bytes.len() {
        return Err(AttestationManifestError::SizeMismatch);
    }

    let entries = &bytes[header_size..expected_size];
    let (_, ak_target_fw_id) = validate_entries(entries, header)?;

    Ok(AttestationManifest {
        bytes,
        header,
        vendor,
        model,
        entries,
        ak_target_fw_id,
    })
}

pub fn validate_store_layout(
    manifest: &AttestationManifest<'_>,
    layout: StoreLayout<'_>,
) -> Result<(), AttestationManifestError> {
    let mut expected_dpe_count = 0usize;
    let mut expected_pcr_count = 0usize;

    for entry in manifest.entries() {
        let (store, index) = if entry.is_tcb() {
            let index = expected_dpe_count;
            expected_dpe_count += 1;
            (layout.dpe_fw_ids, index)
        } else {
            let index = expected_pcr_count;
            expected_pcr_count += 1;
            (layout.pcr_fw_ids, index)
        };

        if store.get(index).copied() != Some(entry.fw_id) {
            return Err(AttestationManifestError::StoreLayoutMismatch);
        }
    }

    if expected_dpe_count != layout.dpe_fw_ids.len()
        || expected_pcr_count != layout.pcr_fw_ids.len()
    {
        return Err(AttestationManifestError::StoreLayoutMismatch);
    }

    Ok(())
}

fn parse_header(bytes: &[u8]) -> Result<AttestationManifestHeader, AttestationManifestError> {
    if bytes.len() < ATTESTATION_MANIFEST_FIXED_HEADER_SIZE {
        return Err(AttestationManifestError::BufferTooSmall);
    }
    Ok(AttestationManifestHeader {
        marker: read_u32(bytes, HEADER_MARKER_OFFSET)?,
        size: read_u32(bytes, HEADER_SIZE_OFFSET)?,
        version: read_u32(bytes, HEADER_VERSION_OFFSET)?,
        header_size: read_u32(bytes, HEADER_HEADER_SIZE_OFFSET)?,
        entry_count: read_u32(bytes, HEADER_ENTRY_COUNT_OFFSET)?,
        tcb_entry_count: read_u32(bytes, HEADER_TCB_ENTRY_COUNT_OFFSET)?,
        vendor_len: read_u16(bytes, HEADER_VENDOR_LEN_OFFSET)?,
        model_len: read_u16(bytes, HEADER_MODEL_LEN_OFFSET)?,
    })
}

fn validate_header(
    bytes: &[u8],
    header: AttestationManifestHeader,
) -> Result<(), AttestationManifestError> {
    if header.marker != ATTESTATION_MANIFEST_MARKER {
        return Err(AttestationManifestError::InvalidMarker);
    }
    if header.version != ATTESTATION_MANIFEST_VERSION {
        return Err(AttestationManifestError::UnsupportedVersion);
    }
    let size = usize::try_from(header.size).map_err(|_| AttestationManifestError::SizeMismatch)?;
    if bytes.len() != size {
        return Err(AttestationManifestError::SizeMismatch);
    }
    Ok(())
}

fn validate_entries(
    entries: &[u8],
    header: AttestationManifestHeader,
) -> Result<(usize, u32), AttestationManifestError> {
    let entry_count = usize::try_from(header.entry_count)
        .map_err(|_| AttestationManifestError::EntryCountOverflow)?;
    let expected_tcb_count = usize::try_from(header.tcb_entry_count)
        .map_err(|_| AttestationManifestError::EntryCountOverflow)?;
    let mut tcb_count = 0usize;
    let mut ak_target_fw_id = None;

    for index in 0..entry_count {
        let offset = index * ATTESTATION_MANIFEST_ENTRY_SIZE;
        let entry = read_entry(entries, offset)?;
        if entry.attestation_flags & !ATTESTATION_FLAGS_SUPPORTED != 0 {
            return Err(AttestationManifestError::UnsupportedAttestationFlags);
        }
        if duplicate_fw_id(entries, index, entry.fw_id)? {
            return Err(AttestationManifestError::DuplicateFwId);
        }
        if entry.is_tcb() {
            tcb_count += 1;
        }
        if entry.is_ak_target() {
            if !entry.is_tcb() {
                return Err(AttestationManifestError::AkTargetNotTcb);
            }
            if ak_target_fw_id.replace(entry.fw_id).is_some() {
                return Err(AttestationManifestError::DuplicateAkTarget);
            }
        }
    }

    if tcb_count != expected_tcb_count {
        return Err(AttestationManifestError::TcbEntryCountMismatch);
    }

    Ok((tcb_count, ak_target_fw_id.unwrap_or(MCU_RT_FW_ID)))
}

fn duplicate_fw_id(
    entries: &[u8],
    current_index: usize,
    fw_id: u32,
) -> Result<bool, AttestationManifestError> {
    for index in 0..current_index {
        let offset = index * ATTESTATION_MANIFEST_ENTRY_SIZE;
        if read_entry(entries, offset)?.fw_id == fw_id {
            return Ok(true);
        }
    }
    Ok(false)
}

fn read_entry(
    bytes: &[u8],
    offset: usize,
) -> Result<AttestationManifestEntry, AttestationManifestError> {
    Ok(AttestationManifestEntry {
        fw_id: read_u32(bytes, offset + ENTRY_FW_ID_OFFSET)?,
        attestation_flags: read_u32(bytes, offset + ENTRY_ATTESTATION_FLAGS_OFFSET)?,
    })
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, AttestationManifestError> {
    let end = offset
        .checked_add(core::mem::size_of::<u32>())
        .ok_or(AttestationManifestError::BufferTooSmall)?;
    let bytes = bytes
        .get(offset..end)
        .ok_or(AttestationManifestError::BufferTooSmall)?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, AttestationManifestError> {
    let end = offset
        .checked_add(core::mem::size_of::<u16>())
        .ok_or(AttestationManifestError::BufferTooSmall)?;
    let bytes = bytes
        .get(offset..end)
        .ok_or(AttestationManifestError::BufferTooSmall)?;
    Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    const TCB_FW_ID: u32 = 0x1000;
    const CHILD_TCB_FW_ID: u32 = 0x1001;
    const NON_TCB_FW_ID: u32 = 0x2000;

    fn push_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u16(out: &mut Vec<u8>, value: u16) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn entry(fw_id: u32, flags: u32) -> [u8; ATTESTATION_MANIFEST_ENTRY_SIZE] {
        let mut entry = [0u8; ATTESTATION_MANIFEST_ENTRY_SIZE];
        entry[..4].copy_from_slice(&fw_id.to_le_bytes());
        entry[4..].copy_from_slice(&flags.to_le_bytes());
        entry
    }

    fn manifest(vendor: &str, model: &str, entries: &[[u8; 8]]) -> Vec<u8> {
        assert!(vendor.len() <= ATTESTATION_MANIFEST_PLATFORM_INFO_MAX_LEN);
        assert!(model.len() <= ATTESTATION_MANIFEST_PLATFORM_INFO_MAX_LEN);
        let header_size = ATTESTATION_MANIFEST_FIXED_HEADER_SIZE;
        let size = header_size + entries.len() * ATTESTATION_MANIFEST_ENTRY_SIZE;
        let tcb_entry_count = entries
            .iter()
            .filter(|entry| {
                let flags = u32::from_le_bytes(entry[4..].try_into().unwrap());
                flags & ATTESTATION_FLAG_SOC_TCB_DPE != 0
            })
            .count();
        let mut out = Vec::new();
        push_u32(&mut out, ATTESTATION_MANIFEST_MARKER);
        push_u32(&mut out, size as u32);
        push_u32(&mut out, ATTESTATION_MANIFEST_VERSION);
        push_u32(&mut out, header_size as u32);
        push_u32(&mut out, entries.len() as u32);
        push_u32(&mut out, tcb_entry_count as u32);
        push_u16(&mut out, vendor.len() as u16);
        push_u16(&mut out, model.len() as u16);
        out.extend_from_slice(vendor.as_bytes());
        out.resize(HEADER_MODEL_OFFSET, 0);
        out.extend_from_slice(model.as_bytes());
        out.resize(header_size, 0);
        for entry in entries {
            out.extend_from_slice(entry);
        }
        out
    }

    fn set_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn valid_empty_manifest_defaults_to_mcu_ak_target() {
        let bytes = manifest("vendor", "model", &[]);
        let manifest = parse_and_validate(&bytes).unwrap();

        assert_eq!(manifest.vendor(), "vendor");
        assert_eq!(manifest.model(), "model");
        assert_eq!(manifest.attestation_target_fw_id(), MCU_RT_FW_ID);
        assert_eq!(manifest.entries().count(), 0);
    }

    #[test]
    fn valid_manifest_iterates_entries_and_reads_ak_target() {
        let bytes = manifest(
            "v",
            "m",
            &[
                entry(
                    TCB_FW_ID,
                    ATTESTATION_FLAG_SOC_TCB_DPE | ATTESTATION_FLAG_AK_TARGET,
                ),
                entry(CHILD_TCB_FW_ID, ATTESTATION_FLAG_SOC_TCB_DPE),
                entry(NON_TCB_FW_ID, 0),
            ],
        );

        let manifest = parse_and_validate(&bytes).unwrap();
        let entries: Vec<_> = manifest.entries().collect();

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].fw_id, TCB_FW_ID);
        assert!(entries[0].is_tcb());
        assert!(entries[0].is_ak_target());
        assert_eq!(manifest.lookup(NON_TCB_FW_ID).unwrap().fw_id, NON_TCB_FW_ID);
        assert_eq!(manifest.attestation_target_fw_id(), TCB_FW_ID);
    }

    #[test]
    fn size_mismatch_is_rejected() {
        let mut bytes = manifest("v", "m", &[]);
        bytes.push(0);

        assert_eq!(
            parse_and_validate(&bytes).unwrap_err(),
            AttestationManifestError::SizeMismatch
        );
    }

    #[test]
    fn non_zero_platform_info_unused_bytes_are_rejected() {
        let mut bytes = manifest("vv", "m", &[]);
        bytes[HEADER_VENDOR_OFFSET + 2] = 1;

        assert_eq!(
            parse_and_validate(&bytes).unwrap_err(),
            AttestationManifestError::NonZeroPlatformInfoUnusedBytes
        );
    }

    #[test]
    fn duplicate_fw_id_is_rejected() {
        let bytes = manifest(
            "v",
            "m",
            &[
                entry(TCB_FW_ID, ATTESTATION_FLAG_SOC_TCB_DPE),
                entry(TCB_FW_ID, ATTESTATION_FLAG_SOC_TCB_DPE),
            ],
        );

        assert_eq!(
            parse_and_validate(&bytes).unwrap_err(),
            AttestationManifestError::DuplicateFwId
        );
    }

    #[test]
    fn reserved_flags_are_rejected() {
        let bytes = manifest("v", "m", &[entry(TCB_FW_ID, 1 << 31)]);

        assert_eq!(
            parse_and_validate(&bytes).unwrap_err(),
            AttestationManifestError::UnsupportedAttestationFlags
        );
    }

    #[test]
    fn duplicate_ak_target_is_rejected() {
        let bytes = manifest(
            "v",
            "m",
            &[
                entry(
                    TCB_FW_ID,
                    ATTESTATION_FLAG_SOC_TCB_DPE | ATTESTATION_FLAG_AK_TARGET,
                ),
                entry(
                    CHILD_TCB_FW_ID,
                    ATTESTATION_FLAG_SOC_TCB_DPE | ATTESTATION_FLAG_AK_TARGET,
                ),
            ],
        );

        assert_eq!(
            parse_and_validate(&bytes).unwrap_err(),
            AttestationManifestError::DuplicateAkTarget
        );
    }

    #[test]
    fn ak_target_without_tcb_is_rejected() {
        let bytes = manifest(
            "v",
            "m",
            &[entry(NON_TCB_FW_ID, ATTESTATION_FLAG_AK_TARGET)],
        );

        assert_eq!(
            parse_and_validate(&bytes).unwrap_err(),
            AttestationManifestError::AkTargetNotTcb
        );
    }

    #[test]
    fn mixed_tcb_and_non_tcb_order_is_accepted() {
        let bytes = manifest(
            "v",
            "m",
            &[
                entry(TCB_FW_ID, ATTESTATION_FLAG_SOC_TCB_DPE),
                entry(NON_TCB_FW_ID, 0),
                entry(CHILD_TCB_FW_ID, ATTESTATION_FLAG_SOC_TCB_DPE),
            ],
        );
        let manifest = parse_and_validate(&bytes).unwrap();

        assert_eq!(manifest.header().tcb_entry_count, 2);
        validate_store_layout(
            &manifest,
            StoreLayout {
                dpe_fw_ids: &[TCB_FW_ID, CHILD_TCB_FW_ID],
                pcr_fw_ids: &[NON_TCB_FW_ID],
            },
        )
        .unwrap();
    }

    #[test]
    fn tcb_entry_count_mismatch_is_rejected() {
        let mut bytes = manifest("v", "m", &[entry(TCB_FW_ID, ATTESTATION_FLAG_SOC_TCB_DPE)]);
        set_u32(&mut bytes, HEADER_TCB_ENTRY_COUNT_OFFSET, 0);

        assert_eq!(
            parse_and_validate(&bytes).unwrap_err(),
            AttestationManifestError::TcbEntryCountMismatch
        );
    }

    #[test]
    fn store_layout_matches_manifest_split_and_order() {
        let bytes = manifest(
            "v",
            "m",
            &[
                entry(TCB_FW_ID, ATTESTATION_FLAG_SOC_TCB_DPE),
                entry(CHILD_TCB_FW_ID, ATTESTATION_FLAG_SOC_TCB_DPE),
                entry(NON_TCB_FW_ID, 0),
            ],
        );
        let manifest = parse_and_validate(&bytes).unwrap();

        validate_store_layout(
            &manifest,
            StoreLayout {
                dpe_fw_ids: &[TCB_FW_ID, CHILD_TCB_FW_ID],
                pcr_fw_ids: &[NON_TCB_FW_ID],
            },
        )
        .unwrap();
    }

    #[test]
    fn store_layout_mismatch_is_rejected() {
        let bytes = manifest(
            "v",
            "m",
            &[
                entry(TCB_FW_ID, ATTESTATION_FLAG_SOC_TCB_DPE),
                entry(NON_TCB_FW_ID, 0),
            ],
        );
        let manifest = parse_and_validate(&bytes).unwrap();

        assert_eq!(
            validate_store_layout(
                &manifest,
                StoreLayout {
                    dpe_fw_ids: &[NON_TCB_FW_ID],
                    pcr_fw_ids: &[TCB_FW_ID],
                },
            ),
            Err(AttestationManifestError::StoreLayoutMismatch)
        );
    }

    #[test]
    fn unknown_lookup_is_rejected() {
        let bytes = manifest("v", "m", &[]);
        let manifest = parse_and_validate(&bytes).unwrap();

        assert_eq!(
            manifest.lookup(TCB_FW_ID),
            Err(AttestationManifestError::UnknownFwId)
        );
    }
}
