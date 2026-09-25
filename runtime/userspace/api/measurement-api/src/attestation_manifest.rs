// Licensed under the Apache-2.0 license

//! Attestation Manifest binary format constants and parsed-view types.

use core::str;

/// Manifest marker (`MCAM` in little-endian bytes), short for MCU Attestation Manifest.
pub const ATTESTATION_MANIFEST_MARKER: u32 = 0x4d41_434d;

/// Owner Attestation Manifest marker (`MOAM` in little-endian bytes).
pub const OWNER_ATTESTATION_MANIFEST_MARKER: u32 = 0x4d41_4f4d;

/// Owner FW Load List marker (`MOLL` in little-endian bytes).
pub const OWNER_FW_LOAD_LIST_MARKER: u32 = 0x4c4c_4f4d;

/// Owner FW Load List format version.
pub const OWNER_FW_LOAD_LIST_VERSION: u32 = 1;

/// Initial Attestation Manifest format version.
pub const ATTESTATION_MANIFEST_VERSION: u32 = 1;

/// Size of each serialized component entry.
pub const ATTESTATION_MANIFEST_ENTRY_SIZE: usize = 8;

/// Maximum canonical UTF-8 byte length for each platform-information string.
pub const ATTESTATION_MANIFEST_PLATFORM_INFO_MAX_LEN: usize = 100;

/// Size of the fixed scalar header prefix before the fixed platform-information arrays.
pub const ATTESTATION_MANIFEST_FIXED_HEADER_PREFIX_SIZE: usize = 28;

/// Size of the fixed platform-information region: `vendor[100]` plus `model[100]`.
pub const ATTESTATION_MANIFEST_FIXED_PLATFORM_INFO_SIZE: usize =
    ATTESTATION_MANIFEST_PLATFORM_INFO_MAX_LEN * 2;

/// Size of the fixed header region before component entries begin.
pub const ATTESTATION_MANIFEST_FIXED_HEADER_SIZE: usize =
    ATTESTATION_MANIFEST_FIXED_HEADER_PREFIX_SIZE + ATTESTATION_MANIFEST_FIXED_PLATFORM_INFO_SIZE;

/// Size of the fixed header for the Owner Attestation Manifest (no platform-info region).
pub const OWNER_ATTESTATION_MANIFEST_FIXED_HEADER_SIZE: usize =
    ATTESTATION_MANIFEST_FIXED_HEADER_PREFIX_SIZE;

/// Size of the fixed header for the Owner FW Load List.
pub const OWNER_FW_LOAD_LIST_FIXED_HEADER_SIZE: usize = 16;

/// Component is part of the SoC TCB and is measured through the DPE-backed path.
pub const ATTESTATION_FLAG_SOC_TCB_DPE: u32 = 1 << 0;

/// Component is the SoC TCB entry selected as the attestation key target.
pub const ATTESTATION_FLAG_AK_TARGET: u32 = 1 << 1;

/// Attestation flags supported by this format version.
pub const ATTESTATION_FLAGS_SUPPORTED: u32 =
    ATTESTATION_FLAG_SOC_TCB_DPE | ATTESTATION_FLAG_AK_TARGET;

/// MCU Runtime firmware identifier used as the default attestation target.
pub const MCU_RT_FW_ID: u32 = 0x0000_0002;

/// Reserved component identifier for the Vendor Authorization Key digest entry in Base SoC Manifest.
pub const V_AUTH_KEY_ID: u32 = 0x0000_0004;

/// Reserved component identifier for the Owner Measurement Policy payload (Component 0x5).
pub const OWNER_MEASUREMENT_POLICY_IDENTIFIER: u32 = 0x0000_0005;

/// Reserved component identifier for the Owner Authorization Key digest entry in Owner SoC Manifest.
pub const O_AUTH_KEY_ID: u32 = 0x0000_0006;

/// Minimum identifier for non-control owner firmware components (0x0001_0000..=0xFFFF_FFFF).
pub const OWNER_FW_ID_MIN: u32 = 0x0001_0000;

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
    OwnerAkTargetNotAllowed,
    OwnerFwIdOutOfRange,
    MissingRequiredEntry,
    TcbEntriesNotContiguous,
    InvalidLoadListMarker,
    InvalidLoadListSize,
    LoadListManifestMismatch,
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

    pub const fn is_owner(&self) -> bool {
        self.header.marker == OWNER_ATTESTATION_MANIFEST_MARKER
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
    parse_and_validate_internal(bytes, false)
}

pub fn parse_and_validate_owner(
    bytes: &[u8],
) -> Result<AttestationManifest<'_>, AttestationManifestError> {
    parse_and_validate_internal(bytes, true)
}

fn parse_and_validate_internal(
    bytes: &[u8],
    is_owner: bool,
) -> Result<AttestationManifest<'_>, AttestationManifestError> {
    let header = parse_header(bytes, is_owner)?;
    validate_header(bytes, header, is_owner)?;

    let (header_size, vendor, model) = if is_owner {
        if header.header_size as usize != OWNER_ATTESTATION_MANIFEST_FIXED_HEADER_SIZE {
            return Err(AttestationManifestError::HeaderSizeMismatch);
        }
        if header.vendor_len != 0 || header.model_len != 0 {
            return Err(AttestationManifestError::PlatformInfoTooLong);
        }
        (OWNER_ATTESTATION_MANIFEST_FIXED_HEADER_SIZE, "", "")
    } else {
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

        let vendor_bytes = checked_slice(
            bytes,
            HEADER_VENDOR_OFFSET,
            ATTESTATION_MANIFEST_PLATFORM_INFO_MAX_LEN,
        )?;
        let model_bytes = checked_slice(
            bytes,
            HEADER_MODEL_OFFSET,
            ATTESTATION_MANIFEST_PLATFORM_INFO_MAX_LEN,
        )?;
        let vendor = str::from_utf8(
            vendor_bytes
                .get(..vendor_len)
                .ok_or(AttestationManifestError::PlatformInfoTooLong)?,
        )
        .map_err(|_| AttestationManifestError::InvalidPlatformInfoUtf8)?;
        let model = str::from_utf8(
            model_bytes
                .get(..model_len)
                .ok_or(AttestationManifestError::PlatformInfoTooLong)?,
        )
        .map_err(|_| AttestationManifestError::InvalidPlatformInfoUtf8)?;
        if vendor_bytes
            .get(vendor_len..)
            .ok_or(AttestationManifestError::PlatformInfoTooLong)?
            .iter()
            .any(|byte| *byte != 0)
            || model_bytes
                .get(model_len..)
                .ok_or(AttestationManifestError::PlatformInfoTooLong)?
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(AttestationManifestError::NonZeroPlatformInfoUnusedBytes);
        }
        (header_size, vendor, model)
    };

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

    let entries = checked_slice(bytes, header_size, entries_len)?;
    let (_, ak_target_fw_id) = validate_entries(entries, header, is_owner)?;

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

fn parse_header(
    bytes: &[u8],
    is_owner: bool,
) -> Result<AttestationManifestHeader, AttestationManifestError> {
    if bytes.len() < ATTESTATION_MANIFEST_FIXED_HEADER_PREFIX_SIZE {
        return Err(AttestationManifestError::BufferTooSmall);
    }
    let marker = read_u32(bytes, HEADER_MARKER_OFFSET)?;
    let expected_marker = if is_owner {
        OWNER_ATTESTATION_MANIFEST_MARKER
    } else {
        ATTESTATION_MANIFEST_MARKER
    };
    if marker != expected_marker {
        return Err(AttestationManifestError::InvalidMarker);
    }
    let min_size = if is_owner {
        OWNER_ATTESTATION_MANIFEST_FIXED_HEADER_SIZE
    } else {
        ATTESTATION_MANIFEST_FIXED_HEADER_SIZE
    };
    if bytes.len() < min_size {
        return Err(AttestationManifestError::BufferTooSmall);
    }
    Ok(AttestationManifestHeader {
        marker,
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
    is_owner: bool,
) -> Result<(), AttestationManifestError> {
    let expected_marker = if is_owner {
        OWNER_ATTESTATION_MANIFEST_MARKER
    } else {
        ATTESTATION_MANIFEST_MARKER
    };
    if header.marker != expected_marker {
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
    is_owner: bool,
) -> Result<(usize, u32), AttestationManifestError> {
    let entry_count = usize::try_from(header.entry_count)
        .map_err(|_| AttestationManifestError::EntryCountOverflow)?;
    let expected_tcb_count = usize::try_from(header.tcb_entry_count)
        .map_err(|_| AttestationManifestError::EntryCountOverflow)?;
    let mut tcb_count = 0usize;
    let mut ak_target_fw_id = None;
    let mut seen_non_tcb = false;
    let mut has_policy_entry = false;
    let mut has_owner_auth_key_entry = false;

    for index in 0..entry_count {
        let offset = index * ATTESTATION_MANIFEST_ENTRY_SIZE;
        let entry = read_entry(entries, offset)?;
        if entry.attestation_flags & !ATTESTATION_FLAGS_SUPPORTED != 0 {
            return Err(AttestationManifestError::UnsupportedAttestationFlags);
        }
        if duplicate_fw_id(entries, index, entry.fw_id)? {
            return Err(AttestationManifestError::DuplicateFwId);
        }
        if is_owner
            && entry.fw_id != OWNER_MEASUREMENT_POLICY_IDENTIFIER
            && entry.fw_id != O_AUTH_KEY_ID
            && entry.fw_id < OWNER_FW_ID_MIN
        {
            return Err(AttestationManifestError::OwnerFwIdOutOfRange);
        }
        if entry.is_ak_target() {
            if is_owner {
                return Err(AttestationManifestError::OwnerAkTargetNotAllowed);
            }
            if !entry.is_tcb() {
                return Err(AttestationManifestError::AkTargetNotTcb);
            }
            if ak_target_fw_id.replace(entry.fw_id).is_some() {
                return Err(AttestationManifestError::DuplicateAkTarget);
            }
        }
        if entry.is_tcb() {
            if is_owner && seen_non_tcb {
                return Err(AttestationManifestError::TcbEntriesNotContiguous);
            }
            tcb_count += 1;
            if entry.fw_id == OWNER_MEASUREMENT_POLICY_IDENTIFIER {
                has_policy_entry = true;
            } else if entry.fw_id == O_AUTH_KEY_ID {
                has_owner_auth_key_entry = true;
            }
        } else {
            seen_non_tcb = true;
        }
    }

    if tcb_count != expected_tcb_count {
        return Err(AttestationManifestError::TcbEntryCountMismatch);
    }

    if is_owner && (!has_policy_entry || !has_owner_auth_key_entry) {
        return Err(AttestationManifestError::MissingRequiredEntry);
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

/// Parsed view of the Owner FW Load List header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerFwLoadListHeader {
    pub marker: u32,
    pub size: u32,
    pub version: u32,
    pub entry_count: u32,
}

/// Parsed view of an Owner FW Load List.
#[derive(Debug)]
pub struct OwnerFwLoadList<'a> {
    bytes: &'a [u8],
    header: OwnerFwLoadListHeader,
    entries: &'a [u8],
}

impl<'a> OwnerFwLoadList<'a> {
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub const fn header(&self) -> OwnerFwLoadListHeader {
        self.header
    }

    pub const fn entry_count(&self) -> usize {
        self.header.entry_count as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.header.entry_count == 0
    }

    pub fn entries(&self) -> OwnerFwLoadListIter<'a> {
        OwnerFwLoadListIter {
            entries: self.entries,
            offset: 0,
        }
    }

    pub fn contains(&self, fw_id: u32) -> bool {
        self.entries().any(|id| id == fw_id)
    }
}

pub struct OwnerFwLoadListIter<'a> {
    entries: &'a [u8],
    offset: usize,
}

impl Iterator for OwnerFwLoadListIter<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.entries.len() {
            return None;
        }
        let val = read_u32(self.entries, self.offset).ok()?;
        self.offset += core::mem::size_of::<u32>();
        Some(val)
    }
}

pub fn parse_and_validate_owner_fw_load_list(
    bytes: &[u8],
) -> Result<OwnerFwLoadList<'_>, AttestationManifestError> {
    if bytes.len() < OWNER_FW_LOAD_LIST_FIXED_HEADER_SIZE {
        return Err(AttestationManifestError::BufferTooSmall);
    }
    let marker = read_u32(bytes, 0)?;
    let size = read_u32(bytes, 4)?;
    let version = read_u32(bytes, 8)?;
    let entry_count = read_u32(bytes, 12)?;

    if marker != OWNER_FW_LOAD_LIST_MARKER {
        return Err(AttestationManifestError::InvalidLoadListMarker);
    }
    if version != OWNER_FW_LOAD_LIST_VERSION {
        return Err(AttestationManifestError::UnsupportedVersion);
    }
    let count =
        usize::try_from(entry_count).map_err(|_| AttestationManifestError::EntryCountOverflow)?;
    let entries_len = count
        .checked_mul(core::mem::size_of::<u32>())
        .ok_or(AttestationManifestError::EntryCountOverflow)?;
    let expected_size = OWNER_FW_LOAD_LIST_FIXED_HEADER_SIZE
        .checked_add(entries_len)
        .ok_or(AttestationManifestError::EntryCountOverflow)?;
    if size as usize != expected_size || bytes.len() != expected_size {
        return Err(AttestationManifestError::InvalidLoadListSize);
    }

    let entries = checked_slice(bytes, OWNER_FW_LOAD_LIST_FIXED_HEADER_SIZE, entries_len)?;
    for i in 0..count {
        let fw_id = read_u32(entries, i * core::mem::size_of::<u32>())?;
        if fw_id < OWNER_FW_ID_MIN {
            return Err(AttestationManifestError::OwnerFwIdOutOfRange);
        }
        for j in 0..i {
            let prev_fw_id = read_u32(entries, j * core::mem::size_of::<u32>())?;
            if fw_id == prev_fw_id {
                return Err(AttestationManifestError::DuplicateFwId);
            }
        }
    }

    let header = OwnerFwLoadListHeader {
        marker,
        size,
        version,
        entry_count,
    };

    Ok(OwnerFwLoadList {
        bytes,
        header,
        entries,
    })
}

/// Parsed view of the complete Owner Measurement Policy container (Component 0x5).
#[derive(Debug)]
pub struct OwnerMeasurementPolicy<'a> {
    raw_bytes: &'a [u8],
    manifest: AttestationManifest<'a>,
    load_list: OwnerFwLoadList<'a>,
}

impl<'a> OwnerMeasurementPolicy<'a> {
    pub const fn raw_bytes(&self) -> &'a [u8] {
        self.raw_bytes
    }

    pub const fn manifest(&self) -> &AttestationManifest<'a> {
        &self.manifest
    }

    pub const fn load_list(&self) -> &OwnerFwLoadList<'a> {
        &self.load_list
    }
}

pub fn parse_and_validate_owner_measurement_policy(
    bytes: &[u8],
) -> Result<OwnerMeasurementPolicy<'_>, AttestationManifestError> {
    if bytes.len() < OWNER_ATTESTATION_MANIFEST_FIXED_HEADER_SIZE {
        return Err(AttestationManifestError::BufferTooSmall);
    }
    let manifest_size = usize::try_from(read_u32(bytes, HEADER_SIZE_OFFSET)?)
        .map_err(|_| AttestationManifestError::SizeMismatch)?;
    if manifest_size > bytes.len() {
        return Err(AttestationManifestError::SizeMismatch);
    }

    let manifest_bytes = checked_slice(bytes, 0, manifest_size)?;
    let manifest = parse_and_validate_owner(manifest_bytes)?;

    let load_list_bytes = checked_slice(bytes, manifest_size, bytes.len() - manifest_size)?;
    let load_list = parse_and_validate_owner_fw_load_list(load_list_bytes)?;

    // Validate 1:1 correspondence between load list and manifest non-control entries
    let mut non_control_manifest_count = 0usize;
    for entry in manifest.entries() {
        if entry.fw_id != OWNER_MEASUREMENT_POLICY_IDENTIFIER && entry.fw_id != O_AUTH_KEY_ID {
            non_control_manifest_count += 1;
            if !load_list.contains(entry.fw_id) {
                return Err(AttestationManifestError::LoadListManifestMismatch);
            }
        }
    }
    if non_control_manifest_count != load_list.entry_count() {
        return Err(AttestationManifestError::LoadListManifestMismatch);
    }

    Ok(OwnerMeasurementPolicy {
        raw_bytes: bytes,
        manifest,
        load_list,
    })
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
    let mut out = [0u8; core::mem::size_of::<u32>()];
    copy_bytes(
        &mut out,
        checked_slice(bytes, offset, core::mem::size_of::<u32>())?,
    );
    Ok(u32::from_le_bytes(out))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, AttestationManifestError> {
    let mut out = [0u8; core::mem::size_of::<u16>()];
    copy_bytes(
        &mut out,
        checked_slice(bytes, offset, core::mem::size_of::<u16>())?,
    );
    Ok(u16::from_le_bytes(out))
}

fn checked_slice(
    bytes: &[u8],
    offset: usize,
    len: usize,
) -> Result<&[u8], AttestationManifestError> {
    let end = offset
        .checked_add(len)
        .ok_or(AttestationManifestError::BufferTooSmall)?;
    bytes
        .get(offset..end)
        .ok_or(AttestationManifestError::BufferTooSmall)
}

fn copy_bytes(dst: &mut [u8], src: &[u8]) {
    for (dst_byte, src_byte) in dst.iter_mut().zip(src.iter()) {
        *dst_byte = *src_byte;
    }
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

    fn owner_manifest(entries: &[[u8; 8]]) -> Vec<u8> {
        let header_size = OWNER_ATTESTATION_MANIFEST_FIXED_HEADER_SIZE;
        let size = header_size + entries.len() * ATTESTATION_MANIFEST_ENTRY_SIZE;
        let tcb_entry_count = entries
            .iter()
            .filter(|entry| {
                let flags = u32::from_le_bytes(entry[4..].try_into().unwrap());
                flags & ATTESTATION_FLAG_SOC_TCB_DPE != 0
            })
            .count();
        let mut out = Vec::new();
        push_u32(&mut out, OWNER_ATTESTATION_MANIFEST_MARKER);
        push_u32(&mut out, size as u32);
        push_u32(&mut out, ATTESTATION_MANIFEST_VERSION);
        push_u32(&mut out, header_size as u32);
        push_u32(&mut out, entries.len() as u32);
        push_u32(&mut out, tcb_entry_count as u32);
        push_u16(&mut out, 0);
        push_u16(&mut out, 0);
        for entry in entries {
            out.extend_from_slice(entry);
        }
        out
    }

    fn owner_load_list(fw_ids: &[u32]) -> Vec<u8> {
        let header_size = OWNER_FW_LOAD_LIST_FIXED_HEADER_SIZE;
        let size = header_size + fw_ids.len() * 4;
        let mut out = Vec::new();
        push_u32(&mut out, OWNER_FW_LOAD_LIST_MARKER);
        push_u32(&mut out, size as u32);
        push_u32(&mut out, OWNER_FW_LOAD_LIST_VERSION);
        push_u32(&mut out, fw_ids.len() as u32);
        for fw_id in fw_ids {
            push_u32(&mut out, *fw_id);
        }
        out
    }

    #[test]
    fn valid_owner_manifest_roundtrip() {
        let bytes = owner_manifest(&[
            entry(
                OWNER_MEASUREMENT_POLICY_IDENTIFIER,
                ATTESTATION_FLAG_SOC_TCB_DPE,
            ),
            entry(O_AUTH_KEY_ID, ATTESTATION_FLAG_SOC_TCB_DPE),
            entry(0x10000, ATTESTATION_FLAG_SOC_TCB_DPE),
            entry(0x10001, 0),
        ]);
        let manifest = parse_and_validate_owner(&bytes).unwrap();

        assert!(manifest.is_owner());
        assert_eq!(manifest.vendor(), "");
        assert_eq!(manifest.model(), "");
        assert_eq!(manifest.attestation_target_fw_id(), MCU_RT_FW_ID);
        assert_eq!(manifest.header().entry_count, 4);
        assert_eq!(manifest.header().tcb_entry_count, 3);
        assert_eq!(manifest.entries().count(), 4);
    }

    #[test]
    fn marker_domain_separation_is_enforced() {
        let base_bytes = manifest("v", "m", &[]);
        let owner_bytes = owner_manifest(&[
            entry(
                OWNER_MEASUREMENT_POLICY_IDENTIFIER,
                ATTESTATION_FLAG_SOC_TCB_DPE,
            ),
            entry(O_AUTH_KEY_ID, ATTESTATION_FLAG_SOC_TCB_DPE),
        ]);

        assert_eq!(
            parse_and_validate(&owner_bytes).unwrap_err(),
            AttestationManifestError::InvalidMarker
        );
        assert_eq!(
            parse_and_validate_owner(&base_bytes).unwrap_err(),
            AttestationManifestError::InvalidMarker
        );
    }

    #[test]
    fn owner_manifest_rejects_ak_target() {
        let bytes = owner_manifest(&[
            entry(
                OWNER_MEASUREMENT_POLICY_IDENTIFIER,
                ATTESTATION_FLAG_SOC_TCB_DPE,
            ),
            entry(O_AUTH_KEY_ID, ATTESTATION_FLAG_SOC_TCB_DPE),
            entry(
                0x10000,
                ATTESTATION_FLAG_SOC_TCB_DPE | ATTESTATION_FLAG_AK_TARGET,
            ),
        ]);

        assert_eq!(
            parse_and_validate_owner(&bytes).unwrap_err(),
            AttestationManifestError::OwnerAkTargetNotAllowed
        );
    }

    #[test]
    fn owner_manifest_requires_policy_and_key_entries() {
        // Missing O_AUTH_KEY_ID
        let bytes = owner_manifest(&[
            entry(
                OWNER_MEASUREMENT_POLICY_IDENTIFIER,
                ATTESTATION_FLAG_SOC_TCB_DPE,
            ),
            entry(0x10000, ATTESTATION_FLAG_SOC_TCB_DPE),
        ]);
        assert_eq!(
            parse_and_validate_owner(&bytes).unwrap_err(),
            AttestationManifestError::MissingRequiredEntry
        );

        // Missing OWNER_MEASUREMENT_POLICY_IDENTIFIER
        let bytes2 = owner_manifest(&[
            entry(O_AUTH_KEY_ID, ATTESTATION_FLAG_SOC_TCB_DPE),
            entry(0x10000, ATTESTATION_FLAG_SOC_TCB_DPE),
        ]);
        assert_eq!(
            parse_and_validate_owner(&bytes2).unwrap_err(),
            AttestationManifestError::MissingRequiredEntry
        );
    }

    #[test]
    fn owner_manifest_rejects_id_out_of_range() {
        let bytes = owner_manifest(&[
            entry(
                OWNER_MEASUREMENT_POLICY_IDENTIFIER,
                ATTESTATION_FLAG_SOC_TCB_DPE,
            ),
            entry(O_AUTH_KEY_ID, ATTESTATION_FLAG_SOC_TCB_DPE),
            entry(0x0FFF, ATTESTATION_FLAG_SOC_TCB_DPE), // < 0x10000
        ]);

        assert_eq!(
            parse_and_validate_owner(&bytes).unwrap_err(),
            AttestationManifestError::OwnerFwIdOutOfRange
        );
    }

    #[test]
    fn owner_manifest_rejects_non_contiguous_tcb_entries() {
        let bytes = owner_manifest(&[
            entry(
                OWNER_MEASUREMENT_POLICY_IDENTIFIER,
                ATTESTATION_FLAG_SOC_TCB_DPE,
            ),
            entry(0x10001, 0), // non-TCB before TCB
            entry(O_AUTH_KEY_ID, ATTESTATION_FLAG_SOC_TCB_DPE),
        ]);

        assert_eq!(
            parse_and_validate_owner(&bytes).unwrap_err(),
            AttestationManifestError::TcbEntriesNotContiguous
        );
    }

    #[test]
    fn owner_manifest_rejects_platform_info() {
        let mut bytes = owner_manifest(&[
            entry(
                OWNER_MEASUREMENT_POLICY_IDENTIFIER,
                ATTESTATION_FLAG_SOC_TCB_DPE,
            ),
            entry(O_AUTH_KEY_ID, ATTESTATION_FLAG_SOC_TCB_DPE),
        ]);
        bytes[HEADER_VENDOR_LEN_OFFSET] = 1;

        assert_eq!(
            parse_and_validate_owner(&bytes).unwrap_err(),
            AttestationManifestError::PlatformInfoTooLong
        );
    }

    #[test]
    fn valid_owner_fw_load_list_roundtrip() {
        let bytes = owner_load_list(&[0x10000, 0x10001, 0x10002]);
        let load_list = parse_and_validate_owner_fw_load_list(&bytes).unwrap();

        assert_eq!(load_list.entry_count(), 3);
        assert!(!load_list.is_empty());
        assert!(load_list.contains(0x10000));
        assert!(load_list.contains(0x10001));
        assert!(load_list.contains(0x10002));
        assert!(!load_list.contains(0x10003));

        let entries: Vec<_> = load_list.entries().collect();
        assert_eq!(entries, [0x10000, 0x10001, 0x10002]);
    }

    #[test]
    fn owner_fw_load_list_rejects_reserved_ids_and_out_of_range() {
        let bytes = owner_load_list(&[OWNER_MEASUREMENT_POLICY_IDENTIFIER]);
        assert_eq!(
            parse_and_validate_owner_fw_load_list(&bytes).unwrap_err(),
            AttestationManifestError::OwnerFwIdOutOfRange
        );

        let bytes2 = owner_load_list(&[O_AUTH_KEY_ID]);
        assert_eq!(
            parse_and_validate_owner_fw_load_list(&bytes2).unwrap_err(),
            AttestationManifestError::OwnerFwIdOutOfRange
        );

        let bytes3 = owner_load_list(&[0x0FFF]);
        assert_eq!(
            parse_and_validate_owner_fw_load_list(&bytes3).unwrap_err(),
            AttestationManifestError::OwnerFwIdOutOfRange
        );
    }

    #[test]
    fn owner_fw_load_list_rejects_duplicates() {
        let bytes = owner_load_list(&[0x10000, 0x10000]);
        assert_eq!(
            parse_and_validate_owner_fw_load_list(&bytes).unwrap_err(),
            AttestationManifestError::DuplicateFwId
        );
    }

    #[test]
    fn valid_owner_measurement_policy_container() {
        let mut policy_bytes = owner_manifest(&[
            entry(
                OWNER_MEASUREMENT_POLICY_IDENTIFIER,
                ATTESTATION_FLAG_SOC_TCB_DPE,
            ),
            entry(O_AUTH_KEY_ID, ATTESTATION_FLAG_SOC_TCB_DPE),
            entry(0x10000, ATTESTATION_FLAG_SOC_TCB_DPE),
            entry(0x10001, 0),
        ]);
        let load_list_bytes = owner_load_list(&[0x10000, 0x10001]);
        policy_bytes.extend_from_slice(&load_list_bytes);

        let policy = parse_and_validate_owner_measurement_policy(&policy_bytes).unwrap();
        assert!(policy.manifest().is_owner());
        assert_eq!(policy.load_list().entry_count(), 2);
        assert_eq!(policy.raw_bytes().len(), policy_bytes.len());

        // Digest verification
        use sha2::{Digest, Sha384};
        let mut hasher = Sha384::new();
        hasher.update(&policy_bytes);
        let expected_digest: [u8; 48] = hasher.finalize().into();
        assert_ne!(expected_digest, [0u8; 48]);
    }

    #[test]
    fn owner_measurement_policy_rejects_mismatch() {
        // Manifest has 0x10000, load list has 0x10001
        let mut policy_bytes = owner_manifest(&[
            entry(
                OWNER_MEASUREMENT_POLICY_IDENTIFIER,
                ATTESTATION_FLAG_SOC_TCB_DPE,
            ),
            entry(O_AUTH_KEY_ID, ATTESTATION_FLAG_SOC_TCB_DPE),
            entry(0x10000, ATTESTATION_FLAG_SOC_TCB_DPE),
        ]);
        let load_list_bytes = owner_load_list(&[0x10001]);
        policy_bytes.extend_from_slice(&load_list_bytes);

        assert_eq!(
            parse_and_validate_owner_measurement_policy(&policy_bytes).unwrap_err(),
            AttestationManifestError::LoadListManifestMismatch
        );
    }
}
