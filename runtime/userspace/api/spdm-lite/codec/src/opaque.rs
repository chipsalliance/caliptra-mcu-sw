// Licensed under the Apache-2.0 license

//! Opaque data helpers for KEY_EXCHANGE (DSP0274 §10.11.3,
//! DSP0277 §6.1 Secured Message version negotiation).
//!
//! The requester sends a *supported-version-list* opaque element;
//! the responder replies with a *version-selection* opaque element.

use crate::{WireError, WireReader, WireWriter};

// ---- Constants -------------------------------------------------------------

/// DMTF standards body ID.
const OPAQUE_STANDARD_DMTF: u8 = 0x00;

/// Secured-message opaque data version.
const SM_DATA_VERSION: u8 = 1;

/// Data ID: version selection (response).
const DATA_ID_VERSION_SELECTION: u8 = 0;

/// Data ID: supported version list (request).
const DATA_ID_SUPPORTED_VERSION_LIST: u8 = 1;

/// Maximum supported version entries we'll parse.
const MAX_SM_VERSION_COUNT: usize = 4;

/// Size of the version-selection opaque blob (always 12 bytes).
///
/// Layout:
/// ```text
/// GeneralOpaqueDataHdr:  total_elements(1) + reserved(3) = 4
/// OpaqueElementHdr:      standards_body_id(1) + vendor_id_len(1) +
///                        opaque_element_data_len(2) = 4
/// SmData:                sm_data_version(1) + sm_data_id(1) +
///                        selected_version(2) = 4
/// Total = 12 (4-byte aligned, no padding needed)
/// ```
pub const OPAQUE_VERSION_SELECTION_SIZE: usize = 12;

/// SmVersion (2 bytes, LE): major[15:12] | minor[11:8] |
/// update[7:4] | alpha[3:0].
pub type SmVersion = [u8; 2];

// ---- Encoding (response) ---------------------------------------------------

/// Build the version-selection opaque data into `out`.
///
/// `selected_version` is a 2-byte SmVersion (LE bitfield).
/// Returns bytes written (always [`OPAQUE_VERSION_SELECTION_SIZE`]).
pub fn encode_version_selection(
    selected_version: SmVersion,
    out: &mut [u8],
) -> Result<usize, WireError> {
    if out.len() < OPAQUE_VERSION_SELECTION_SIZE {
        return Err(WireError);
    }
    let mut w = WireWriter::new(out);

    // GeneralOpaqueDataHdr: total_elements=1, reserved=0
    w.write_bytes(&[1u8, 0, 0, 0])?;

    // OpaqueElementHdr: standards_body_id=DMTF, vendor_id_len=0,
    // opaque_element_data_len=4 (sm_data_version + sm_data_id + version)
    w.write_bytes(&[OPAQUE_STANDARD_DMTF, 0])?;
    w.write_bytes(&4u16.to_le_bytes())?;

    // SmOpaqueElementData: sm_data_version=1, sm_data_id=0 (selection)
    w.write_bytes(&[SM_DATA_VERSION, DATA_ID_VERSION_SELECTION])?;

    // Selected version (2 bytes LE)
    w.write_bytes(&selected_version)?;

    Ok(OPAQUE_VERSION_SELECTION_SIZE)
}

// ---- Decoding (request) ----------------------------------------------------

/// Parsed supported-version-list from the requester's opaque data.
pub struct SupportedVersions {
    /// Number of valid entries in `versions`.
    pub count: u8,
    /// Version entries (only first `count` are valid).
    pub versions: [SmVersion; MAX_SM_VERSION_COUNT],
}

/// Parse the supported-version-list opaque element from a
/// KEY_EXCHANGE request.
///
/// Validates the GeneralOpaqueDataHdr, OpaqueElementHdr, and
/// SmOpaqueElementDataHdr, then extracts the version list.
pub fn parse_supported_versions(opaque: &[u8]) -> Result<SupportedVersions, WireError> {
    // Must be 4-byte aligned
    if opaque.len() & 0x3 != 0 {
        return Err(WireError);
    }

    let mut r = WireReader::new(opaque);

    // GeneralOpaqueDataHdr
    let total_elements = r.take(1)?[0];
    r.skip(3)?; // reserved
    if total_elements != 1 {
        return Err(WireError);
    }

    // OpaqueElementHdr
    let standards_body_id = r.take(1)?[0];
    let vendor_id_len = r.take(1)?[0];
    if standards_body_id != OPAQUE_STANDARD_DMTF || vendor_id_len != 0 {
        return Err(WireError);
    }
    let data_len_bytes = r.take(2)?;
    let data_len = u16::from_le_bytes([data_len_bytes[0], data_len_bytes[1]]) as usize;

    // SmOpaqueElementDataHdr
    if data_len < 4 {
        return Err(WireError);
    }
    let sm_data_version = r.take(1)?[0];
    let sm_data_id = r.take(1)?[0];
    if sm_data_version != SM_DATA_VERSION || sm_data_id != DATA_ID_SUPPORTED_VERSION_LIST {
        return Err(WireError);
    }

    // Version count
    let version_count = r.take(1)?[0];
    if version_count == 0 || version_count as usize > MAX_SM_VERSION_COUNT {
        return Err(WireError);
    }

    // Each version is 2 bytes
    let versions_len = version_count as usize * 2;
    if versions_len > data_len - 3 {
        return Err(WireError);
    }

    let mut versions = [[0u8; 2]; MAX_SM_VERSION_COUNT];
    for v in versions.iter_mut().take(version_count as usize) {
        let vb = r.take(2)?;
        v.copy_from_slice(vb);
    }

    Ok(SupportedVersions {
        count: version_count,
        versions,
    })
}

/// Select the best matching version from the requester's list.
///
/// We support SPDM secured message version 1.1 (major=1, minor=1).
/// Returns the selected version, or `WireError` if no match.
pub fn select_version(offered: &SupportedVersions) -> Result<SmVersion, WireError> {
    // Our supported version: 1.1.0.0
    // SmVersion bitfield: major[15:12]=1, minor[11:8]=1, update[7:4]=0, alpha[3:0]=0
    let our_version: SmVersion = [0x00, 0x11]; // LE: byte0=update|alpha=0x00, byte1=major|minor=0x11

    for v in &offered.versions[..offered.count as usize] {
        // Match on major.minor only (ignore update/alpha)
        if v[1] == our_version[1] {
            return Ok(*v);
        }
    }
    Err(WireError)
}
