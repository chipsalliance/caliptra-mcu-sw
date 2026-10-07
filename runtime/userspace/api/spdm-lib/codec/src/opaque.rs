// Licensed under the Apache-2.0 license

//! Opaque data helpers for secured-message version negotiation.
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

const GENERAL_HEADER_SIZE: usize = 4;
const ELEMENT_HEADER_SIZE: usize = 4;
const SUPPORTED_VERSION_FIXED_SIZE: usize = 3;

/// Maximum encoded supported-version-list accepted by this responder.
pub const MAX_SUPPORTED_VERSION_LIST_OPAQUE_SIZE: usize = GENERAL_HEADER_SIZE
    + ((ELEMENT_HEADER_SIZE + SUPPORTED_VERSION_FIXED_SIZE + 2 * MAX_SM_VERSION_COUNT + 3) & !3);

/// Size of the version-selection opaque blob (always 12 bytes).
///
/// Layout:
/// ```text
/// GeneralOpaqueDataHdr: total_elements(1) + reserved(3) = 4
/// OpaqueElementHdr:   standards_body_id(1) + vendor_id_len(1) +
///            opaque_element_data_len(2) = 4
/// SmData:        sm_data_version(1) + sm_data_id(1) +
///            selected_version(2) = 4
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
    if opaque.len() > MAX_SUPPORTED_VERSION_LIST_OPAQUE_SIZE || opaque.len() & 0x3 != 0 {
        return Err(WireError);
    }

    let mut r = WireReader::new(opaque);

    // GeneralOpaqueDataHdr
    let total_elements = r.take(1)?[0];
    let reserved = r.take(3)?;
    if total_elements != 1 || reserved.iter().any(|&byte| byte != 0) {
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
    if data_len != SUPPORTED_VERSION_FIXED_SIZE + versions_len {
        return Err(WireError);
    }

    let mut versions = [[0u8; 2]; MAX_SM_VERSION_COUNT];
    for v in versions.iter_mut().take(version_count as usize) {
        let vb = r.take(2)?;
        v.copy_from_slice(vb);
    }

    let element_len = ELEMENT_HEADER_SIZE + data_len;
    let padding_len = (4 - (element_len & 3)) & 3;
    let padding = r.take(padding_len)?;
    if padding.iter().any(|&byte| byte != 0) || !r.is_empty() {
        return Err(WireError);
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

#[cfg(test)]
mod tests {
    use super::*;

    const VERSION_LIST: [u8; 16] = [
        1, 0, 0, 0, // General header.
        0, 0, 5, 0, // DMTF element, five data bytes.
        1, 1, 1, // Supported-version-list header, one version.
        0, 0x11, // Secured-message version 1.1.
        0, 0, 0, // Alignment padding.
    ];

    #[test]
    fn parses_exact_supported_version_list() {
        let parsed = parse_supported_versions(&VERSION_LIST).unwrap();

        assert_eq!(parsed.count, 1);
        assert_eq!(parsed.versions[0], [0, 0x11]);
    }

    #[test]
    fn rejects_mismatched_element_length() {
        let mut opaque = VERSION_LIST;
        opaque[6] = 6;

        assert!(parse_supported_versions(&opaque).is_err());
    }

    #[test]
    fn rejects_nonzero_general_header_reserved() {
        let mut opaque = VERSION_LIST;
        opaque[1] = 1;

        assert!(parse_supported_versions(&opaque).is_err());
    }

    #[test]
    fn rejects_nonzero_padding() {
        let mut opaque = VERSION_LIST;
        opaque[15] = 1;

        assert!(parse_supported_versions(&opaque).is_err());
    }

    #[test]
    fn rejects_missing_padding() {
        assert!(parse_supported_versions(&VERSION_LIST[..13]).is_err());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut opaque = [0u8; 20];
        opaque[..VERSION_LIST.len()].copy_from_slice(&VERSION_LIST);

        assert!(parse_supported_versions(&opaque).is_err());
    }

    #[test]
    fn rejects_version_count_length_mismatch() {
        let mut opaque = VERSION_LIST;
        opaque[10] = 2;

        assert!(parse_supported_versions(&opaque).is_err());
    }

    #[test]
    fn maximum_supported_version_list_matches_bound() {
        let opaque = [
            1, 0, 0, 0, // General header.
            0, 0, 11, 0, // DMTF element, eleven data bytes.
            1, 1, 4, // Supported-version-list header, four versions.
            0, 0x10, 0, 0x11, 0, 0x12, 0, 0x13, // Versions.
            0,    // Alignment padding.
        ];

        assert_eq!(opaque.len(), MAX_SUPPORTED_VERSION_LIST_OPAQUE_SIZE);
        assert_eq!(parse_supported_versions(&opaque).unwrap().count, 4);
    }
}
