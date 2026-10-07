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

/// Reader to read general opaque data elements.
struct OpaqueDataReader<'a> {
    /// Total number of elements declared in the header.
    total_elements: u8,
    /// Counter to track parsed elements.
    parsed_elements: u8,
    opaque_list: WireReader<'a>,
}

impl<'a> OpaqueDataReader<'a> {
    /// Create a new reader from opaque data
    ///
    /// `opaque_data` has to be in the _general opaque data_ format.
    fn new(opaque_data: &'a [u8]) -> Result<OpaqueDataReader<'a>, WireError> {
        // Reject wrong alignment
        if opaque_data.len() & 0x3 != 0 {
            return Err(WireError);
        }

        let mut r = WireReader::new(opaque_data);

        // GeneralOpaqueDataHdr
        let total_elements = r.take(1)?[0];
        let reserved = r.take(3)?;
        if reserved.iter().any(|&byte| byte != 0) {
            return Err(WireError);
        }
        Ok(OpaqueDataReader {
            total_elements,
            parsed_elements: 0,
            opaque_list: r,
        })
    }
    /// Parse the next [OpaqueElement] from the list
    ///
    /// ## Returns
    /// - `Ok(Some(element))`: parsing is successful
    /// - `Ok(None)`: no element is left
    /// - `Err(WireError)`: invalid data
    fn next(&mut self) -> Result<Option<OpaqueElement<'a>>, WireError> {
        if self.parsed_elements >= self.total_elements {
            return Ok(None);
        }

        let id = self.opaque_list.take(1)?[0];
        let vendor_id_len = self.opaque_list.take(1)?[0];
        let vendor_id = self.opaque_list.take(vendor_id_len as usize)?;
        let data_len_bytes = self.opaque_list.take(2)?;
        let data_len = u16::from_le_bytes([data_len_bytes[0], data_len_bytes[1]]) as usize;
        let opaque_element_data = self.opaque_list.take(data_len)?;
        // Padding for 4 byte alignment (4 byte fixed fields + variable data + padding).
        let padding_len = (4 - ((vendor_id_len as usize + data_len) & 3)) & 3;
        let padding = self.opaque_list.take(padding_len)?;

        // Padding shall be all zeros according to spec.
        if padding.iter().any(|&byte| byte != 0) {
            return Err(WireError);
        }

        self.parsed_elements += 1;
        Ok(Some(OpaqueElement {
            id,
            vendor_id,
            opaque_element_data,
        }))
    }
}

struct OpaqueElement<'a> {
    id: u8,
    vendor_id: &'a [u8],
    opaque_element_data: &'a [u8],
}

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
/// Iterates over the opaque element list and extracts the
/// supported versions list.
pub fn parse_supported_versions(opaque: &[u8]) -> Result<SupportedVersions, WireError> {
    let mut opaque_elements = OpaqueDataReader::new(opaque)?;
    let mut supported_versions = Err(WireError);
    while let Some(element) = opaque_elements.next()? {
        // Only process DMTF standards body elements
        if element.id != OPAQUE_STANDARD_DMTF {
            continue;
        }
        // DSP0277 Table 7 requires DMTF Secured Message elements to
        // have VendorLen = 0 and contain SMDataVersion + SMDataID.
        if !element.vendor_id.is_empty() || element.opaque_element_data.len() < 2 {
            return Err(WireError);
        }

        let mut r = WireReader::new(element.opaque_element_data);

        // SmOpaqueElementDataHdr
        let sm_data_version = r.take(1)?[0];
        let sm_data_id = r.take(1)?[0];
        if sm_data_version != SM_DATA_VERSION || sm_data_id != DATA_ID_SUPPORTED_VERSION_LIST {
            continue;
        }

        // Version count
        let version_count = r.take(1)?[0];
        if version_count == 0 || version_count as usize > MAX_SM_VERSION_COUNT {
            return Err(WireError);
        }

        let mut versions = [[0u8; 2]; MAX_SM_VERSION_COUNT];
        for v in versions.iter_mut().take(version_count as usize) {
            let vb = r.take(2)?;
            v.copy_from_slice(vb);
        }

        if !r.is_empty() {
            return Err(WireError);
        }

        // Check that only one versions list in the opaque elements exists
        if supported_versions.is_ok() {
            return Err(WireError);
        }

        supported_versions = Ok(SupportedVersions {
            count: version_count,
            versions,
        });
    }

    // Check for trailing garbage in opaque list
    if !opaque_elements.opaque_list.is_empty() {
        return Err(WireError);
    }

    supported_versions
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
    // Opaque data with two elements
    const OPAQUE_DATA: &[u8] = &[
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x01, 0x01, 0x04, 0x00, 0x10, 0x00, 0x11,
        0x00, 0x12, 0x00, 0x13, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x02, 0x40, 0x00,
    ];

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

    #[test]
    fn test_opaque_data_reader() {
        let mut reader = OpaqueDataReader::new(OPAQUE_DATA).unwrap();

        assert_eq!(reader.total_elements, 2, "total_elements should be 2");
        assert_eq!(reader.parsed_elements, 0);

        let element1 = reader.next().unwrap().expect("expected first element");
        let _ = reader.next().unwrap().expect("expected second element");
        assert!(reader.next().unwrap().is_none());
        assert!(reader.opaque_list.is_empty());

        assert_eq!(element1.id, OPAQUE_STANDARD_DMTF);
        assert_eq!(element1.opaque_element_data.len(), 0x0b);
    }

    // Single element with a 2-byte vendor ID and 1 data byte, which requires
    // one byte of padding (4 + 2 + 1 = 7).
    const VENDOR_ELEMENT: [u8; 12] = [
        1, 0, 0, 0, // General header, one element.
        0x01, 0x02, // Non-DMTF standards body, vendor ID length 2.
        0xAA, 0xBB, // Vendor ID.
        0x01, 0x00, // One data byte.
        0x42, // Data.
        0x00, // Alignment padding.
    ];

    #[test]
    fn opaque_reader_parses_vendor_id_and_padding() {
        let mut reader = OpaqueDataReader::new(&VENDOR_ELEMENT).unwrap();

        let element = reader.next().unwrap().expect("expected element");
        assert_eq!(element.id, 0x01);
        assert_eq!(element.vendor_id, &[0xAA, 0xBB]);
        assert_eq!(element.opaque_element_data, &[0x42]);
        assert!(reader.next().unwrap().is_none());
        assert!(reader.opaque_list.is_empty());
    }

    #[test]
    fn opaque_reader_rejects_empty_input() {
        assert!(OpaqueDataReader::new(&[]).is_err());
    }

    #[test]
    fn opaque_reader_rejects_misaligned_input() {
        for len in [1, 2, 3, 5, 6, 7] {
            let data = [0u8; 8];
            assert!(
                OpaqueDataReader::new(&data[..len]).is_err(),
                "length {len} should be rejected"
            );
        }
        // Valid data with one trailing byte must also be rejected.
        let mut data = [0u8; 13];
        data[..12].copy_from_slice(&VENDOR_ELEMENT);
        assert!(OpaqueDataReader::new(&data).is_err());
    }

    #[test]
    fn opaque_reader_rejects_nonzero_reserved_bytes() {
        for idx in 1..4 {
            let mut data = VENDOR_ELEMENT;
            data[idx] = 0x80;
            assert!(
                OpaqueDataReader::new(&data).is_err(),
                "reserved byte {idx} set should be rejected"
            );
        }
    }

    #[test]
    fn opaque_reader_zero_elements_yields_none() {
        let mut reader = OpaqueDataReader::new(&[0, 0, 0, 0]).unwrap();
        assert!(reader.next().unwrap().is_none());
        // Repeated calls stay at `None`.
        assert!(reader.next().unwrap().is_none());
    }

    #[test]
    fn opaque_reader_rejects_missing_element() {
        // Header declares one element but no element data follows.
        let mut reader = OpaqueDataReader::new(&[1, 0, 0, 0]).unwrap();
        assert!(reader.next().is_err());
    }

    #[test]
    fn opaque_reader_rejects_more_declared_elements_than_present() {
        let mut data = [0u8; OPAQUE_DATA.len()];
        data.copy_from_slice(OPAQUE_DATA);
        data[0] = 3;

        let mut reader = OpaqueDataReader::new(&data).unwrap();
        assert!(reader.next().unwrap().is_some());
        assert!(reader.next().unwrap().is_some());
        assert!(reader.next().is_err());
    }

    #[test]
    fn opaque_reader_rejects_max_declared_elements() {
        let mut data = VENDOR_ELEMENT;
        data[0] = u8::MAX;

        let mut reader = OpaqueDataReader::new(&data).unwrap();
        assert!(reader.next().unwrap().is_some());
        assert!(reader.next().is_err());
    }

    #[test]
    fn opaque_reader_rejects_vendor_id_len_exceeding_data() {
        // Vendor ID length 4, but only the 2-byte data length field follows.
        let data = [1, 0, 0, 0, 0x01, 0x04, 0x00, 0x00];
        let mut reader = OpaqueDataReader::new(&data).unwrap();
        assert!(reader.next().is_err());

        let mut data = VENDOR_ELEMENT;
        data[5] = u8::MAX;
        let mut reader = OpaqueDataReader::new(&data).unwrap();
        assert!(reader.next().is_err());
    }

    #[test]
    fn opaque_reader_rejects_data_len_exceeding_data() {
        // Data length 1, but no data byte follows.
        let data = [1, 0, 0, 0, 0x00, 0x00, 0x01, 0x00];
        let mut reader = OpaqueDataReader::new(&data).unwrap();
        assert!(reader.next().is_err());

        // Maximum data length.
        let data = [1, 0, 0, 0, 0x00, 0x00, 0xFF, 0xFF];
        let mut reader = OpaqueDataReader::new(&data).unwrap();
        assert!(reader.next().is_err());
    }

    #[test]
    fn opaque_reader_rejects_nonzero_padding_with_vendor_id() {
        let mut data = VENDOR_ELEMENT;
        data[11] = 0x01;

        let mut reader = OpaqueDataReader::new(&data).unwrap();
        assert!(reader.next().is_err());
    }

    #[test]
    fn opaque_reader_rejects_missing_padding_between_elements() {
        // Two 6-byte elements without their 2-byte padding. The total length
        // is still 4-byte aligned, but the reader consumes the start of the
        // second element as padding of the first, which is non-zero.
        let data = [
            2, 0, 0, 0, // General header, two elements.
            0x00, 0x00, 0x02, 0x00, 0x11, 0x22, // Element 1, padding missing.
            0x01, 0x00, 0x02, 0x00, 0x33, 0x44, // Element 2, padding missing.
        ];
        let mut reader = OpaqueDataReader::new(&data).unwrap();
        assert!(reader.next().is_err());
    }

    #[test]
    fn opaque_reader_rejects_truncated_second_element() {
        let mut data = [0u8; OPAQUE_DATA.len()];
        data.copy_from_slice(OPAQUE_DATA);
        // Second element declares 5 data bytes, only 4 remain.
        data[22] = 5;

        let mut reader = OpaqueDataReader::new(&data).unwrap();
        assert!(reader.next().unwrap().is_some());
        assert!(reader.next().is_err());
    }

    #[test]
    fn opaque_reader_rejects_nonzero_padding_in_second_element() {
        let mut data = [0u8; OPAQUE_DATA.len()];
        data.copy_from_slice(OPAQUE_DATA);
        data[27] = 0x01;

        let mut reader = OpaqueDataReader::new(&data).unwrap();
        assert!(reader.next().unwrap().is_some());
        assert!(reader.next().is_err());
    }

    #[test]
    fn parse_rejects_list_without_dmtf_element() {
        assert!(parse_supported_versions(&VENDOR_ELEMENT).is_err());
        assert!(parse_supported_versions(&[0, 0, 0, 0]).is_err());
    }

    // Supported-version-list preceded by elements that must be skipped.
    const VERSION_LIST_NOT_FIRST: [u8; 44] = [
        4, 0, 0, 0, // General header, four elements.
        // Element 1: non-DMTF standards body with vendor ID.
        0x01, 0x02, 0xAA, 0xBB, // Standards body 1, vendor ID length 2.
        0x01, 0x00, 0x42, // One data byte.
        0x00, // Alignment padding.
        // Element 2: DMTF version selection (wrong data ID).
        0, 0, 4, 0, // DMTF element, four data bytes.
        1, 0, 0, 0x11, // Version-selection header, version 1.1.
        // Element 3: DMTF supported-version-list with unknown data version.
        0, 0, 5, 0, // DMTF element, five data bytes.
        2, 1, 1, // sm_data_version 2, supported-version-list, one version.
        0, 0x12, // Secured-message version 1.2.
        0, 0, 0, // Alignment padding.
        // Element 4: the supported-version-list.
        0, 0, 7, 0, // DMTF element, seven data bytes.
        1, 1, 2, // Supported-version-list header, two versions.
        0, 0x10, 0, 0x11, // Secured-message versions 1.0 and 1.1.
        0,    // Alignment padding.
    ];

    #[test]
    fn parses_version_list_that_is_not_first_element() {
        let versions = parse_supported_versions(&VERSION_LIST_NOT_FIRST).unwrap();

        assert_eq!(versions.count, 2);
        assert_eq!(versions.versions[0], [0x00, 0x10]);
        assert_eq!(versions.versions[1], [0x00, 0x11]);
    }

    #[test]
    fn rejects_list_with_only_skipped_elements() {
        // Same data without the trailing supported-version-list element.
        let mut opaque = [0u8; 32];
        opaque.copy_from_slice(&VERSION_LIST_NOT_FIRST[..32]);
        opaque[0] = 3;

        assert!(parse_supported_versions(&opaque).is_err());
    }

    #[test]
    fn rejects_duplicate_version_list() {
        // VERSION_LIST's element appears twice. Each copy is valid by itself.
        let element = &VERSION_LIST[4..];
        let mut opaque = [0u8; 4 + 2 * 12];
        opaque[0] = 2; // General header, two elements.
        opaque[4..16].copy_from_slice(element);
        opaque[16..].copy_from_slice(element);

        assert!(parse_supported_versions(&VERSION_LIST).is_ok());
        assert!(parse_supported_versions(&opaque).is_err());
    }

    #[test]
    fn parses_version_list_from_multiple_opaque_data_elements() {
        let versions = parse_supported_versions(OPAQUE_DATA).unwrap();
        assert_eq!(versions.count, 4);
        assert_eq!(versions.versions[0], [0x00, 0x10]);
        assert_eq!(versions.versions[1], [0x00, 0x11]);
        assert_eq!(versions.versions[2], [0x00, 0x12]);
        assert_eq!(versions.versions[3], [0x00, 0x13]);
    }
}
