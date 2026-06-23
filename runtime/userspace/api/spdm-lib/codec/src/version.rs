// Licensed under the Apache-2.0 license

//! SPDM protocol version + VERSION response wire types (DSP0274 §10.2).

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{ReqRespCode, ResponseBody, WireError, WireWriter};

// ---- SpdmVersion -----------------------------------------------------------

/// SPDM protocol version. Spec encodes it as a single byte
/// `(major << 4) | minor`.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SpdmVersion {
    V10 = 0x10,
    V11 = 0x11,
    V12 = 0x12,
    V13 = 0x13,
}

impl SpdmVersion {
    /// Highest spec version implemented by the spdm-lib stack.
    pub const MAX: Self = SpdmVersion::V13;

    /// Encode as the DSP0274 single-byte representation.
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Decode from the DSP0274 single-byte representation. Returns
    /// `None` for an unsupported / future spec version.
    pub const fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x10 => Some(SpdmVersion::V10),
            0x11 => Some(SpdmVersion::V11),
            0x12 => Some(SpdmVersion::V12),
            0x13 => Some(SpdmVersion::V13),
            _ => None,
        }
    }

    /// Wire-spec "M.N" string used as the version token inside the
    /// SPDM signing-context prefix (DSP0274 §15.6).
    pub const fn spec_str(self) -> &'static str {
        match self {
            SpdmVersion::V10 => "1.0",
            SpdmVersion::V11 => "1.1",
            SpdmVersion::V12 => "1.2",
            SpdmVersion::V13 => "1.3",
        }
    }
}

// ---- VERSION response wire types -------------------------------------------

/// 4-byte VERSION response body header (DSP0274 §10.2 Table 9).
///
/// ```text
///  byte 0   byte 1   byte 2     byte 3
/// ┌────────┬────────┬──────────┬───────┐
/// │ Param1 │ Param2 │ Reserved │ Count │
/// └────────┴────────┴──────────┴───────┘
/// ```
///
/// `Count` is the number of [`VersionNumberEntry`] entries that
/// follow. `param1` and `param2` are unused (always 0).
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct VersionRspBody {
    pub param1: u8,
    pub param2: u8,
    pub reserved: u8,
    pub entry_count: u8,
}

impl VersionRspBody {
    pub const SIZE: usize = 4;
}

/// 2-byte SPDM `VersionNumberEntry` (DSP0274 §10.2 Table 10).
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct VersionNumberEntry {
    /// `Update[7:4] | Alpha[3:0]` — both zero in this stack.
    pub update_alpha: u8,
    /// `Major[7:4] | Minor[3:0]`.
    pub major_minor: u8,
}

impl VersionNumberEntry {
    pub const SIZE: usize = 2;

    /// Construct an entry from an [`SpdmVersion`] (major/minor only,
    /// update/alpha = 0).
    pub const fn from_version(v: SpdmVersion) -> Self {
        Self {
            update_alpha: 0,
            major_minor: v.to_u8(),
        }
    }
}

const _: () = assert!(core::mem::size_of::<VersionRspBody>() == VersionRspBody::SIZE);
const _: () = assert!(core::mem::size_of::<VersionNumberEntry>() == VersionNumberEntry::SIZE);

/// Builder for a VERSION response.
///
/// Per DSP0274 §10.2 the VERSION response's `SPDMVersion` field is
/// always `V1.0` (version negotiation happens later, in
/// `GET_CAPABILITIES`). The caller of
/// [`encode_with_header`](crate::ResponseBody::encode_with_header)
/// must pass `SpdmVersion::V10`.
pub struct VersionRsp<'a> {
    pub versions: &'a [SpdmVersion],
}

impl ResponseBody for VersionRsp<'_> {
    const RESPONSE_CODE: ReqRespCode = ReqRespCode::VERSION;

    fn body_size(&self) -> usize {
        VersionRspBody::SIZE + self.versions.len() * VersionNumberEntry::SIZE
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write(&VersionRspBody {
            param1: 0,
            param2: 0,
            reserved: 0,
            entry_count: self.versions.len() as u8,
        })?;
        for &v in self.versions {
            w.write(&VersionNumberEntry::from_version(v))?;
        }
        Ok(())
    }
}
