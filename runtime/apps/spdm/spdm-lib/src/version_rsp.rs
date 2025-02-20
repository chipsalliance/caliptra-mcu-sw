// Licensed under the Apache-2.0 license

use crate::context::SpdmContext;
use crate::error_rsp::{CommandError, ErrorCode};
use crate::message_buf::{Codec, CodecError, CodecResult, MessageBuf};
use crate::protocol::SpdmMsgHdr;
use crate::req_resp_codes::CommandResult;
use crate::req_resp_codes::ReqRespCode;
use bitfield::bitfield;
use libtock_platform::Syscalls;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const VERSION_RESP_COMMON_SIZE: usize = 4;
pub const VERSION_NUMBER_ENTRY_SIZE: usize = 2;

#[derive(Debug, PartialEq, Clone, Copy, PartialOrd)]
pub enum SpdmVersion {
    V10,
    V11,
    V12,
    V13,
}

impl Default for SpdmVersion {
    fn default() -> Self {
        SpdmVersion::V10
    }
}

impl From<u8> for SpdmVersion {
    fn from(value: u8) -> Self {
        match value {
            0x10 => SpdmVersion::V10,
            0x11 => SpdmVersion::V11,
            0x12 => SpdmVersion::V12,
            0x13 => SpdmVersion::V13,
            _ => SpdmVersion::default(),
        }
    }
}

impl From<SpdmVersion> for u8 {
    fn from(version: SpdmVersion) -> Self {
        version.to_u8()
    }
}

impl SpdmVersion {
    fn to_u8(&self) -> u8 {
        match self {
            SpdmVersion::V10 => 0x10,
            SpdmVersion::V11 => 0x11,
            SpdmVersion::V12 => 0x12,
            SpdmVersion::V13 => 0x13,
        }
    }

    pub fn major(&self) -> u8 {
        self.to_u8() >> 4
    }

    pub fn minor(&self) -> u8 {
        self.to_u8() & 0x0F
    }
}

bitfield! {
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable)]
pub struct VersionRespCommon(MSB0 [u8]);
impl Debug;
u8;
    param1, _: 7, 0;
    param2, _: 15, 8;
    reserved, _: 23, 16;
    pub version_num_entry_count, set_version_num_entry_count: 31, 24;
}

impl Default for VersionRespCommon<[u8; 4]> {
    fn default() -> Self {
        VersionRespCommon::new(0)
    }
}

impl VersionRespCommon<[u8; VERSION_RESP_COMMON_SIZE]> {
    pub fn new(entry_count: u8) -> Self {
        let mut payload = VersionRespCommon([0u8; VERSION_RESP_COMMON_SIZE]);
        payload.set_version_num_entry_count(entry_count);
        payload
    }
}

impl Codec for VersionRespCommon<[u8; VERSION_RESP_COMMON_SIZE]> {
    fn encode(&self, buf: &mut MessageBuf) -> CodecResult<usize> {
        let len: usize = core::mem::size_of::<Self>();
        if buf.data_len() < len {
            Err(CodecError::BufferTooSmall)?;
        }

        let rsp = buf.data_mut(len)?;
        let src_bytes = self.as_bytes();
        rsp.copy_from_slice(src_bytes);

        buf.pull_data(len)?;

        Ok(len)
    }

    fn decode(buf: &mut MessageBuf) -> CodecResult<Self> {
        let len = core::mem::size_of::<Self>();
        if buf.len() < len {
            Err(CodecError::BufferTooSmall)?;
        }
        let hdr_bytes = buf.data(len)?;

        let hdr =
            VersionRespCommon::read_from_bytes(hdr_bytes).map_err(|_| CodecError::ReadError)?;
        buf.pull_data(len)?;
        Ok(hdr)
    }
}

bitfield! {
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable)]
pub struct VersionNumberEntry(MSB0 [u8]);
impl Debug;
u8;
    pub update_ver, set_update_ver: 3, 0;
    pub alpha, set_alpha: 7, 4;
    pub major, set_major: 11, 8;
    pub minor, set_minor: 15, 12;
}

impl Default for VersionNumberEntry<[u8; 2]> {
    fn default() -> Self {
        VersionNumberEntry::new(SpdmVersion::default())
    }
}

impl VersionNumberEntry<[u8; 2]> {
    pub fn new(version: SpdmVersion) -> Self {
        let mut entry = VersionNumberEntry([0u8; 2]);
        entry.set_major(version.major());
        assert!(entry.minor() != 1);
        entry.set_minor(version.minor());
        // assert!(entry.minor() != version.minor());
        entry
    }
}

// impl Codec for VersionNumberEntry<[u8; 2]> {
//     fn encode(&self, buf: &mut MessageBuf) -> CodecResult<usize> {
//         let len = core::mem::size_of::<Self>();
//         if buf.remaining() < len {
//             Err(CodecError::BufferTooSmall)?;
//         }

//         if buf.len() < len {
//             Err(CodecError::BufferTooSmall)?;
//         }
//         let mut buf_hdr: VersionNumberEntry<[u8; 2]> =
//             VersionNumberEntry::read_from_bytes(buf).map_err(|_| CodecError::ReadError)?;
//         buf_hdr.set_major(self.major());
//         buf_hdr.set_minor(self.minor());

//         buf.push_offset(len)?;
//         Ok(len)
//     }

//     fn decode(buf: &mut MessageBuf) -> CodecResult<Self> {
//         if buf.len() < core::mem::size_of::<Self>() {
//             Err(CodecError::BufferTooSmall)?;
//         }
//         let buf_hdr =
//             VersionNumberEntry::read_from_bytes(buf).map_err(|_| CodecError::ReadError)?;

//         buf.push_offset(core::mem::size_of::<Self>())?;

//         Ok(buf_hdr)
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::req_resp_codes::ReqRespCode;

    #[test]
    fn test_version_conversion() {
        let version = SpdmVersion::V10;
        let ver_num: u8 = version.into();
        assert_eq!(ver_num, 0x10);

        let ver_num: SpdmVersion = 0x11.into();
        assert_eq!(ver_num, SpdmVersion::V11);
    }
}
