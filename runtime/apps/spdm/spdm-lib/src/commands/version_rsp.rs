// Licensed under the Apache-2.0 license

use crate::codec::{Codec, CodecError, CodecResult, MessageBuf};
use crate::protocol::SpdmVersion;
use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const VERSION_RESP_COMMON_SIZE: usize = 4;
pub const VERSION_NUMBER_ENTRY_SIZE: usize = 2;

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
        buf.put_data(len)?;

        if buf.data_len() < len {
            Err(CodecError::BufferTooSmall)?;
        }

        let payload = buf.data_mut(len)?;
        let src_bytes = self.as_bytes();
        payload.copy_from_slice(src_bytes);

        buf.pull_data(len)?;

        Ok(len)
    }

    fn decode(_buf: &mut MessageBuf) -> CodecResult<Self> {
        unimplemented!()
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

impl Codec for VersionNumberEntry<[u8; 2]> {
    fn encode(&self, buf: &mut MessageBuf) -> CodecResult<usize> {
        let len = core::mem::size_of::<Self>();
        buf.put_data(len)?;

        let payload = buf.data_mut(len)?;
        self.write_to(payload).map_err(|_| CodecError::WriteError)?;

        buf.pull_data(len)?;
        Ok(len)
    }

    fn decode(_buf: &mut MessageBuf) -> CodecResult<Self> {
        unimplemented!()
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::req_resp_codes::ReqRespCode;

//     #[test]
//     fn test_version_conversion() {
//         let version = SpdmVersion::V10;
//         let ver_num: u8 = version.into();
//         assert_eq!(ver_num, 0x10);

//         let ver_num: SpdmVersion = 0x11.into();
//         assert_eq!(ver_num, SpdmVersion::V11);
//     }
// }
