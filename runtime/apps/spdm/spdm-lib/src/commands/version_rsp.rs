// Licensed under the Apache-2.0 license

use crate::codec::{Codec, CodecError, CodecResult, MessageBuf};
use crate::error::{CommandError, CommandResult};
use crate::protocol::SpdmVersion;
use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes};

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

impl VersionRespCommon<[u8; 4]> {
    pub fn new(entry_count: u8) -> Self {
        let mut payload = VersionRespCommon([0u8; 4]);
        payload.set_version_num_entry_count(entry_count);
        payload
    }
}

impl Codec for VersionRespCommon<[u8; 4]> {
    fn encode(&self, buf: &mut MessageBuf) -> CodecResult<usize> {
        let len = core::mem::size_of::<Self>();
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

    fn decode(buf: &mut MessageBuf) -> CodecResult<Self> {
        let len = core::mem::size_of::<Self>();
        if buf.data_len() < len {
            Err(CodecError::BufferTooSmall)?;
        }
        let payload = buf.data(len)?;
        let payload =
            VersionRespCommon::read_from_bytes(payload).map_err(|_| CodecError::ReadError)?;
        buf.pull_data(len)?;
        Ok(payload)
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
        entry.set_minor(version.minor());
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

    fn decode(buf: &mut MessageBuf) -> CodecResult<Self> {
        let len = core::mem::size_of::<Self>();
        if buf.data_len() < len {
            Err(CodecError::BufferTooSmall)?;
        }
        let payload = buf.data(len)?;
        let payload =
            VersionNumberEntry::read_from_bytes(payload).map_err(|_| CodecError::ReadError)?;
        buf.pull_data(len)?;
        Ok(payload)
    }
}

pub fn fill_version_response(
    rsp_buf: &mut MessageBuf,
    supported_versions: &[SpdmVersion],
) -> CommandResult<()> {
    let entry_count = supported_versions.len() as u8;
    // Fill the response in buffer
    let resp_common = VersionRespCommon::new(entry_count);
    let mut payload_len = resp_common
        .encode(rsp_buf)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

    for &version in supported_versions.iter() {
        let entry = VersionNumberEntry::new(version);
        payload_len += entry
            .encode(rsp_buf)
            .map_err(|_| (false, CommandError::BufferTooSmall))?;
    }

    // Push data offset up by total payload length
    rsp_buf
        .push_data(payload_len)
        .map_err(|_| (false, CommandError::BufferTooSmall))
}
