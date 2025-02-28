// Licensed under the Apache-2.0 license

use crate::codec::{Codec, CommonCodec, DataKind, MessageBuf};
use crate::commands::error_rsp::ErrorCode;
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult};
use crate::protocol::common::SpdmMsgHdr;
use crate::protocol::SpdmVersion;
use crate::state::ConnectionState;
use bitfield::bitfield;
use libtock_platform::Syscalls;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use core::fmt::Write;

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

impl CommonCodec for VersionRespCommon<[u8; 4]> {
    const DATA_KIND: DataKind = DataKind::Payload;
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

impl CommonCodec for VersionNumberEntry<[u8; 2]> {
    const DATA_KIND: DataKind = DataKind::Payload;
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

pub(crate) fn handle_version<'a, S: Syscalls>(
    ctx: &mut SpdmContext<'a, S>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    writeln!(ctx.cw, "SPDM_LIB: Received version message").unwrap();
    match spdm_hdr.version() {
        Ok(SpdmVersion::V10) => {}
        _ => {
            writeln!(ctx.cw, "SPDM_LIB: SEnding error response").unwrap();
            return Err(ctx.generate_error_response(
                req_payload,
                ErrorCode::VersionMismatch,
                0,
                None,
            ));
        }
    }

    let rsp_buf = req_payload;

    ctx.prepare_response_buffer(rsp_buf)?;
    fill_version_response(rsp_buf, ctx.supported_versions)?;

    let data_len = rsp_buf.data_len();

    writeln!(
        ctx.cw,
        "SPDM_LIB: Filled version response data len {}  data {:X?}",
        data_len,
        rsp_buf.data(data_len)
    )
    .unwrap();

    ctx.state.reset();
    ctx.state
        .connection_info
        .set_state(ConnectionState::AfterVersion);
    Ok(())
}
