// Licensed under the Apache-2.0 license

use crate::codec::{Codec, CommonCodec, MessageBuf};
use crate::commands::error_rsp::ErrorCode;
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult};
use crate::protocol::{ReqRespCode, SpdmMsgHdr, SpdmVersion};
use crate::state::ConnectionState;
use crate::transcript::TranscriptContext;
use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes};

const VERSION_ENTRY_SIZE: usize = 2;

#[allow(dead_code)]
#[derive(FromBytes, IntoBytes, Immutable)]
struct VersionReqPayload {
    param1: u8,
    param2: u8,
}

#[allow(dead_code)]
#[derive(FromBytes, IntoBytes, Immutable)]
struct VersionRespCommon {
    param1: u8,
    param2: u8,
    reserved: u8,
    version_num_entry_count: u8,
}

impl CommonCodec for VersionReqPayload {}

impl Default for VersionRespCommon {
    fn default() -> Self {
        VersionRespCommon::new(0)
    }
}

impl VersionRespCommon {
    pub fn new(entry_count: u8) -> Self {
        VersionRespCommon {
            param1: 0,
            param2: 0,
            reserved: 0,
            version_num_entry_count: entry_count,
        }
    }
}

impl CommonCodec for VersionRespCommon {}

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

impl Default for VersionNumberEntry<[u8; VERSION_ENTRY_SIZE]> {
    fn default() -> Self {
        VersionNumberEntry::new(SpdmVersion::default())
    }
}

impl VersionNumberEntry<[u8; VERSION_ENTRY_SIZE]> {
    pub fn new(version: SpdmVersion) -> Self {
        let mut entry = VersionNumberEntry([0u8; VERSION_ENTRY_SIZE]);
        entry.set_major(version.major());
        entry.set_minor(version.minor());
        entry
    }
}

impl CommonCodec for VersionNumberEntry<[u8; VERSION_ENTRY_SIZE]> {}

async fn generate_version_response<'a>(
    ctx: &mut SpdmContext<'a>,
    rsp_buf: &mut MessageBuf<'a>,
    supported_versions: &[SpdmVersion],
) -> CommandResult<()> {
    let entry_count = supported_versions.len() as u8;
    // Fill SpdmHeader first
    let spdm_resp_hdr = SpdmMsgHdr::new(SpdmVersion::V10, ReqRespCode::Version);
    let mut payload_len = spdm_resp_hdr
        .encode(rsp_buf)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

    // Fill VersionRespCommon
    let resp_common = VersionRespCommon::new(entry_count);
    payload_len += resp_common
        .encode(rsp_buf)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

    for &version in supported_versions.iter() {
        let entry = VersionNumberEntry::new(version);
        payload_len += entry
            .encode(rsp_buf)
            .map_err(|_| (false, CommandError::BufferTooSmall))?;
    }

    // Append response to VCA transcript
    ctx.append_message_to_transcript(rsp_buf, TranscriptContext::Vca, None)
        .await?;

    // Push data offset up by total payload length
    rsp_buf
        .push_data(payload_len)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;
    Ok(())
}

async fn process_get_version<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    match spdm_hdr.version() {
        Ok(SpdmVersion::V10) => {}
        _ => {
            Err(ctx.generate_error_response(req_payload, ErrorCode::VersionMismatch, 0, None))?;
        }
    }

    VersionReqPayload::decode(req_payload).map_err(|e| (false, CommandError::Codec(e)))?;

    // Reset Transcript
    ctx.shared_transcript.reset();

    // Append request to VCA transcript
    ctx.append_message_to_transcript(req_payload, TranscriptContext::Vca, None)
        .await
}

pub(crate) async fn handle_get_version<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Process GET_VERSION request
    process_get_version(ctx, spdm_hdr, req_payload).await?;

    // Generate VERSION response
    ctx.prepare_response_buffer(req_payload)?;
    generate_version_response(ctx, req_payload, ctx.supported_versions).await?;

    // Invalidate state and reset session info
    ctx.reset();

    // Set connection state to after version
    ctx.state
        .connection_info
        .set_state(ConnectionState::AfterVersion);
    Ok(())
}
