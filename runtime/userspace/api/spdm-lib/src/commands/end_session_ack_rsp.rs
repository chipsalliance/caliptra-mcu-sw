// Licensed under the Apache-2.0 license

use crate::codec::{Codec, CommonCodec, MessageBuf};
use crate::commands::error_rsp::ErrorCode;
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult};
use crate::protocol::*;
use crate::session::SessionState;
use crate::state::ConnectionState;
use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes};

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable)]
    #[repr(C)]
    struct EndSessionReqAttr(u8);
    impl Debug;
    u8;
    pub negotiated_state_cleaning_indicator, set_negotiated_state_cleaning_indicator: 0, 0;
    reserved, _: 7, 1;
}

#[derive(Debug, FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct EndSessionReq {
    req_attr: EndSessionReqAttr,
    reserved: u8,
}

impl CommonCodec for EndSessionReq {}

#[derive(Debug, FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct EndSessionAck {
    reserved1: u8,
    reserved2: u8,
}

impl CommonCodec for EndSessionAck {}

fn process_end_session(
    ctx: &mut SpdmContext<'_>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'_>,
) -> CommandResult<()> {
    // Validate the version
    let _ = ctx.validate_spdm_version(&spdm_hdr, req_payload)?;

    let _end_session_req =
        EndSessionReq::decode(req_payload).map_err(|e| (false, CommandError::Codec(e)))?;

    ctx.reset_transcript_via_req_code(ReqRespCode::EndSession);

    Ok(())
}

fn generate_end_session_response(
    ctx: &mut SpdmContext<'_>,
    rsp: &mut MessageBuf<'_>,
) -> CommandResult<()> {
    // Prepare the response message
    // Spdm Header first
    let connection_version = ctx.state.connection_info.version_number();
    let spdm_hdr = SpdmMsgHdr::new(connection_version, ReqRespCode::EndSessionAck);
    let mut payload_len = spdm_hdr
        .encode(rsp)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    let end_session_ack = EndSessionAck {
        reserved1: 0,
        reserved2: 0,
    };
    payload_len += end_session_ack
        .encode(rsp)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    rsp.push_data(payload_len)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;
    Ok(())
}

pub(crate) async fn handle_end_session<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Check if the connection state is valid
    if ctx.state.connection_info.state() < ConnectionState::AlgorithmsNegotiated {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    }

    let session_id = ctx
        .session_mgr
        .active_session_id()
        .ok_or(ctx.generate_error_response(req_payload, ErrorCode::SessionRequired, 0, None))?;

    // Process END_SESSION request
    process_end_session(ctx, spdm_hdr, req_payload)?;

    // Generate END_SESSION_ACK response
    ctx.prepare_response_buffer(req_payload)?;
    generate_end_session_response(ctx, req_payload)?;

    // Set state to terminate to invalidate the secrets and keys
    let session_info = ctx
        .session_mgr
        .session_info_mut(session_id)
        .map_err(|e| (false, CommandError::Session(e)))?;

    session_info.session_state = SessionState::Terminating;

    Ok(())
}
