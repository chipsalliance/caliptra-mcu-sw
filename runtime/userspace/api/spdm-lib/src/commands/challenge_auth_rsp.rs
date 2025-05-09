// Licensed under the Apache-2.0 license
use crate::codec::{Codec, CommonCodec, MessageBuf};
use crate::commands::algorithms_rsp::selected_measurement_specification;
use crate::commands::error_rsp::ErrorCode;
use crate::context::SpdmContext;
use crate::error::CommandResult;
use crate::protocol::*;
use crate::state::ConnectionState;
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct ChallengeReqBase {
    slot_id: u8,
    measurement_hash_type: u8,
    nonce: [u8; NONCE_LEN],
}
impl CommonCodec for ChallengeReqBase {}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct RequesterContext([u8; REQUESTER_CONTEXT_LEN]);
impl CommonCodec for RequesterContext {}

async fn process_challenge<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Validate the version
    let connection_version = ctx.state.connection_info.version_number();
    if spdm_hdr.version().ok() != Some(connection_version) {
        Err(ctx.generate_error_response(req_payload, ErrorCode::VersionMismatch, 0, None))?;
    }

    // Make sure the selected hash algorithm is SHA384
    ctx.verify_selected_hash_algo()
        .map_err(|_| ctx.generate_error_response(req_payload, ErrorCode::Unspecified, 0, None))?;

    // Decode the CHALLENGE request payload
    let challenge_req = ChallengeReqBase::decode(req_payload).map_err(|_| {
        ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
    })?;

    if connection_version >= SpdmVersion::V13 {
        // Decode the RequesterContext if present
        let requester_context = RequesterContext::decode(req_payload).map_err(|_| {
            ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
        })?;
    }

    if challenge_req.slot_id > 0 && selected_measurement_specification(ctx).0 == 0 {
        // Handle slot ID
        Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
    }

    todo!("Process CHALLENGE request");
}

async fn generate_challenge_auth_response<'a>(
    ctx: &mut SpdmContext<'a>,
    rsp: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    todo!("Generate CHALLENGE_AUTH response");
}

pub(crate) async fn handle_challenge<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Check if the connection state is valid
    if ctx.state.connection_info.state() < ConnectionState::AlgorithmsNegotiated {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    }

    // Check if challenge is supported
    if ctx.local_capabilities.flags.chal_cap() == 0 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnsupportedRequest, 0, None))?;
    }

    // Process CHALLENGE request
    process_challenge(ctx, spdm_hdr, req_payload).await?;

    // Generate CHALLENGE_AUTH response
    ctx.prepare_response_buffer(req_payload)?;
    generate_challenge_auth_response(ctx, req_payload).await?;

    Ok(())
}
