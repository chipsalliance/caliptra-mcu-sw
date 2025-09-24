// Licensed under the Apache-2.0 license

#![allow(dead_code)]

use crate::codec::{decode_u8_slice, encode_u8_slice, Codec, CommonCodec, MessageBuf};
use crate::commands::error_rsp::ErrorCode;
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult};
use crate::protocol::*;
use crate::session::{SessionKeyType, SessionState};
use crate::state::ConnectionState;
use crate::transcript::TranscriptContext;
use bitfield::bitfield;
use constant_time_eq::constant_time_eq;
use libapi_caliptra::crypto::hash::SHA384_HASH_SIZE;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const RANDOM_DATA_LEN: usize = 32;

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable)]
    #[repr(C)]
    struct MutualAuthReqAttr(u8);
    impl Debug;
    u8;
    pub no_encaps_request_flow, set_no_encaps_request_flow: 0, 0;
    pub encaps_request_flow, set_encaps_request_flow: 1, 1;
    pub implicit_get_digests, set_implicit_get_digests: 2, 2;

    reserved, _: 7, 3;
}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct FinishReqBase {
    req_signature_present: u8,
    req_slot_id: u8,
}
impl CommonCodec for FinishReqBase {}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct FinishRspBase {
    _reserved0: u8,
    _reserved1: u8,
}
impl CommonCodec for FinishRspBase {}

impl FinishRspBase {
    fn new() -> Self {
        Self {
            _reserved0: 0,
            _reserved1: 0,
        }
    }
}

async fn verify_requester_verify_data(
    ctx: &mut SpdmContext<'_>,
    session_id: u32,
    requester_verify_data: &[u8; SHA384_HASH_SIZE],
    req_payload: &mut MessageBuf<'_>,
) -> CommandResult<()> {
    // Compute transcript hash for generating the HMAC
    let hmac_transcript_hash = ctx
        .transcript_hash(TranscriptContext::Th, Some(session_id), false)
        .await?;

    let session_info = ctx
        .session_mgr
        .session_info_mut(session_id)
        .map_err(|e| (false, CommandError::Session(e)))?;

    let computed_hmac = session_info
        .compute_hmac(SessionKeyType::RequestFinishedKey, &hmac_transcript_hash)
        .await
        .map_err(|e| (false, CommandError::Session(e)))?;

    if !constant_time_eq(&computed_hmac, requester_verify_data) {
        Err(ctx.generate_error_response(req_payload, ErrorCode::DecryptError, 0, None))?
    }

    Ok(())
}

async fn process_finish<'a>(
    ctx: &mut SpdmContext<'a>,
    session_id: u32,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Validate the version
    let connection_version = ctx.state.connection_info.version_number();
    if spdm_hdr.version().ok() != Some(connection_version) {
        Err(ctx.generate_error_response(req_payload, ErrorCode::VersionMismatch, 0, None))?;
    }

    // Decode the FINISH request payload (currently no Session-based mutual authentication is supported)
    let _finish_req_base =
        FinishReqBase::decode(req_payload).map_err(|e| (false, CommandError::Codec(e)))?;

    ctx.reset_transcript_via_req_code(ReqRespCode::Finish);

    // Append FINISH req (excluding RequesterVerifyData) to TH transcript.
    ctx.append_message_to_transcript(req_payload, TranscriptContext::Th, Some(session_id))
        .await?;

    // Verify HMAC of the RequesterVerifyData
    let mut requester_verify_data = [0u8; SHA384_HASH_SIZE];
    decode_u8_slice(req_payload, &mut requester_verify_data)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    // Verify the RequesterVerifyData
    verify_requester_verify_data(ctx, session_id, &requester_verify_data, req_payload).await?;

    // Add the RequesterVerifyData to the transcript
    ctx.append_slice_to_transcript(
        &requester_verify_data,
        TranscriptContext::Th,
        Some(session_id),
    )
    .await
}

async fn encode_responder_verify_data(
    ctx: &mut SpdmContext<'_>,
    session_id: u32,
    rsp: &mut MessageBuf<'_>,
) -> CommandResult<usize> {
    let hmac_transcript_hash = ctx
        .transcript_hash(TranscriptContext::Th, Some(session_id), false)
        .await?;

    let session_info = ctx
        .session_mgr
        .session_info_mut(session_id)
        .map_err(|e| (false, CommandError::Session(e)))?;

    let responder_verify_data = session_info
        .compute_hmac(SessionKeyType::ResponseFinishedKey, &hmac_transcript_hash)
        .await
        .map_err(|e| (false, CommandError::Session(e)))?;

    let len = encode_u8_slice(&responder_verify_data, rsp)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    // Append ResponderVerifyData to the transcript
    ctx.append_slice_to_transcript(
        &responder_verify_data,
        TranscriptContext::Th,
        Some(session_id),
    )
    .await?;

    Ok(len)
}

async fn generate_finish_response<'a>(
    ctx: &mut SpdmContext<'a>,
    session_id: u32,
    rsp: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Prepare the response buffer
    // Spdm Header first
    let connection_version = ctx.state.connection_info.version_number();
    let spdm_hdr = SpdmMsgHdr::new(connection_version, ReqRespCode::FinishRsp);
    let mut payload_len = spdm_hdr
        .encode(rsp)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    // Encode the FINISH response fixed fields
    payload_len += FinishRspBase::new()
        .encode(rsp)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    ctx.append_message_to_transcript(rsp, TranscriptContext::Th, Some(session_id))
        .await?;

    // Only generate and encode ResponderVerifyData if the session is in the clear
    // This will also add the ResponderVerifyData to the transcript
    if ctx.state.connection_info.handshake_in_the_clear() {
        payload_len += encode_responder_verify_data(ctx, session_id, rsp).await?;
    }

    // Geneate session data key
    let th2_transcript_hash = ctx
        .transcript_hash(TranscriptContext::Th, Some(session_id), true)
        .await?;

    let session_info = ctx
        .session_mgr
        .session_info_mut(session_id)
        .map_err(|e| (false, CommandError::Session(e)))?;

    session_info
        .generate_session_data_key(&th2_transcript_hash)
        .await
        .map_err(|e| (false, CommandError::Session(e)))?;

    rsp.push_data(payload_len)
        .map_err(|e| (false, CommandError::Codec(e)))
}

pub(crate) async fn handle_finish<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Check if the connection state is valid
    if ctx.state.connection_info.state() < ConnectionState::AlgorithmsNegotiated {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    }

    // FINISH is not supported in  v1.0
    if ctx.state.connection_info.version_number() < SpdmVersion::V11 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnsupportedRequest, 0, None))?;
    }

    // Check if KEY_EX_CAP is supported
    if ctx.local_capabilities.flags.key_ex_cap() == 0 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnsupportedRequest, 0, None))?;
    }

    // According to DSP0274, it is valid to set only ENCRYPT_CAP and clear MAC_CAP.
    // However, DSP0277 specifies that secure messaging requires at least MAC_CAP to be set.
    if ctx.local_capabilities.flags.mac_cap() == 0 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
    }

    // Validate session state based on handshake in the clear mode
    let session_id = if ctx.state.connection_info.handshake_in_the_clear() {
        // For handshake in the clear: must have handshake phase session, no active session
        if ctx.session_mgr.active_session_id().is_some() {
            Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
        }
        ctx.session_mgr.handshake_phase_session_id()
    } else {
        // If handshake is not in the clear, we must use the active session ID
        ctx.session_mgr.active_session_id()
    }
    .ok_or_else(|| ctx.generate_error_response(req_payload, ErrorCode::SessionRequired, 0, None))?;

    let session_info = ctx.session_mgr.session_info(session_id).map_err(|_| {
        ctx.generate_error_response(req_payload, ErrorCode::SessionRequired, 0, None)
    })?;

    if session_info.session_state != SessionState::HandshakeInProgress {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    }

    // Verify the negotiated Hash algorithm is SHA384
    ctx.verify_negotiated_hash_algo()
        .map_err(|_| ctx.generate_error_response(req_payload, ErrorCode::Unspecified, 0, None))?;

    // Process FINISH request
    process_finish(ctx, session_id, spdm_hdr, req_payload).await?;

    // Generate FINISH response
    ctx.prepare_response_buffer(req_payload)?;
    generate_finish_response(ctx, session_id, req_payload).await?;

    // Set the session state to Establishing
    ctx.session_mgr
        .set_session_state(session_id, SessionState::Establishing)
        .map_err(|e| (false, CommandError::Session(e)))?;

    // Reset handshake phase session ID
    ctx.session_mgr.reset_handshake_phase_session_id();

    Ok(())
}
