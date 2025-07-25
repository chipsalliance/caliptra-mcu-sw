// Licensed under the Apache-2.0 license

#![allow(dead_code)]

use crate::codec::{encode_u8_slice, Codec, CommonCodec, MessageBuf};
use crate::commands::error_rsp::ErrorCode;
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult};
use crate::protocol::opaque_data::encode_opaque_data;
use crate::protocol::*;
use crate::state::ConnectionState;
use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const RANDOM_DATA_LEN: usize = 32;
pub const ECDSA384_SIGNATURE_LEN: usize = 96;

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
    signature_present: u8,
    slot_id: u8,
    opaque_data_len: u16,
}
impl CommonCodec for FinishReqBase {}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct FinishRspBase {
    _reserved0: u8,
    _reserved1: u8,
    opaque_data_len: u16,
}
impl CommonCodec for FinishRspBase {}

impl FinishRspBase {
    fn new() -> Self {
        Self {
            _reserved0: 0,
            _reserved1: 0,
            opaque_data_len: 0,
        }
    }
}

async fn process_finish<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Validate the version
    let connection_version = ctx.state.connection_info.version_number();
    if spdm_hdr.version().ok() != Some(connection_version) {
        Err(ctx.generate_error_response(req_payload, ErrorCode::VersionMismatch, 0, None))?;
    }

    // Make sure the asymmetric algorithm is ECC P384
    if !matches!(ctx.selected_base_asym_algo(), Ok(AsymAlgo::EccP384)) {
        Err(ctx.generate_error_response(req_payload, ErrorCode::Unspecified, 0, None))?;
    }

    // Decode the FINISH request payload
    let finish_req_base = FinishReqBase::decode(req_payload).map_err(|_| {
        ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
    })?;
    if finish_req_base.opaque_data_len > OPAQUE_DATA_LEN_MAX_SIZE as u16 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
    }
    // ignore the opaque data
    req_payload
        .pull_data(finish_req_base.opaque_data_len as usize)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    if finish_req_base.signature_present != 0 {
        // TODO: validate the signature
        let mut signature = [0u8; ECDSA384_SIGNATURE_LEN];
        signature.copy_from_slice(
            req_payload
                .data(ECDSA384_SIGNATURE_LEN)
                .map_err(|e| (false, CommandError::Codec(e)))?,
        );
        req_payload
            .pull_data(ECDSA384_SIGNATURE_LEN)
            .map_err(|e| (false, CommandError::Codec(e)))?;
    }
    let _requester_verify_data = req_payload
        .data(SHA384_HASH_SIZE)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    // TODO: verify requester verify data
    Ok(())
}

async fn generate_finish_response<'a>(
    ctx: &mut SpdmContext<'a>,
    generate_responder_verify_data: bool,
    rsp: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Prepare the response buffer
    // Spdm Header first
    let connection_version = ctx.state.connection_info.version_number();
    let spdm_hdr = SpdmMsgHdr::new(connection_version, ReqRespCode::Finish);
    spdm_hdr
        .encode(rsp)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    // TODO: update transcripts
    // ctx.append_message_to_transcript(rsp, TranscriptContext::FinishRspResponderOnly)
    //     .await?;

    // Encode the FINISH response fixed fields
    FinishRspBase::new()
        .encode(rsp)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    // Encode the Opaque data length = 0
    encode_opaque_data(rsp, &[])?;

    if generate_responder_verify_data {
        let hmac = finish_rsp_transcript_responder_only(ctx).await?;
        encode_u8_slice(&hmac, rsp).map_err(|e| (false, CommandError::Codec(e)))?;
    }
    Ok(())
}

async fn finish_rsp_transcript_responder_only(
    _ctx: &mut SpdmContext<'_>,
) -> CommandResult<[u8; SHA384_HASH_SIZE]> {
    // Hash of the specified certificate chain in DER format (that is, Param2 of KEY_EXCHANGE ) or hash of the
    // public key in its provisioned format, if a certificate is not used.
    // TODO: transcript.extend(cert_chain_hash);
    // TODO: transcript.extend(key_exchange);
    // TODO: transcript.extend(key_exchange_rsp);
    // TODO: transcript.extend(finish);

    let hash = [0u8; SHA384_HASH_SIZE];
    // ctx.transcript_mgr
    //     .hash(TranscriptContext::FinishRspResponderOnly, &mut hash)
    //     .await
    //     .map_err(|e| (false, CommandError::Transcript(e)))?;

    // TODO: HMAC(...)

    Ok(hash)
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

    // Check if key exchange is supported
    if ctx.local_capabilities.flags.key_ex_cap() == 0 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnsupportedRequest, 0, None))?;
    }

    // TODO: Check that we have started a key exchange
    // if ctx.secrets.request_direction_handshake.is_none() {
    //     Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    // }

    // Process FINISH request
    process_finish(ctx, spdm_hdr, req_payload).await?;

    // Generate FINISH response
    ctx.prepare_response_buffer(req_payload)?;
    let generate_responder_verify_data = false; // TODO: see if we support handshake in the clear, ctx.handshake_in_the_clear();
    generate_finish_response(ctx, generate_responder_verify_data, req_payload).await?;

    // TODO: mark the session as mutually authenticated?

    Ok(())
}
