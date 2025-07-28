// Licensed under the Apache-2.0 license

#![allow(dead_code)]

use crate::cert_store::{hash_cert_chain, MAX_CERT_SLOTS_SUPPORTED};
use crate::codec::{encode_u8_slice, Codec, CommonCodec, MessageBuf};
use crate::commands::algorithms_rsp::selected_measurement_specification;
use crate::commands::challenge_auth_rsp::encode_measurement_summary_hash;
use crate::commands::error_rsp::ErrorCode;
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult};
use crate::protocol::*;
use crate::session::SessionPolicy;
use crate::state::ConnectionState;
use crate::transcript::TranscriptContext;
use bitfield::bitfield;
use libapi_caliptra::crypto::asym::ecdh::CMB_ECDH_EXCHANGE_DATA_MAX_SIZE;
use libapi_caliptra::crypto::asym::{AsymAlgo, ECC_P384_SIGNATURE_SIZE};
// use libapi_caliptra::crypto::hash::SHA384_HASH_SIZE;
use libapi_caliptra::crypto::rng::Rng;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const RANDOM_DATA_LEN: usize = 32;
// pub const ECDSA383_SIGNATURE_LEN: usize = 96;
pub const OPAQUE_DATA_LEN_MAX_SIZE: usize = 1024; // Maximum size for opaque data

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct KeyExchangeEcdhReqBase {
    meas_summary_hash_type: u8,
    slot_id: u8,
    req_session_id: u16,
    session_policy: SessionPolicy,
    _reserved: u8,
    random_data: [u8; RANDOM_DATA_LEN],
    exchange_data: [u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
}

impl CommonCodec for KeyExchangeEcdhReqBase {}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct KeyExchangeRspBase {
    heartbeat_period: u8,
    _reserved: u8,
    rsp_session_id: u16,
    mut_auth_requested: MutualAuthReqAttr,
    slot_id_param: u8,
    random_data: [u8; RANDOM_DATA_LEN],
    exchange_data: [u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
}
impl CommonCodec for KeyExchangeRspBase {}

impl KeyExchangeRspBase {
    fn new() -> Self {
        Self {
            heartbeat_period: 0,
            _reserved: 0,
            rsp_session_id: 0,
            mut_auth_requested: MutualAuthReqAttr(0),
            slot_id_param: 0,
            random_data: [0; RANDOM_DATA_LEN],
            exchange_data: [0; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
        }
    }
}

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

async fn process_key_exchange<'a>(
    ctx: &mut SpdmContext<'a>,
    asym_algo: AsymAlgo,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<(u8, u8, [u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE], u16, u32)> {
    // Validate the version
    let connection_version = ctx.state.connection_info.version_number();
    if spdm_hdr.version().ok() != Some(connection_version) {
        Err(ctx.generate_error_response(req_payload, ErrorCode::VersionMismatch, 0, None))?;
    }

    // Decode the KEY_EXCHANGE request payload
    let exch_req = KeyExchangeEcdhReqBase::decode(req_payload).map_err(|_| {
        ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
    })?;

    // Verify that the selected measurement hash type is DMTF
    if exch_req.meas_summary_hash_type > 0 && selected_measurement_specification(ctx).0 == 0 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
    }

    // Note: Pubkey of the responder will not be pre-provisioned to Requester. So slot ID 0xFF is invalid.
    if exch_req.slot_id >= MAX_CERT_SLOTS_SUPPORTED
        || ctx.local_capabilities.flags.cert_cap() == 0
        || !ctx
            .device_certs_store
            .is_provisioned(exch_req.slot_id)
            .await
    {
        Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
    }

    // If multi-key connection response is supported, validate the key supports key_exch usage
    if connection_version >= SpdmVersion::V13 && ctx.state.connection_info.multi_key_conn_rsp() {
        match ctx
            .device_certs_store
            .key_usage_mask(exch_req.slot_id)
            .await
        {
            Some(key_usage_mask) if key_usage_mask.key_exch_usage() != 0 => {}
            _ => Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?,
        }
    }

    // If session policy with event_all_policy is set, verify that the responder supports event capability
    if exch_req.session_policy.event_all_policy() != 0
        && ctx.local_capabilities.flags.event_cap() == 0
    {
        Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
    }

    let (_opaque_data, _opaque_data_len) = decode_opaque_data(req_payload).map_err(|_| {
        ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
    })?;

    // TODO: Process opaque data if needed.

    // Create session
    let (session_id, resp_session_id) =
        ctx.session_mgr.generate_session_id(exch_req.req_session_id);

    ctx.session_mgr
        .create_session(session_id, exch_req.session_policy)
        .map_err(|_| {
            ctx.generate_error_response(req_payload, ErrorCode::SessionLimitExceeded, 0, None)
        })?;

    let session_info = ctx
        .session_mgr
        .session_info_mut(session_id)
        .map_err(|e| (false, CommandError::Session(e)))?;

    let resp_exch_data = session_info
        .compute_dhe_secret(&exch_req.exchange_data)
        .await
        .map_err(|e| (false, CommandError::Session(e)))?;

    // Reset the transcript for the GET_MEASUREMENTS request
    ctx.reset_transcript_via_req_code(ReqRespCode::KeyExchange);

    let cert_chain_hash = hash_cert_chain(ctx.device_certs_store, exch_req.slot_id, asym_algo)
        .await
        .map_err(|e| (false, CommandError::CertStore(e)))?;

    // Update transcript
    // Hash of the cert chain in DER format
    // KEY_EXCHANGE request
    ctx.append_slice_to_transcript(&cert_chain_hash, TranscriptContext::Th, Some(session_id))
        .await?;
    ctx.append_message_to_transcript(req_payload, TranscriptContext::Th, Some(session_id))
        .await?;

    Ok((
        exch_req.meas_summary_hash_type,
        exch_req.slot_id,
        resp_exch_data,
        resp_session_id,
        session_id,
    ))
}

async fn encode_key_exchange_rsp_base(
    resp_session_id: u16,
    resp_exchange_data: [u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
    rsp: &mut MessageBuf<'_>,
) -> CommandResult<usize> {
    let mut key_exch_rsp = KeyExchangeRspBase::new();
    key_exch_rsp.rsp_session_id = resp_session_id;
    key_exch_rsp
        .exchange_data
        .copy_from_slice(&resp_exchange_data);

    // Generate random data
    Rng::generate_random_number(&mut key_exch_rsp.random_data)
        .await
        .map_err(|e| (false, CommandError::CaliptraApi(e)))?;

    // Encode the response fixed fields
    key_exch_rsp
        .encode(rsp)
        .map_err(|e| (false, CommandError::Codec(e)))
}

async fn encode_th1_signature(
    ctx: &mut SpdmContext<'_>,
    session_id: u32,
    slot_id: u8,
    asym_algo: AsymAlgo,
    rsp: &mut MessageBuf<'_>,
) -> CommandResult<usize> {
    let spdm_version = ctx.state.connection_info.version_number();
    let th1_transcript_hash = ctx
        .transcript_hash(
            TranscriptContext::Th,
            Some(session_id),
            false, // Do not finish hash yet
        )
        .await?;

    let tbs = get_tbs_via_response_code(
        spdm_version,
        ReqRespCode::KeyExchangeRsp,
        th1_transcript_hash,
    )
    .await
    .map_err(|e| (false, CommandError::SignCtx(e)))?;

    let mut signature = [0u8; ECC_P384_SIGNATURE_SIZE];
    ctx.device_certs_store
        .sign_hash(slot_id, asym_algo, &tbs, &mut signature)
        .await
        .map_err(|e| (false, CommandError::CertStore(e)))?;

    encode_u8_slice(&signature, rsp).map_err(|e| (false, CommandError::Codec(e)))?;

    Ok(signature.len())
}

fn init_secure_session(_ctx: &mut SpdmContext<'_>, _session_id: u32) -> CommandResult<()> {
    todo!("Initialize session's info and state");
}

#[allow(clippy::too_many_arguments)]
async fn generate_key_exchange_response<'a>(
    ctx: &mut SpdmContext<'a>,
    asym_algo: AsymAlgo,
    slot_id: u8,
    meas_summary_hash_type: u8,
    resp_exchange_data: [u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
    resp_session_id: u16,
    session_id: u32,
    rsp: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Prepare the response buffer
    // Spdm Header first
    let connection_version = ctx.state.connection_info.version_number();
    let spdm_hdr = SpdmMsgHdr::new(connection_version, ReqRespCode::KeyExchange);
    let mut payload_len = spdm_hdr
        .encode(rsp)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    // Encode the KEY_EXCHANGE response fixed fields
    payload_len += encode_key_exchange_rsp_base(resp_session_id, resp_exchange_data, rsp).await?;

    // Get the measurement summary hash
    if meas_summary_hash_type != 0 {
        payload_len +=
            encode_measurement_summary_hash(ctx, asym_algo, meas_summary_hash_type, rsp).await?;
    }

    // Encode the Opaque data length = 0
    payload_len += encode_opaque_data(rsp, &[])?;

    payload_len += encode_th1_signature(ctx, session_id, slot_id, asym_algo, rsp).await?;

    // TODO: Update transcript
    // ctx.append_message_to_transcript(rsp, TranscriptContext::KeyExchangeRspSignature)
    //     .await?;

    // TODO: Add signature
    // let signature =
    //     sign_transcript(ctx, slot_id, TranscriptContext::KeyExchangeRspSignature).await?;
    // encode_u8_slice(&signature, rsp).map_err(|e| (false, CommandError::Codec(e)))?;

    // TODO: we won't need this transcript any more
    // ctx.shared_transcript
    //     .disable_transcript(TranscriptContext::KeyExchangeRspSignature);

    let session_handshake_encrypted = false; // TODO: Need to figure this out
    let session_handshake_message_authenticated = false; // TODO: Need to figure this out
    let generate_hmac = session_handshake_encrypted || session_handshake_message_authenticated;
    if generate_hmac {
        // TODO: Append to HMAC transcript
        // ctx.append_message_to_transcript(rsp, TranscriptContext::KeyExchangeRspHmac)
        //     .await?;

        // let mut hash_to_hmac = [0u8; SHA384_HASH_SIZE];
        // TODO: compute the HMAC
        // ctx.shared_transcript
        //     .hash(TranscriptContext::KeyExchangeRspHmac, &mut hash_to_hmac)
        //     .await
        //     .map_err(|e| (false, CommandError::Transcript(e)))?;
        // let mac = Hmac::hmac(ctx.secrets.finished_key.as_ref().unwrap(), &hash_to_hmac)
        //     .await
        //     .map_err(|e| (false, CommandError::CaliptraApi(e)))?;
        // encode_u8_slice(&mac.mac[..mac.hdr.data_len as usize], rsp)
        //     .map_err(|e| (false, CommandError::Codec(e)))?;
    }

    // TODO: update transcripts
    // We won't need this transcript any more.
    // ctx.shared_transcript
    //     .disable_transcript(TranscriptContext::KeyExchangeRspHmac);

    // // Append the final key exchange response to the finish response transcripts.
    // ctx.append_message_to_transcripts(
    //     rsp,
    //     &[
    //         TranscriptContext::FinishMutualAuthHmac,
    //         TranscriptContext::FinishRspMutualAuth,
    //         TranscriptContext::FinishRspResponderOnly,
    //         TranscriptContext::FinishMutualAuthSignaure,
    //     ],
    // )
    // .await?;
    rsp.push_data(payload_len)
        .map_err(|e| (false, CommandError::Codec(e)))
}

pub(crate) async fn handle_key_exchange<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Check if the connection state is valid
    if ctx.state.connection_info.state() < ConnectionState::AlgorithmsNegotiated {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    }

    // KEY_EXCHANGE request is prohibited within session
    if ctx.session_mgr.session_active() {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    }

    if ctx.session_mgr.session_active() {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    }

    // Check if KEY_EX_CAP and at least MAC_CAP (of MAC_CAP and ENCRYPT_CAP) is supported
    if ctx.local_capabilities.flags.key_ex_cap() == 0 || ctx.local_capabilities.flags.mac_cap() == 0
    {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnsupportedRequest, 0, None))?;
    }

    // Get the selected AsymAlgo and verify the selected hash algorithm is SHA384
    let asym_algo = ctx
        .selected_base_asym_algo()
        .and_then(|algo| ctx.verify_selected_hash_algo().map(|_| algo))
        .map_err(|_| ctx.generate_error_response(req_payload, ErrorCode::Unspecified, 0, None))?;

    // Process KEY_EXCHANGE request
    let (slot_id, meas_summary_hash_type, resp_exchange_data, resp_session_id, session_id) =
        process_key_exchange(ctx, asym_algo, spdm_hdr, req_payload).await?;

    // Generate KEY_EXCHANGE response
    ctx.prepare_response_buffer(req_payload)?;
    generate_key_exchange_response(
        ctx,
        asym_algo,
        slot_id,
        meas_summary_hash_type,
        resp_exchange_data,
        resp_session_id,
        session_id,
        req_payload,
    )
    .await?;

    // TODO: derive the secrets
    Ok(())
}
