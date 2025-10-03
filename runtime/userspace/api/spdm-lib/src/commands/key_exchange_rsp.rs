// Licensed under the Apache-2.0 license

#![allow(dead_code)]

use crate::cert_store::{compute_cert_chain_hash, MAX_CERT_SLOTS_SUPPORTED};
use crate::codec::{encode_u8_slice, Codec, CommonCodec, MessageBuf};
use crate::commands::algorithms_rsp::selected_measurement_specification;
use crate::commands::challenge_auth_rsp::encode_measurement_summary_hash;
use crate::commands::error_rsp::ErrorCode;
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult};
use crate::opaque_element::secure_message::{
    sm_select_version_from_list, sm_selected_version_opaque_data, SmVersion,
};
use crate::protocol::*;
use crate::session::{SessionInfo, SessionKeyType, SessionPolicy, SessionState, SessionType};
use crate::state::ConnectionInfo;
use crate::state::ConnectionState;
use crate::transcript::TranscriptContext;
use bitfield::bitfield;
use libapi_caliptra::crypto::asym::ecdh::CMB_ECDH_EXCHANGE_DATA_MAX_SIZE;
use libapi_caliptra::crypto::asym::{AsymAlgo, ECC_P384_SIGNATURE_SIZE};
use libapi_caliptra::crypto::hash::SHA384_HASH_SIZE;
use libapi_caliptra::crypto::rng::Rng;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const RANDOM_DATA_LEN: usize = 32;

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

struct KeyExchRspContext {
    slot_id: u8,
    meas_summary_hash_type: u8,
    resp_exch_data: [u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
    selected_sm_version: SmVersion,
    resp_session_id: u16,
    session_id: u32,
}

fn init_session(
    session_info: &mut SessionInfo,
    local_capabilities_flags: CapabilityFlags,
    connection_info: &ConnectionInfo,
    session_policy: SessionPolicy,
    asym_algo: AsymAlgo,
) {
    // let local_capabilities_flags = ctx.local_capabilities.flags;
    let peer_capabilities = connection_info.peer_capabilities().flags;

    let mac_cap = local_capabilities_flags.mac_cap() != 0 && peer_capabilities.mac_cap() != 0;
    let encrypt_cap =
        local_capabilities_flags.encrypt_cap() != 0 && peer_capabilities.encrypt_cap() != 0;

    let session_type = match (mac_cap, encrypt_cap) {
        (true, true) => SessionType::MacAndEncrypt,
        (true, false) => SessionType::MacOnly,
        _ => SessionType::None,
    };

    session_info.init(
        session_policy,
        session_type,
        connection_info.version_number(),
        asym_algo,
    );
}

async fn process_key_exchange<'a>(
    ctx: &mut SpdmContext<'a>,
    asym_algo: AsymAlgo,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<KeyExchRspContext> {
    // Validate the version
    let connection_version = ctx.state.connection_info.version_number();
    if spdm_hdr.version().ok() != Some(connection_version) {
        Err(ctx.generate_error_response(req_payload, ErrorCode::VersionMismatch, 0, None))?;
    }

    // Decode the KEY_EXCHANGE request payload
    let exch_req = KeyExchangeEcdhReqBase::decode(req_payload).map_err(|_| {
        ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
    })?;

    // Validate measurement summary hash type and DMTF spec
    match exch_req.meas_summary_hash_type {
        0 => {} // No measurement summary hash requested
        1 | 0xFF => {
            if selected_measurement_specification(ctx).dmtf_measurement_spec() != 1 {
                Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
            }
        }
        _ => Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?,
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

    // Decode the OpaqueData and select the secure version from list
    let req_opaque_data =
        OpaqueData::decode(req_payload).map_err(|e| (false, CommandError::Codec(e)))?;

    let selected_sm_version =
        sm_select_version_from_list(req_opaque_data, ctx.supported_secure_versions).map_err(
            |_| ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None),
        )?;

    ctx.state
        .connection_info
        .set_sec_msg_version(selected_sm_version);

    // Create session
    let (session_id, resp_session_id) =
        ctx.session_mgr.generate_session_id(exch_req.req_session_id);

    // Create session and initialize it
    ctx.session_mgr.create_session(session_id).map_err(|_| {
        ctx.generate_error_response(req_payload, ErrorCode::SessionLimitExceeded, 0, None)
    })?;

    ctx.session_mgr.set_handshake_phase_session_id(session_id);

    let session_info = ctx
        .session_mgr
        .session_info_mut(session_id)
        .map_err(|e| (false, CommandError::Session(e)))?;

    init_session(
        session_info,
        ctx.local_capabilities.flags,
        &ctx.state.connection_info,
        exch_req.session_policy,
        asym_algo,
    );

    let resp_exch_data = session_info
        .compute_dhe_secret(&exch_req.exchange_data)
        .await
        .map_err(|e| (false, CommandError::Session(e)))?;

    // Reset the transcript for the GET_MEASUREMENTS request
    ctx.reset_transcript_via_req_code(ReqRespCode::KeyExchange);

    let mut cert_chain_hash = [0u8; SHA384_HASH_SIZE];

    compute_cert_chain_hash(
        ctx.device_certs_store,
        exch_req.slot_id,
        asym_algo,
        &mut cert_chain_hash,
    )
    .await
    .map_err(|e| (false, CommandError::CertStore(e)))?;

    // Update transcript
    // Hash of the cert chain in DER format
    // KEY_EXCHANGE request
    ctx.append_slice_to_transcript(&cert_chain_hash, TranscriptContext::Th, Some(session_id))
        .await?;
    ctx.append_message_to_transcript(req_payload, TranscriptContext::Th, Some(session_id))
        .await?;

    Ok(KeyExchRspContext {
        meas_summary_hash_type: exch_req.meas_summary_hash_type,
        slot_id: exch_req.slot_id,
        resp_exch_data,
        selected_sm_version,
        resp_session_id,
        session_id,
    })
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

async fn th1_signature(
    ctx: &mut SpdmContext<'_>,
    session_id: u32,
    slot_id: u8,
    asym_algo: AsymAlgo,
) -> CommandResult<[u8; ECC_P384_SIGNATURE_SIZE]> {
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
    Ok(signature)
}

#[allow(clippy::too_many_arguments)]
async fn generate_key_exchange_response<'a>(
    ctx: &mut SpdmContext<'a>,
    asym_algo: AsymAlgo,
    key_exch_rsp_ctx: KeyExchRspContext,
    rsp: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Prepare the response buffer
    // Spdm Header first
    let connection_version = ctx.state.connection_info.version_number();
    let spdm_hdr = SpdmMsgHdr::new(connection_version, ReqRespCode::KeyExchangeRsp);
    let mut payload_len = spdm_hdr
        .encode(rsp)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    // Encode the KEY_EXCHANGE response fixed fields
    payload_len += encode_key_exchange_rsp_base(
        key_exch_rsp_ctx.resp_session_id,
        key_exch_rsp_ctx.resp_exch_data,
        rsp,
    )
    .await?;

    // Get the measurement summary hash
    if key_exch_rsp_ctx.meas_summary_hash_type != 0 {
        payload_len +=
            encode_measurement_summary_hash(ctx, key_exch_rsp_ctx.meas_summary_hash_type, rsp)
                .await?;
    }

    let opaque_data = sm_selected_version_opaque_data(key_exch_rsp_ctx.selected_sm_version)
        .map_err(|e| (false, CommandError::OpaqueData(e)))?;

    // Encode the Opaque with version selection data
    payload_len += opaque_data
        .encode(rsp)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    // Append the response to Th transcript
    ctx.append_message_to_transcript(
        rsp,
        TranscriptContext::Th,
        Some(key_exch_rsp_ctx.session_id),
    )
    .await?;

    // Encode TH1 signature.
    let th1_sig = th1_signature(
        ctx,
        key_exch_rsp_ctx.session_id,
        key_exch_rsp_ctx.slot_id,
        asym_algo,
    )
    .await?;

    payload_len += encode_u8_slice(&th1_sig, rsp).map_err(|e| (false, CommandError::Codec(e)))?;

    // Update the session transcript with the KEY_EXCHANGE_RSP signature
    ctx.append_slice_to_transcript(
        &th1_sig,
        TranscriptContext::Th,
        Some(key_exch_rsp_ctx.session_id),
    )
    .await?;

    // Compute TH1 transcript hash for generating the session handshake key
    let th1_transcript_hash = ctx
        .transcript_hash(
            TranscriptContext::Th,
            Some(key_exch_rsp_ctx.session_id),
            false,
        )
        .await?;

    // generate session handshake key
    let session_info = ctx
        .session_mgr
        .session_info_mut(key_exch_rsp_ctx.session_id)
        .map_err(|e| (false, CommandError::Session(e)))?;

    session_info
        .generate_session_handshake_key(&th1_transcript_hash)
        .await
        .map_err(|e| (false, CommandError::Session(e)))?;

    // Encode ResponderVerifyData if applicable
    let responder_verify_data = if !ctx.state.connection_info.handshake_in_the_clear()
        && session_info.session_type != SessionType::None
    {
        Some(
            session_info
                .compute_hmac(SessionKeyType::ResponseFinishedKey, &th1_transcript_hash)
                .await
                .map_err(|e| (false, CommandError::Session(e)))?,
        )
    } else {
        None
    };

    if let Some(responder_verify_data) = responder_verify_data {
        payload_len += encode_u8_slice(&responder_verify_data, rsp)
            .map_err(|e| (false, CommandError::Codec(e)))?;

        ctx.append_slice_to_transcript(
            &responder_verify_data,
            TranscriptContext::Th,
            Some(key_exch_rsp_ctx.session_id),
        )
        .await?;
    }

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

    // KEY_EXCHANGE is not supported in  v1.0
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

    // Check negotiated algorithms are valid and generate error response once
    let asym_algo = ctx
        .negotiated_base_asym_algo()
        .and_then(|algo| {
            // Check hash algorithm
            ctx.verify_negotiated_hash_algo()?;
            // Check DHE group
            ctx.verify_negotiated_dhe_group()?;
            Ok(algo)
        })
        .map_err(|_| ctx.generate_error_response(req_payload, ErrorCode::Unspecified, 0, None))?;

    // Process KEY_EXCHANGE request
    let key_exch_rsp_ctx = match process_key_exchange(ctx, asym_algo, spdm_hdr, req_payload).await {
        Ok(result) => result,
        Err(e) => {
            if ctx.session_mgr.handshake_phase_session_id().is_some() {
                let session_id = ctx.session_mgr.handshake_phase_session_id().unwrap();
                let _ = ctx.session_mgr.delete_session(session_id);
            }
            return Err(e);
        }
    };

    // Generate KEY_EXCHANGE response
    ctx.prepare_response_buffer(req_payload)?;

    let session_id = key_exch_rsp_ctx.session_id;

    // Generate response with automatic cleanup on error
    if let Err(e) =
        generate_key_exchange_response(ctx, asym_algo, key_exch_rsp_ctx, req_payload).await
    {
        // Clean up session on error
        if ctx.session_mgr.handshake_phase_session_id().is_some() {
            let _ = ctx.session_mgr.delete_session(session_id); // Ignore cleanup errors
        }
        return Err(e);
    }

    if !ctx.state.connection_info.handshake_in_the_clear() {
        ctx.session_mgr.set_handshake_phase_session_id(session_id);
    }

    ctx.session_mgr
        .set_session_state(session_id, SessionState::HandshakeInProgress)
        .map_err(|e| (false, CommandError::Session(e)))?;

    Ok(())
}
