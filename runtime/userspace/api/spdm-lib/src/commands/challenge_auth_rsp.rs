// Licensed under the Apache-2.0 license
use crate::cert_store::{spdm_cert_chain_hash, MAX_CERT_SLOTS_SUPPORTED};
use crate::codec::{Codec, CommonCodec, MessageBuf};
use crate::commands::algorithms_rsp::selected_measurement_specification;
use crate::commands::error_rsp::ErrorCode;
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult};
use crate::protocol::*;
use crate::state::ConnectionState;
use crate::transcript::TranscriptContext;
use bitfield::bitfield;
use libapi_caliptra::crypto::asym::*;
use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext, SHA384_HASH_SIZE};
use libapi_caliptra::crypto::rng::Rng;
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct ChallengeReqBase {
    slot_id: u8,
    meas_summary_hash_type: u8,
    nonce: [u8; SPDM_NONCE_LEN],
}
impl CommonCodec for ChallengeReqBase {}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct ChallengeAuthRspBase {
    challenge_auth_attr: ChallengeAuthAttr,
    slot_mask: u8,
    cert_chain_hash: [u8; SHA384_HASH_SIZE],
    nonce: [u8; SPDM_NONCE_LEN],
}
impl CommonCodec for ChallengeAuthRspBase {}

impl ChallengeAuthRspBase {
    fn new(slot_id: u8) -> Self {
        Self {
            challenge_auth_attr: ChallengeAuthAttr(slot_id),
            slot_mask: 1 << slot_id,
            cert_chain_hash: [0; SHA384_HASH_SIZE],
            nonce: [0; SPDM_NONCE_LEN],
        }
    }
}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable)]
    #[repr(C)]
    struct ChallengeAuthAttr(u8);
    impl Debug;
    u8;
    pub slot_id, set_slot_id: 3, 0;
    reserved, _: 7, 4;
}

async fn process_challenge<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<(u8, u8, Option<RequesterContext>)> {
    // Validate the version
    let connection_version = ctx.validate_spdm_version(&spdm_hdr, req_payload)?;

    // Make sure the selected hash algorithm is SHA384
    ctx.validate_negotiated_hash_algo(req_payload)?;

    // Decode the CHALLENGE request payload
    let challenge_req = ChallengeReqBase::decode(req_payload).map_err(|_| {
        ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
    })?;

    let mut requester_context = None;

    if connection_version >= SpdmVersion::V13 {
        // Decode the RequesterContext if present
        requester_context = Some(RequesterContext::decode(req_payload).map_err(|_| {
            ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
        })?);
    }

    if challenge_req.meas_summary_hash_type > 0 && selected_measurement_specification(ctx).0 == 0 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
    }

    // Note: Pubkey of the responder will not be pre-provisioned to Requester. So slot ID 0xFF is invalid.
    if challenge_req.slot_id >= MAX_CERT_SLOTS_SUPPORTED
        || !ctx
            .device_certs_store
            .is_provisioned(challenge_req.slot_id)
            .await
    {
        Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
    }

    // If multi-key connection response is supported, validate the key supports challenge usage
    if connection_version >= SpdmVersion::V13 && ctx.state.connection_info.multi_key_conn_rsp() {
        match ctx
            .device_certs_store
            .key_usage_mask(challenge_req.slot_id)
            .await
        {
            Some(key_usage_mask) if key_usage_mask.challenge_usage() != 0 => {}
            _ => Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?,
        }
    }

    // Append the CHALLENGE request to the M1 transcript
    ctx.append_message_to_transcript(req_payload, TranscriptContext::M1, None)
        .await?;

    Ok((
        challenge_req.slot_id,
        challenge_req.meas_summary_hash_type,
        requester_context,
    ))
}

async fn encode_m1_signature<'a>(
    ctx: &mut SpdmContext<'a>,
    slot_id: u8,
    asym_algo: AsymAlgo,
    rsp: &mut MessageBuf<'a>,
) -> CommandResult<usize> {
    let spdm_version = ctx.state.connection_info.version_number();

    // Get the M1 transcript hash
    let mut m1_transcript_hash = [0u8; SHA384_HASH_SIZE];
    ctx.shared_transcript
        .hash(TranscriptContext::M1, None, &mut m1_transcript_hash, true)
        .await
        .map_err(|e| (false, CommandError::Transcript(e)))?;

    let signing_context = if spdm_version >= SpdmVersion::V12 {
        Some(
            create_responder_signing_context(spdm_version, ReqRespCode::ChallengeAuth)
                .map_err(|e| (false, CommandError::SignCtx(e)))?,
        )
    } else {
        None
    };

    let context = signing_context.as_ref().map(|x| &x[..]);

    let mut hash_ctx = HashContext::new();
    let tbs = if let Some(context) = context {
        // If the signing context is present, use it to compute the TBS hash
        let mut tbs = [0u8; SHA384_HASH_SIZE];
        let mut message = [0u8; SPDM_SIGNING_CONTEXT_LEN + SHA384_HASH_SIZE];
        message[..SPDM_SIGNING_CONTEXT_LEN].copy_from_slice(context);
        message[SPDM_SIGNING_CONTEXT_LEN..]
            .copy_from_slice(&m1_transcript_hash[..SHA384_HASH_SIZE]);
        hash_ctx
            .init(HashAlgoType::SHA384, Some(&message[..]))
            .await
            .map_err(|e| (false, CommandError::CaliptraApi(e)))?;
        hash_ctx
            .finalize(&mut tbs)
            .await
            .map_err(|e| (false, CommandError::CaliptraApi(e)))?;
        tbs
    } else {
        m1_transcript_hash
    };

    let mut signature = [0u8; ECC_P384_SIGNATURE_SIZE];

    ctx.device_certs_store
        .sign_hash(slot_id, asym_algo, &tbs, &mut signature)
        .await
        .map_err(|e| (false, CommandError::CertStore(e)))?;

    // Encode the signature
    let sig_len = asym_algo.signature_size();
    rsp.put_data(sig_len)
        .map_err(|e| (false, CommandError::Codec(e)))?;
    let sig_buf = rsp
        .data_mut(sig_len)
        .map_err(|e| (false, CommandError::Codec(e)))?;
    sig_buf.copy_from_slice(&signature[..sig_len]);
    rsp.pull_data(sig_len)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    Ok(sig_len)
}

async fn encode_challenge_auth_rsp_base<'a>(
    ctx: &mut SpdmContext<'a>,
    slot_id: u8,
    asym_algo: AsymAlgo,
    rsp: &mut MessageBuf<'a>,
) -> CommandResult<usize> {
    let mut challenge_auth_rsp = ChallengeAuthRspBase::new(slot_id);

    // Get the certificate chain hash
    spdm_cert_chain_hash(
        ctx.device_certs_store,
        slot_id,
        asym_algo,
        &mut challenge_auth_rsp.cert_chain_hash,
    )
    .await
    .map_err(|e| (false, CommandError::CertStore(e)))?;

    // Get the nonce
    Rng::generate_random_number(&mut challenge_auth_rsp.nonce)
        .await
        .map_err(|e| (false, CommandError::CaliptraApi(e)))?;

    // Encode the response
    challenge_auth_rsp
        .encode(rsp)
        .map_err(|e| (false, CommandError::Codec(e)))
}

pub(crate) async fn encode_measurement_summary_hash<'a>(
    ctx: &mut SpdmContext<'a>,
    meas_summary_hash_type: u8,
    rsp: &mut MessageBuf<'a>,
) -> CommandResult<usize> {
    let mut meas_summary_hash = [0u8; SHA384_HASH_SIZE];
    ctx.measurements
        .measurement_summary_hash(meas_summary_hash_type, &mut meas_summary_hash)
        .await
        .map_err(|e| (false, CommandError::Measurement(e)))?;

    let hash_len = meas_summary_hash.len();
    rsp.put_data(hash_len)
        .map_err(|e| (false, CommandError::Codec(e)))?;
    let hash_buf = rsp
        .data_mut(hash_len)
        .map_err(|e| (false, CommandError::Codec(e)))?;
    hash_buf.copy_from_slice(&meas_summary_hash[..hash_len]);
    rsp.pull_data(hash_len)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    Ok(hash_len)
}

async fn generate_challenge_auth_response<'a>(
    ctx: &mut SpdmContext<'a>,
    slot_id: u8,
    meas_summary_hash_type: u8,
    requester_context: Option<RequesterContext>,
    rsp: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Get the selected asymmetric algorithm
    let asym_algo = ctx.validate_negotiated_base_asym_algo(rsp)?;

    // Prepare the response buffer
    // Spdm Header first
    let connection_version = ctx.state.connection_info.version_number();
    let spdm_hdr = SpdmMsgHdr::new(connection_version, ReqRespCode::ChallengeAuth);
    let mut payload_len = spdm_hdr
        .encode(rsp)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    // Encode the CHALLENGE_AUTH response fixed fields
    payload_len += encode_challenge_auth_rsp_base(ctx, slot_id, asym_algo, rsp).await?;

    // Get the measurement summary hash
    if meas_summary_hash_type != 0 {
        payload_len += encode_measurement_summary_hash(ctx, meas_summary_hash_type, rsp).await?;
    }

    let opaque_data = OpaqueData::default();

    // Encode the Opaque data length = 0
    payload_len += opaque_data
        .encode(rsp)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    // if requester context is present, encode it
    if let Some(context) = requester_context {
        payload_len += context
            .encode(rsp)
            .map_err(|e| (false, CommandError::Codec(e)))?;
    }

    // Append CHALLENGE_AUTH to the M1 transcript
    ctx.append_message_to_transcript(rsp, TranscriptContext::M1, None)
        .await?;

    // Generate the signature and encode it in the response
    payload_len += encode_m1_signature(ctx, slot_id, asym_algo, rsp).await?;

    rsp.push_data(payload_len)
        .map_err(|e| (false, CommandError::Codec(e)))
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
    let (slot_id, meas_summary_hash_type, req_context) =
        process_challenge(ctx, spdm_hdr, req_payload).await?;

    // Generate CHALLENGE_AUTH response
    ctx.prepare_response_buffer(req_payload)?;
    generate_challenge_auth_response(
        ctx,
        slot_id,
        meas_summary_hash_type,
        req_context,
        req_payload,
    )
    .await?;

    // Change the connection state to Authenticated
    ctx.state
        .connection_info
        .set_state(ConnectionState::Authenticated);

    Ok(())
}
