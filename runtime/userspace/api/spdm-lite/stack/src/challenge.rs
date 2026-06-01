// Licensed under the Apache-2.0 license

//! CHALLENGE / CHALLENGE_AUTH handler.

use mcu_spdm_lite_codec::{
    ChallengeAuthRsp, ChallengeReqBody, ResponseBody, SpdmMsgHdrPdu, SpdmVersion,
    ECC_P384_SIGNATURE_SIZE, REQUESTER_CONTEXT_LEN, SHA384_HASH_SIZE, SPDM_CONTEXT_LEN,
    SPDM_PREFIX_LEN, SPDM_SIGNING_CONTEXT_LEN,
};
use mcu_spdm_lite_traits::*;
use zerocopy::FromBytes;

use crate::build::build_response;
use crate::error::{SpdmResult, SPDM_INVALID_REQUEST, SPDM_UNEXPECTED_REQUEST, SPDM_UNSPECIFIED};
use crate::stack::{ConnectionState, Phase};

pub(crate) async fn handle_challenge<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
) -> SpdmResult<PalBytes<'a, Pal>> {
    // Phase: must be after algorithms negotiation.
    // GET_DIGESTS and GET_CERTIFICATE are optional before CHALLENGE.
    if (state.phase as u8) < (Phase::AfterAlgorithms as u8) {
        return Err(SPDM_UNEXPECTED_REQUEST);
    }

    // Validate version matches negotiated.
    let req = io.request();
    let (hdr, rest) = SpdmMsgHdrPdu::ref_from_prefix(req).map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != state.version.to_u8() {
        return Err(crate::error::SPDM_VERSION_MISMATCH);
    }

    // Decode CHALLENGE body.
    let (challenge_req, after) =
        ChallengeReqBody::ref_from_prefix(rest).map_err(|_| SPDM_INVALID_REQUEST)?;

    let slot_id = challenge_req.slot_id & 0x0F;
    let meas_hash_type = challenge_req.meas_summary_hash_type;

    // Validate slot_id.
    if slot_id >= MAX_SLOTS || (pal.provisioned_slots() & (1 << slot_id)) == 0 {
        return Err(SPDM_INVALID_REQUEST);
    }

    // Validate meas_summary_hash_type: 0, 1, or 0xFF.
    if meas_hash_type != 0 && meas_hash_type != 1 && meas_hash_type != 0xFF {
        return Err(SPDM_INVALID_REQUEST);
    }

    // Parse RequesterContext for V1.3+.
    let mut requester_context = None;
    if state.version >= SpdmVersion::V13 {
        if after.len() < REQUESTER_CONTEXT_LEN {
            return Err(SPDM_INVALID_REQUEST);
        }
        let mut ctx = [0u8; REQUESTER_CONTEXT_LEN];
        ctx.copy_from_slice(&after[..REQUESTER_CONTEXT_LEN]);
        requester_context = Some(ctx);
    }

    // Append CHALLENGE request to M1 transcript.
    state.transcript.append_m1(pal, io, req).await?;

    let asym_algo = state.asym_algo();

    // Get cert chain hash — use cache if available, else compute.
    let mut cert_chain_hash = [0u8; SHA384_HASH_SIZE];
    if let Some(cached) = pal.cached_chain_digest(slot_id, SpdmPalHashAlgo::Sha384) {
        cert_chain_hash = cached;
    } else {
        crate::digests::cert_chain_hash(
            pal,
            io,
            slot_id,
            asym_algo,
            SpdmPalHashAlgo::Sha384,
            &mut cert_chain_hash,
        )
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;
        pal.cache_chain_digest(slot_id, SpdmPalHashAlgo::Sha384, &cert_chain_hash);
    }

    // Generate nonce via PAL RNG.
    let mut nonce = [0u8; SPDM_NONCE_LEN];
    pal.generate_nonce(io, &mut nonce)
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;

    // Measurement summary hash: zero-filled placeholder until
    // GET_MEASUREMENTS is implemented. Omitted when type=0.
    let meas_summary_hash = [0u8; SHA384_HASH_SIZE];
    let meas_hash_ref = if meas_hash_type != 0 {
        Some(&meas_summary_hash)
    } else {
        None
    };

    // Build response body (without signature — appended after M1 finalize).
    let body_no_sig = ChallengeAuthRsp {
        slot_id,
        cert_chain_hash: &cert_chain_hash,
        nonce: &nonce,
        meas_summary_hash: meas_hash_ref,
        opaque_len: 0,
        requester_context: requester_context.as_ref(),
        signature: &[],
    };

    let resp =
        build_response(pal, io, state.version, &body_no_sig).map_err(|_| SPDM_UNSPECIFIED)?;

    // Append CHALLENGE_AUTH response (without signature) to M1.
    // Only the SPDM message bytes, not transport padding.
    let head = pal.header_size();
    let spdm_len = body_no_sig.encoded_size();
    state
        .transcript
        .append_m1(pal, io, &resp[head..head + spdm_len])
        .await?;

    // Finalize M1 transcript hash.
    let mut m1_hash = [0u8; SHA384_HASH_SIZE];
    state.transcript.finalize_m1(pal, io, &mut m1_hash).await?;

    // Build signing context and compute TBS hash.
    let signing_ctx = build_signing_context(state.version);
    let tbs_hash = compute_tbs_hash(pal, io, &signing_ctx, &m1_hash)
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;

    // Sign the TBS hash.
    let mut signature = [0u8; ECC_P384_SIGNATURE_SIZE];
    let sig_len = pal
        .sign_hash(io, slot_id, asym_algo, &tbs_hash, &mut signature)
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;
    if sig_len != ECC_P384_SIGNATURE_SIZE {
        return Err(SPDM_UNSPECIFIED);
    }

    // Now rebuild the full response with signature.
    let full_body = ChallengeAuthRsp {
        slot_id,
        cert_chain_hash: &cert_chain_hash,
        nonce: &nonce,
        meas_summary_hash: meas_hash_ref,
        opaque_len: 0,
        requester_context: requester_context.as_ref(),
        signature: &signature,
    };

    let full_resp =
        build_response(pal, io, state.version, &full_body).map_err(|_| SPDM_UNSPECIFIED)?;

    // Transition to authenticated.
    state.phase = Phase::AfterCertificate; // TODO: add Phase::Authenticated

    Ok(full_resp)
}

/// Build the 100-byte SPDM signing context for CHALLENGE_AUTH.
fn build_signing_context(version: SpdmVersion) -> [u8; SPDM_SIGNING_CONTEXT_LEN] {
    let mut ctx = [0u8; SPDM_SIGNING_CONTEXT_LEN];

    // Prefix: "dmtf-spdm-v" + version + ".*" repeated 4× = 64 bytes.
    let base = b"dmtf-spdm-v";
    let ver = match version {
        SpdmVersion::V10 => b"1.0.*",
        SpdmVersion::V11 => b"1.1.*",
        SpdmVersion::V12 => b"1.2.*",
        SpdmVersion::V13 => b"1.3.*",
    };
    let mut pos = 0;
    for _ in 0..4 {
        ctx[pos..pos + base.len()].copy_from_slice(base);
        pos += base.len();
        ctx[pos..pos + ver.len()].copy_from_slice(ver);
        pos += ver.len();
        // Each block is 16 bytes: 11 + 5 = 16.
    }

    // Operation context: zero-padded on the left, string at the end.
    let op = b"responder-challenge_auth signing";
    let pad = SPDM_CONTEXT_LEN - op.len();
    ctx[SPDM_PREFIX_LEN + pad..SPDM_PREFIX_LEN + pad + op.len()].copy_from_slice(op);

    ctx
}

/// Hash(signing_context || M1_hash) → TBS digest for signing.
async fn compute_tbs_hash<Pal: SpdmPal>(
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    signing_ctx: &[u8; SPDM_SIGNING_CONTEXT_LEN],
    m1_hash: &[u8; SHA384_HASH_SIZE],
) -> mcu_error::McuResult<[u8; SHA384_HASH_SIZE]> {
    let mut state = pal
        .hash_init(io, SpdmPalHashAlgo::Sha384, signing_ctx)
        .await?;
    pal.hash_update(io, &mut state, m1_hash).await?;
    let mut tbs = [0u8; SHA384_HASH_SIZE];
    pal.hash_finish(io, &mut state, &mut tbs).await?;
    Ok(tbs)
}
