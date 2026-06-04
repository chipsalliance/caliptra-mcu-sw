// Licensed under the Apache-2.0 license

//! KEY_EXCHANGE / KEY_EXCHANGE_RSP handler (DSP0274 §10.11.3).
//!
//! Implements the responder side of the SPDM key exchange:
//!
//! 1. Parse + validate the request (slot, meas hash type, opaque)
//! 2. ECDH generate + finish → DHE shared secret
//! 3. Create session, fork VCA running hash into session TH
//! 4. Feed cert_chain_hash, request, partial response to TH
//! 5. Sign TH1 → signature
//! 6. Derive handshake keys from TH1'
//! 7. Compute responder verify_data (HMAC of TH1')
//! 8. Build final response with signature + verify_data

use mcu_spdm_lite_codec::{
    encode_version_selection, parse_supported_versions, select_version, KeyExchangeReqBody,
    KeyExchangeRsp, ResponseBody, SpdmMsgHdrPdu, SpdmVersion, ECC_P384_SIGNATURE_SIZE,
    ECDH_P384_EXCHANGE_DATA_SIZE, KEY_EXCHANGE_RANDOM_DATA_LEN, OPAQUE_VERSION_SELECTION_SIZE,
    SHA384_HASH_SIZE, SPDM_CONTEXT_LEN, SPDM_PREFIX_LEN, SPDM_SIGNING_CONTEXT_LEN,
};
use mcu_spdm_lite_traits::*;
use zerocopy::FromBytes;

use crate::build::build_response;
use crate::error::{SpdmResult, SPDM_INVALID_REQUEST, SPDM_UNEXPECTED_REQUEST, SPDM_UNSPECIFIED};
use crate::key_schedule::SessionKeyType;
use crate::session::SessionManager;
use crate::stack::{ConnectionState, Phase};

pub(crate) async fn handle_key_exchange<'a, Pal: SpdmPal, const N: usize>(
    state: &mut ConnectionState<Pal::State>,
    sessions: &mut SessionManager<<Pal as SpdmPalSessionCrypto>::Key, Pal::State, N>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
) -> SpdmResult<PalBytes<'a, Pal>> {
    // ── Phase check ─────────────────────────────────────────────────
    if (state.phase as u8) < (Phase::AfterAlgorithms as u8) {
        return Err(SPDM_UNEXPECTED_REQUEST);
    }

    // Only one handshake at a time.
    if sessions.has_handshake_in_progress() {
        return Err(SPDM_UNEXPECTED_REQUEST);
    }

    // ── Parse request ───────────────────────────────────────────────
    let req = io.request();
    let (hdr, rest) = SpdmMsgHdrPdu::ref_from_prefix(req).map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != state.version.to_u8() {
        return Err(crate::error::SPDM_VERSION_MISMATCH);
    }

    let (ke_req, after) =
        KeyExchangeReqBody::ref_from_prefix(rest).map_err(|_| SPDM_INVALID_REQUEST)?;

    let slot_id = ke_req.slot_id & 0x0F;
    let meas_hash_type = ke_req.meas_summary_hash_type;
    let req_session_id = ke_req.req_session_id_u16();

    // Validate slot_id.
    if slot_id >= MAX_SLOTS || (pal.provisioned_slots() & (1 << slot_id)) == 0 {
        return Err(SPDM_INVALID_REQUEST);
    }

    // Validate meas_summary_hash_type: 0 (none), 1 (TCB), or 0xFF (all).
    // DSP0274 §10.11 — must accept all three when MEAS_CAP != 0.
    if meas_hash_type != 0 && meas_hash_type != 1 && meas_hash_type != 0xFF {
        return Err(SPDM_INVALID_REQUEST);
    }

    // ── Parse opaque data ───────────────────────────────────────────
    if after.len() < 2 {
        return Err(SPDM_INVALID_REQUEST);
    }
    let opaque_len = u16::from_le_bytes([after[0], after[1]]) as usize;
    if after.len() < 2 + opaque_len {
        return Err(SPDM_INVALID_REQUEST);
    }
    let opaque_data = &after[2..2 + opaque_len];

    // Select secured-message version from requester's list.
    let supported = parse_supported_versions(opaque_data).map_err(|_| SPDM_INVALID_REQUEST)?;
    let selected_version = select_version(&supported).map_err(|_| SPDM_INVALID_REQUEST)?;

    // ── ECDH key generation ─────────────────────────────────────────
    let (ecdh_context, our_exchange_data) =
        pal.ecdh_generate(io).await.map_err(|_| SPDM_UNSPECIFIED)?;

    // Complete ECDH with peer's exchange data → DHE shared secret.
    let dhe_secret = pal
        .ecdh_finish(io, &ecdh_context, &ke_req.exchange_data)
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;

    // ── Create session ──────────────────────────────────────────────
    let session_id = match sessions.create_session(req_session_id, state.version) {
        Ok(id) => id,
        Err(_) => {
            // Destroy DHE secret so we don't leak the CMK handle.
            let _ = pal.delete_key(io, &dhe_secret).await;
            return Err(SPDM_UNSPECIFIED);
        }
    };
    let rsp_session_id = (session_id >> 16) as u16;

    // From here on, errors must clean up the session.
    let result = key_exchange_inner(
        state,
        sessions,
        pal,
        io,
        req,
        ke_req,
        slot_id,
        meas_hash_type,
        session_id,
        rsp_session_id,
        dhe_secret,
        &our_exchange_data,
        &selected_version,
    )
    .await;

    if result.is_err() {
        sessions.remove_and_destroy(pal, io, session_id).await;
    }

    result
}

/// Inner implementation that can fail; caller handles session cleanup.
#[inline(never)]
async fn key_exchange_inner<'a, Pal: SpdmPal, const N: usize>(
    state: &mut ConnectionState<Pal::State>,
    sessions: &mut SessionManager<<Pal as SpdmPalSessionCrypto>::Key, Pal::State, N>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    req: &[u8],
    _ke_req: &KeyExchangeReqBody,
    slot_id: u8,
    meas_hash_type: u8,
    session_id: u32,
    rsp_session_id: u16,
    dhe_secret: <Pal as SpdmPalSessionCrypto>::Key,
    our_exchange_data: &[u8; ECDH_P384_EXCHANGE_DATA_SIZE],
    selected_version: &[u8; 2],
) -> SpdmResult<PalBytes<'a, Pal>> {
    let session = sessions.find_mut(session_id).ok_or(SPDM_UNSPECIFIED)?;

    // Store DHE secret for later key derivation.
    session.key_schedule.set_dhe_secret(dhe_secret);

    // ── Init session TH by forking the VCA running hash ────────────
    // The VCA hash state already contains the raw VCA message bytes.
    // Cloning it avoids the incorrect hash(hash(VCA)) nesting.
    let vca_state = state.transcript.vca.as_ref().ok_or(SPDM_UNSPECIFIED)?;
    session.transcript.init_from_running(pal, io, vca_state)?;

    // ── Cert chain hash ─────────────────────────────────────────────
    let asym_algo = state.asym_algo();
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

    // ── Feed TH: cert_chain_hash ────────────────────────────────────
    session.transcript.append(pal, io, &cert_chain_hash).await?;

    // ── Feed TH: full KEY_EXCHANGE request ──────────────────────────
    // Use only the actual SPDM bytes (not transport padding).
    let spdm_req_len = SpdmMsgHdrPdu::SIZE
        + core::mem::size_of::<KeyExchangeReqBody>()
        + 2 // opaque_len field
        + u16::from_le_bytes([
            req[SpdmMsgHdrPdu::SIZE + core::mem::size_of::<KeyExchangeReqBody>()],
            req[SpdmMsgHdrPdu::SIZE + core::mem::size_of::<KeyExchangeReqBody>() + 1],
        ]) as usize;
    session
        .transcript
        .append(pal, io, &req[..spdm_req_len])
        .await?;

    // ── Generate random + summary hash ──────────────────────────────
    let mut nonce = [0u8; KEY_EXCHANGE_RANDOM_DATA_LEN];
    pal.generate_nonce(io, &mut nonce)
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;

    // Measurement summary hash: zero-filled when type=0xFF.
    // TODO: compute real measurement summary hash.
    let meas_summary_hash = [0u8; SHA384_HASH_SIZE];
    let meas_hash_ref = if meas_hash_type != 0 {
        Some(&meas_summary_hash)
    } else {
        None
    };

    // ── Encode opaque version selection ─────────────────────────────
    let mut opaque_buf = [0u8; OPAQUE_VERSION_SELECTION_SIZE];
    encode_version_selection(*selected_version, &mut opaque_buf).map_err(|_| SPDM_UNSPECIFIED)?;

    // ── Build partial response (no signature, no verify_data) ───────
    let partial_body = KeyExchangeRsp {
        rsp_session_id,
        random_data: &nonce,
        exchange_data: our_exchange_data,
        meas_summary_hash: meas_hash_ref,
        opaque_data: &opaque_buf,
        signature: &[],
        responder_verify_data: None,
    };

    let partial_resp =
        build_response(pal, io, state.version, &partial_body).map_err(|_| SPDM_UNSPECIFIED)?;

    // Feed partial response (SPDM bytes only) to TH.
    let head = pal.header_size();
    let spdm_rsp_len = partial_body.encoded_size();
    session
        .transcript
        .append(pal, io, &partial_resp[head..head + spdm_rsp_len])
        .await?;
    drop(partial_resp);

    // ── TH1 = clone-and-finalize (for signing) ─────────────────────
    let mut th1 = [0u8; SHA384_HASH_SIZE];
    session
        .transcript
        .clone_and_finalize(pal, io, &mut th1)
        .await?;

    // ── Sign TH1 ────────────────────────────────────────────────────
    let signing_ctx = build_signing_context(state.version);
    let tbs_hash = compute_tbs_hash(pal, io, &signing_ctx, &th1)
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;

    let mut signature = [0u8; ECC_P384_SIGNATURE_SIZE];
    let sig_len = pal
        .sign_hash(io, slot_id, asym_algo, &tbs_hash, &mut signature)
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;
    if sig_len != ECC_P384_SIGNATURE_SIZE {
        return Err(SPDM_UNSPECIFIED);
    }

    // ── Feed signature to TH ────────────────────────────────────────
    session.transcript.append(pal, io, &signature).await?;

    // ── TH1' = clone-and-finalize (for HMAC + key derivation) ──────
    let mut th1_prime = [0u8; SHA384_HASH_SIZE];
    session
        .transcript
        .clone_and_finalize(pal, io, &mut th1_prime)
        .await?;

    // ── Derive handshake keys ───────────────────────────────────────
    session
        .key_schedule
        .generate_handshake_keys(pal, io, &th1_prime)
        .await?;

    // ── Compute responder verify_data ───────────────────────────────
    let mut verify_data = [0u8; SHA384_HASH_SIZE];
    let vd_len = session
        .key_schedule
        .hmac_finished(
            pal,
            io,
            SessionKeyType::ResponseFinishedKey,
            &th1_prime,
            &mut verify_data,
        )
        .await?;
    if vd_len != SHA384_HASH_SIZE {
        return Err(SPDM_UNSPECIFIED);
    }

    // Feed verify_data to TH (state persists for FINISH phase).
    session.transcript.append(pal, io, &verify_data).await?;

    // ── Build full response ─────────────────────────────────────────
    let full_body = KeyExchangeRsp {
        rsp_session_id,
        random_data: &nonce,
        exchange_data: our_exchange_data,
        meas_summary_hash: meas_hash_ref,
        opaque_data: &opaque_buf,
        signature: &signature,
        responder_verify_data: Some(&verify_data),
    };

    let full_resp =
        build_response(pal, io, state.version, &full_body).map_err(|_| SPDM_UNSPECIFIED)?;

    Ok(full_resp)
}

// ── Signing helpers ─────────────────────────────────────────────────

fn build_signing_context(version: SpdmVersion) -> [u8; SPDM_SIGNING_CONTEXT_LEN] {
    let mut ctx = [0u8; SPDM_SIGNING_CONTEXT_LEN];

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
    }

    let op = b"responder-key_exchange_rsp signing";
    let pad = SPDM_CONTEXT_LEN - op.len();
    ctx[SPDM_PREFIX_LEN + pad..SPDM_PREFIX_LEN + pad + op.len()].copy_from_slice(op);

    ctx
}

async fn compute_tbs_hash<Pal: SpdmPal>(
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    signing_ctx: &[u8; SPDM_SIGNING_CONTEXT_LEN],
    th_hash: &[u8; SHA384_HASH_SIZE],
) -> mcu_error::McuResult<[u8; SHA384_HASH_SIZE]> {
    let mut state = pal
        .hash_init(io, SpdmPalHashAlgo::Sha384, signing_ctx)
        .await?;
    pal.hash_update(io, &mut state, th_hash).await?;
    let mut tbs = [0u8; SHA384_HASH_SIZE];
    pal.hash_finish(io, &mut state, &mut tbs).await?;
    Ok(tbs)
}
