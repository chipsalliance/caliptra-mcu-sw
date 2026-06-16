// Licensed under the Apache-2.0 license

//! KEY_EXCHANGE / KEY_EXCHANGE_RSP handler.
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
    SHA384_HASH_SIZE, SPDM_PREFIX_LEN, SPDM_SIGNING_CONTEXT_LEN,
};
use mcu_spdm_lite_traits::SpdmPalAlloc;
use mcu_spdm_lite_traits::*;
use zerocopy::FromBytes;

use crate::build::build_response;
use crate::error::{
    SpdmError, SpdmResult, SPDM_INVALID_REQUEST, SPDM_UNEXPECTED_REQUEST, SPDM_UNSPECIFIED,
};
use crate::key_schedule::SessionKeyType;
use crate::session::SessionManager;
use crate::stack::{ConnectionState, Phase};

const ECDH_P384_ENCRYPTED_CONTEXT_SIZE: usize = 76;
const KEY_EXCHANGE_WORKSPACE_SIZE: usize = SHA384_HASH_SIZE
    + SPDM_SIGNING_CONTEXT_LEN
    + KEY_EXCHANGE_RANDOM_DATA_LEN
    + SHA384_HASH_SIZE
    + OPAQUE_VERSION_SELECTION_SIZE
    + ECC_P384_SIGNATURE_SIZE
    + SHA384_HASH_SIZE;
const KEY_EXCHANGE_SIGNING_PREFIX_CHUNK_LEN: usize = 16;
const KEY_EXCHANGE_SIGNING_PREFIX_V10: &[u8; KEY_EXCHANGE_SIGNING_PREFIX_CHUNK_LEN] =
    b"dmtf-spdm-v1.0.*";
const KEY_EXCHANGE_SIGNING_PREFIX_V11: &[u8; KEY_EXCHANGE_SIGNING_PREFIX_CHUNK_LEN] =
    b"dmtf-spdm-v1.1.*";
const KEY_EXCHANGE_SIGNING_PREFIX_V12: &[u8; KEY_EXCHANGE_SIGNING_PREFIX_CHUNK_LEN] =
    b"dmtf-spdm-v1.2.*";
const KEY_EXCHANGE_SIGNING_PREFIX_V13: &[u8; KEY_EXCHANGE_SIGNING_PREFIX_CHUNK_LEN] =
    b"dmtf-spdm-v1.3.*";
const KEY_EXCHANGE_SIGNING_OP: &[u8; 34] = b"responder-key_exchange_rsp signing";

pub(crate) async fn handle_key_exchange<'a, Pal: SpdmPal, const N: usize>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
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
    // SPDM — must accept all three when MEAS_CAP != 0.
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
    let mut ecdh_context = pal.alloc_bytes(io, ECDH_P384_ENCRYPTED_CONTEXT_SIZE)?;
    let mut our_exchange_data = pal.alloc_bytes(io, ECDH_P384_EXCHANGE_DATA_SIZE)?;
    pal.ecdh_generate(io, &mut ecdh_context, &mut our_exchange_data)
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;

    // Complete ECDH with peer's exchange data → DHE shared secret.
    let dhe_secret = pal
        .ecdh_finish(io, &ecdh_context, &ke_req.exchange_data)
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;

    // ── Create session ──────────────────────────────────────────────
    let session_id = match sessions.create_session(req_session_id, state.version) {
        Ok(id) => id,
        Err(e) => {
            let err = SpdmError::from(e);
            drop(dhe_secret);
            return Err(err);
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
        sessions.remove_and_destroy(session_id);
    }

    result
}

/// Inner implementation that can fail; caller handles session cleanup.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
async fn key_exchange_inner<'a, Pal: SpdmPal, const N: usize>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
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
    our_exchange_data: &[u8],
    selected_version: &[u8; 2],
) -> SpdmResult<PalBytes<'a, Pal>> {
    let session = sessions.find_mut(session_id).ok_or(SPDM_UNSPECIFIED)?;
    let mut workspace = pal.alloc_bytes(io, KEY_EXCHANGE_WORKSPACE_SIZE)?;
    workspace.fill(0);
    let mut rest = &mut workspace[..];

    let (hash_scratch, next) = rest.split_at_mut(SHA384_HASH_SIZE);
    rest = next;
    let hash_scratch: &mut [u8; SHA384_HASH_SIZE] =
        hash_scratch.try_into().map_err(|_| SPDM_UNSPECIFIED)?;

    let (signing_ctx, next) = rest.split_at_mut(SPDM_SIGNING_CONTEXT_LEN);
    rest = next;
    let signing_ctx: &mut [u8; SPDM_SIGNING_CONTEXT_LEN] =
        signing_ctx.try_into().map_err(|_| SPDM_UNSPECIFIED)?;

    let (nonce, next) = rest.split_at_mut(KEY_EXCHANGE_RANDOM_DATA_LEN);
    rest = next;
    let nonce: &mut [u8; KEY_EXCHANGE_RANDOM_DATA_LEN] =
        nonce.try_into().map_err(|_| SPDM_UNSPECIFIED)?;

    let (meas_summary_hash, next) = rest.split_at_mut(SHA384_HASH_SIZE);
    rest = next;
    let meas_summary_hash: &mut [u8; SHA384_HASH_SIZE] =
        meas_summary_hash.try_into().map_err(|_| SPDM_UNSPECIFIED)?;

    let (opaque_buf, next) = rest.split_at_mut(OPAQUE_VERSION_SELECTION_SIZE);
    rest = next;

    let (signature, next) = rest.split_at_mut(ECC_P384_SIGNATURE_SIZE);
    rest = next;

    let (verify_data, rest) = rest.split_at_mut(SHA384_HASH_SIZE);
    let verify_data: &mut [u8; SHA384_HASH_SIZE] =
        verify_data.try_into().map_err(|_| SPDM_UNSPECIFIED)?;
    debug_assert!(rest.is_empty());

    session.key_schedule.set_dhe_secret(dhe_secret);

    // ── Init session TH by forking the VCA running hash ────────────
    // The VCA hash state already contains the raw VCA message bytes.
    // Cloning it avoids the incorrect hash(hash(VCA)) nesting.
    let vca_state = state.transcript.vca.as_ref().ok_or(SPDM_UNSPECIFIED)?;
    session.transcript.init_from_running(pal, io, vca_state)?;

    // ── Cert chain hash ─────────────────────────────────────────────
    let asym_algo = state.asym_algo();
    let cert_chain_hash = &mut *hash_scratch;
    if let Some(cached) = pal.cached_chain_digest(slot_id, SpdmPalHashAlgo::Sha384) {
        cert_chain_hash.copy_from_slice(&cached);
    } else {
        crate::digests::cert_chain_hash(
            pal,
            io,
            slot_id,
            asym_algo,
            SpdmPalHashAlgo::Sha384,
            cert_chain_hash,
        )
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;
        pal.cache_chain_digest(slot_id, SpdmPalHashAlgo::Sha384, cert_chain_hash);
    }

    // ── Feed TH: cert_chain_hash ────────────────────────────────────
    session.transcript.append(pal, io, cert_chain_hash).await?;

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
    pal.generate_nonce(io, nonce)
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;

    let meas_hash_ref: Option<&[u8; SHA384_HASH_SIZE]> = if meas_hash_type != 0 {
        crate::measurements::measurement_summary_hash(pal, io, meas_hash_type, meas_summary_hash)
            .await?;
        Some(&*meas_summary_hash)
    } else {
        None
    };

    // ── Encode opaque version selection ─────────────────────────────
    encode_version_selection(*selected_version, opaque_buf).map_err(|_| SPDM_UNSPECIFIED)?;

    // ── Build partial response (no signature, no verify_data) ───────
    let partial_body = KeyExchangeRsp {
        rsp_session_id,
        random_data: nonce,
        exchange_data: our_exchange_data.try_into().map_err(|_| SPDM_UNSPECIFIED)?,
        meas_summary_hash: meas_hash_ref,
        opaque_data: opaque_buf,
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
    let th1 = &mut *hash_scratch;
    session.transcript.clone_and_finalize(pal, io, th1).await?;

    // ── Sign TH1 ────────────────────────────────────────────────────
    build_signing_context(state.version, signing_ctx);
    compute_tbs_hash(pal, io, signing_ctx, th1)
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;
    let tbs_hash = &signing_ctx[..SHA384_HASH_SIZE];

    let sig_len = pal
        .sign_hash(io, slot_id, asym_algo, tbs_hash, signature)
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;
    if sig_len != ECC_P384_SIGNATURE_SIZE {
        return Err(SPDM_UNSPECIFIED);
    }

    // ── Feed signature to TH ────────────────────────────────────────
    session.transcript.append(pal, io, signature).await?;

    // ── TH1' = clone-and-finalize (for HMAC + key derivation) ──────
    let th1_prime = &mut *hash_scratch;
    session
        .transcript
        .clone_and_finalize(pal, io, th1_prime)
        .await?;

    // ── Derive handshake keys ───────────────────────────────────────
    session
        .key_schedule
        .generate_handshake_keys(pal, io, th1_prime)
        .await?;

    // ── Compute responder verify_data ───────────────────────────────
    let vd_len = session
        .key_schedule
        .hmac_finished(
            pal,
            io,
            SessionKeyType::ResponseFinishedKey,
            th1_prime,
            verify_data,
        )
        .await?;
    if vd_len != SHA384_HASH_SIZE {
        return Err(SPDM_UNSPECIFIED);
    }

    // Feed verify_data to TH (state persists for FINISH phase).
    session.transcript.append(pal, io, verify_data).await?;

    // ── Build full response ─────────────────────────────────────────
    let full_body = KeyExchangeRsp {
        rsp_session_id,
        random_data: nonce,
        exchange_data: our_exchange_data.try_into().map_err(|_| SPDM_UNSPECIFIED)?,
        meas_summary_hash: meas_hash_ref,
        opaque_data: opaque_buf,
        signature,
        responder_verify_data: Some(verify_data),
    };

    let full_resp =
        build_response(pal, io, state.version, &full_body).map_err(|_| SPDM_UNSPECIFIED)?;

    Ok(full_resp)
}

// ── Signing helpers ─────────────────────────────────────────────────

fn build_signing_context(version: SpdmVersion, ctx: &mut [u8; SPDM_SIGNING_CONTEXT_LEN]) {
    let prefix = match version {
        SpdmVersion::V10 => KEY_EXCHANGE_SIGNING_PREFIX_V10,
        SpdmVersion::V11 => KEY_EXCHANGE_SIGNING_PREFIX_V11,
        SpdmVersion::V12 => KEY_EXCHANGE_SIGNING_PREFIX_V12,
        SpdmVersion::V13 => KEY_EXCHANGE_SIGNING_PREFIX_V13,
    };
    for dst in ctx[..SPDM_PREFIX_LEN].chunks_exact_mut(KEY_EXCHANGE_SIGNING_PREFIX_CHUNK_LEN) {
        dst.copy_from_slice(prefix);
    }

    ctx[SPDM_PREFIX_LEN] = 0;
    ctx[SPDM_PREFIX_LEN + 1] = 0;
    ctx[SPDM_PREFIX_LEN + 2..].copy_from_slice(KEY_EXCHANGE_SIGNING_OP);
}

async fn compute_tbs_hash<Pal: SpdmPal>(
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    signing_ctx: &mut [u8; SPDM_SIGNING_CONTEXT_LEN],
    th_hash: &[u8; SHA384_HASH_SIZE],
) -> mcu_error::McuResult<()> {
    let mut state = pal
        .hash_init(io, SpdmPalHashAlgo::Sha384, &*signing_ctx)
        .await?;
    pal.hash_update(io, &mut state, th_hash).await?;
    pal.hash_finish(io, &mut state, &mut signing_ctx[..SHA384_HASH_SIZE])
        .await?;
    Ok(())
}
