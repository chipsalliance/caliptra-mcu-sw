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

use caliptra_mcu_spdm_codec::{
    encode_version_selection, parse_supported_versions, select_version, KeyExSel, KeyExchangeReq,
    KeyExchangeRsp, ResponseBody, SpdmMsgHdrPdu, WireWriter, ECDH_P384_EXCHANGE_DATA_SIZE,
    KEY_EXCHANGE_RANDOM_DATA_LEN, ML_KEM_1024_EXCHANGE_DATA_SIZE, OPAQUE_VERSION_SELECTION_SIZE,
    SHA384_HASH_SIZE,
};
use caliptra_mcu_spdm_traits::*;
use mcu_caliptra_api::{MLKEM1024_CIPHERTEXT_SIZE, MLKEM1024_ENCAPS_KEY_SIZE};
use zerocopy::FromBytes;

// Cross-check wire-format constants against the mailbox API.
const _: () = assert!(ML_KEM_1024_EXCHANGE_DATA_SIZE == MLKEM1024_ENCAPS_KEY_SIZE);
const _: () = assert!(ML_KEM_1024_EXCHANGE_DATA_SIZE == MLKEM1024_CIPHERTEXT_SIZE);

use crate::build::{align_send_len, sign_transcript};
use crate::chunk::{self, WipeOnDrop};
use crate::error::{
    SpdmError, SpdmResult, SPDM_INVALID_REQUEST, SPDM_UNEXPECTED_REQUEST, SPDM_UNSPECIFIED,
};
use crate::key_schedule::SessionKeyType;
use crate::stack::{ConnState, Phase, Sessions};

const ECDH_P384_ENCRYPTED_CONTEXT_SIZE: usize = 76;

/// Workspace allocation for KEY_EXCHANGE handler.
///
/// Covers: hash scratch, nonce, measurement summary hash, opaque data, verify_data.
/// The signature is allocated directly into the response buffer's signature slot.
const KEY_EXCHANGE_WORKSPACE_SIZE: usize = SHA384_HASH_SIZE
    + KEY_EXCHANGE_RANDOM_DATA_LEN
    + SHA384_HASH_SIZE
    + OPAQUE_VERSION_SELECTION_SIZE
    + SHA384_HASH_SIZE;

/// FIPS 204 signing context for KEY_EXCHANGE_RSP.
const KEY_EXCHANGE_SIGNING_OP: &[u8; 34] = b"responder-key_exchange_rsp signing";

pub(crate) async fn handle_key_exchange<'a, Pal: SpdmPal, const N: usize>(
    state: &mut ConnState<'_, Pal>,
    sessions: &mut Sessions<Pal, N>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
) -> SpdmResult<PalBytes<'a, Pal>> {
    let (resp, _spdm_len) = handle_key_exchange_req(state, sessions, pal, io, io.request()).await?;
    Ok(resp)
}

/// Handle KEY_EXCHANGE request with explicit request bytes.
///
/// Separated from `handle_key_exchange` to support both direct dispatch and
/// reassembled `CHUNK_SEND` paths.
pub(crate) async fn handle_key_exchange_req<'a, Pal: SpdmPal, const N: usize>(
    state: &mut ConnState<'_, Pal>,
    sessions: &mut Sessions<Pal, N>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    req: &[u8],
) -> SpdmResult<(PalBytes<'a, Pal>, usize)> {
    // ── Phase check ─────────────────────────────────────────────────
    if (state.phase as u8) < (Phase::AfterAlgorithms as u8) {
        return Err(SPDM_UNEXPECTED_REQUEST);
    }

    // Only one handshake at a time.
    if sessions.has_handshake_in_progress() {
        return Err(SPDM_UNEXPECTED_REQUEST);
    }

    // ── Parse request ───────────────────────────────────────────────
    let (hdr, rest) = SpdmMsgHdrPdu::ref_from_prefix(req).map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != state.version.to_u8() {
        return Err(crate::error::SPDM_VERSION_MISMATCH);
    }

    // Resolve the expected exchange data size from the negotiated key exchange selection.
    let exchange_data_size = state
        .negotiated_key_ex_sel
        .exchange_data_size()
        .ok_or(SPDM_UNEXPECTED_REQUEST)?;

    let ke_req =
        KeyExchangeReq::parse(rest, exchange_data_size).map_err(|_| SPDM_INVALID_REQUEST)?;

    let slot_id = ke_req.fixed.slot_id & 0x0F;
    let meas_hash_type = ke_req.fixed.meas_summary_hash_type;
    let req_session_id = ke_req.fixed.req_session_id_u16();

    // Validate slot_id.
    if slot_id >= MAX_SLOTS || (pal.provisioned_slots(state.asym_algo()) & (1 << slot_id)) == 0 {
        return Err(SPDM_INVALID_REQUEST);
    }

    // Validate meas_summary_hash_type: 0 (none), 1 (TCB), or 0xFF (all).
    // SPDM — must accept all three when MEAS_CAP != 0.
    if meas_hash_type != 0 && meas_hash_type != 1 && meas_hash_type != 0xFF {
        return Err(SPDM_INVALID_REQUEST);
    }

    // Select secured-message version from requester's list.
    let supported =
        parse_supported_versions(ke_req.opaque_data).map_err(|_| SPDM_INVALID_REQUEST)?;
    let selected_version = select_version(&supported).map_err(|_| SPDM_INVALID_REQUEST)?;

    // ── Key exchange (DHE/KEM) ──────────────────────────────────────
    let (our_exchange_data, shared_secret) =
        generate_key_exchange_secret(state, pal, io, ke_req.exchange_data).await?;

    // ── Create session ──────────────────────────────────────────────
    let session_id = match sessions.create_session(req_session_id, state.version, |info| {
        pal.alloc_persistent(info)
    }) {
        Ok(id) => id,
        Err(e) => {
            let err = SpdmError::from(e);
            drop(shared_secret);
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
        &ke_req,
        slot_id,
        meas_hash_type,
        session_id,
        rsp_session_id,
        shared_secret,
        &our_exchange_data,
        &selected_version,
    )
    .await;

    if result.is_err() {
        sessions.remove_and_destroy(session_id);
    }

    result
}

/// Generate key exchange data and compute shared secret.
///
/// # Arguments
/// * `state` - Connection state containing the negotiated key exchange selection
/// * `pal` - Platform abstraction layer for cryptographic operations
/// * `io` - I/O context for memory allocation
/// * `peer_exchange_data` - The peer's public key exchange data from the request
///
/// # Returns
/// A tuple containing:
/// - Our public exchange data to send to the peer
/// - The computed shared secret
///
/// # Errors
/// Returns `SPDM_UNEXPECTED_REQUEST` if no key exchange algorithm was negotiated.
/// Returns `SPDM_UNSPECIFIED` if cryptographic operations fail.
async fn generate_key_exchange_secret<'a, Pal: SpdmPal>(
    state: &ConnState<'_, Pal>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    peer_exchange_data: &[u8],
) -> SpdmResult<(PalBytes<'a, Pal>, <Pal as SpdmPalSessionCrypto>::Key)> {
    match state.negotiated_key_ex_sel {
        KeyExSel::None => Err(SPDM_UNEXPECTED_REQUEST),
        KeyExSel::Dhe => {
            // Validate peer exchange data length before ECDH operations.
            if peer_exchange_data.len() != ECDH_P384_EXCHANGE_DATA_SIZE {
                return Err(SPDM_INVALID_REQUEST);
            }

            // ECDH P-384 key generation
            let mut ecdh_context = pal.alloc_bytes(io, ECDH_P384_ENCRYPTED_CONTEXT_SIZE)?;
            let mut our_exchange_data = pal.alloc_bytes(io, ECDH_P384_EXCHANGE_DATA_SIZE)?;
            pal.ecdh_generate(io, &mut ecdh_context, &mut our_exchange_data)
                .await
                .map_err(|_| SPDM_UNSPECIFIED)?;

            // Complete ECDH with peer's exchange data → DHE shared secret.
            let dhe_secret = pal
                .ecdh_finish(io, &ecdh_context, peer_exchange_data)
                .await
                .map_err(|_| SPDM_UNSPECIFIED)?;

            Ok((our_exchange_data, dhe_secret))
        }
        KeyExSel::Kem => {
            // Validate peer encapsulation key length before ML-KEM operations.
            if peer_exchange_data.len() != MLKEM1024_ENCAPS_KEY_SIZE {
                return Err(SPDM_INVALID_REQUEST);
            }

            let mut ciphertext = pal.alloc_bytes(io, MLKEM1024_CIPHERTEXT_SIZE)?;
            let kem_secret = pal
                .mlkem_encapsulate(io, peer_exchange_data, &mut ciphertext)
                .await
                .map_err(|_| SPDM_UNSPECIFIED)?;
            Ok((ciphertext, kem_secret))
        }
    }
}

/// Inner implementation that can fail; caller handles session cleanup.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
async fn key_exchange_inner<'a, Pal: SpdmPal, const N: usize>(
    state: &mut ConnState<'_, Pal>,
    sessions: &mut Sessions<Pal, N>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    req: &[u8],
    ke_req: &KeyExchangeReq<'_>,
    slot_id: u8,
    meas_hash_type: u8,
    session_id: u32,
    rsp_session_id: u16,
    shared_secret: <Pal as SpdmPalSessionCrypto>::Key,
    our_exchange_data: &[u8],
    selected_version: &[u8; 2],
) -> SpdmResult<(PalBytes<'a, Pal>, usize)> {
    let session = sessions.find_mut(session_id).ok_or(SPDM_UNSPECIFIED)?;
    let mut workspace = pal.alloc_bytes(io, KEY_EXCHANGE_WORKSPACE_SIZE)?;
    workspace.fill(0);
    let mut rest = &mut workspace[..];

    let (hash_scratch, next) = rest.split_at_mut(SHA384_HASH_SIZE);
    rest = next;
    let hash_scratch: &mut [u8; SHA384_HASH_SIZE] =
        hash_scratch.try_into().map_err(|_| SPDM_UNSPECIFIED)?;

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

    let (_verify_data, rest) = rest.split_at_mut(SHA384_HASH_SIZE);
    debug_assert!(rest.is_empty());

    session.key_schedule.set_shared_secret(shared_secret);

    // ── Init session TH by forking the VCA running hash ────────────
    // The VCA hash state already contains the raw VCA message bytes.
    // Cloning it avoids the incorrect hash(hash(VCA)) nesting.
    let vca_state = state.transcript.vca.as_ref().ok_or(SPDM_UNSPECIFIED)?;
    session.transcript.init_from_running(pal, io, vca_state)?;

    // ── Cert chain hash ─────────────────────────────────────────────
    let asym_algo = state.asym_algo();
    let cert_chain_hash = &mut *hash_scratch;
    if let Some(cached) = pal.cached_chain_digest(slot_id, asym_algo, SpdmPalHashAlgo::Sha384) {
        *cert_chain_hash = cached;
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
        pal.cache_chain_digest(slot_id, asym_algo, SpdmPalHashAlgo::Sha384, cert_chain_hash);
    }

    // ── Feed TH: cert_chain_hash ────────────────────────────────────
    session.transcript.append(pal, io, cert_chain_hash).await?;

    // ── Feed TH: full KEY_EXCHANGE request ──────────────────────────
    // Use only the actual SPDM bytes (not transport padding).
    let spdm_req_len = SpdmMsgHdrPdu::SIZE + ke_req.encoded_len();
    let spdm_req = req.get(..spdm_req_len).ok_or(SPDM_INVALID_REQUEST)?;
    session.transcript.append(pal, io, spdm_req).await?;

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

    // ── Determine response size and allocate large buffer ──────────
    let asym_algo = state.asym_algo();
    let sig_len = asym_algo.signature_size();

    // Build partial response body to calculate size without signature/verify_data.
    let no_sig_body = KeyExchangeRsp {
        rsp_session_id,
        random_data: nonce,
        exchange_data: our_exchange_data,
        meas_summary_hash: meas_hash_ref,
        opaque_data: opaque_buf,
        signature: &[],
        responder_verify_data: None,
    };
    let no_sig_len = no_sig_body.encoded_size();
    let spdm_len = no_sig_len
        .checked_add(sig_len)
        .and_then(|n| n.checked_add(SHA384_HASH_SIZE))
        .ok_or(SPDM_UNSPECIFIED)?;

    let head = pal.header_size();
    let raw_len = head.checked_add(spdm_len).ok_or(SPDM_UNSPECIFIED)?;
    let padded_len = align_send_len(pal, raw_len)?;

    // Reject undeliverable response before crypto operations (pre-flight check).
    let use_normal_response = spdm_len <= state.effective_data_transfer_size(pal);
    if !use_normal_response {
        chunk::validate_buffered_large_response_with_capacity(
            state,
            spdm_len,
            pal.large_buffered_msg_capacity(),
        )?;
    }

    let mut guard = WipeOnDrop {
        buf: Some(pal.alloc_large_buf(padded_len)?),
    };
    let resp = guard.buf.as_mut().ok_or(SPDM_UNSPECIFIED)?;

    // ── Encode partial response (no signature, no verify_data) ─────
    let body_slot = resp
        .get_mut(head..head + no_sig_len)
        .ok_or(SPDM_UNSPECIFIED)?;
    no_sig_body
        .encode_with_header(state.version, &mut WireWriter::new(body_slot))
        .map_err(|_| SPDM_UNSPECIFIED)?;

    // Feed partial response (SPDM bytes only) to TH.
    let partial_spdm = resp.get(head..head + no_sig_len).ok_or(SPDM_UNSPECIFIED)?;
    session.transcript.append(pal, io, partial_spdm).await?;

    // ── TH1 = clone-and-finalize (for signing) ─────────────────────
    let th1 = &mut *hash_scratch;
    session.transcript.clone_and_finalize(pal, io, th1).await?;

    // ── Sign TH1 directly into response buffer ─────────────────────
    let sig_slot = resp
        .get_mut(head + no_sig_len..head + no_sig_len + sig_len)
        .ok_or(SPDM_UNSPECIFIED)?;
    sign_transcript(
        pal,
        io,
        slot_id,
        asym_algo,
        state.version,
        KEY_EXCHANGE_SIGNING_OP,
        th1,
        sig_slot,
        sig_len,
    )
    .await?;

    // ── Feed signature to TH ────────────────────────────────────────
    session.transcript.append(pal, io, sig_slot).await?;

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

    // ── Compute responder verify_data directly into response buffer ─
    let vd_slot = resp
        .get_mut(head + no_sig_len + sig_len..head + no_sig_len + sig_len + SHA384_HASH_SIZE)
        .ok_or(SPDM_UNSPECIFIED)?;
    let vd_len = session
        .key_schedule
        .hmac_finished(
            pal,
            io,
            SessionKeyType::ResponseFinishedKey,
            th1_prime,
            vd_slot,
        )
        .await?;
    if vd_len != SHA384_HASH_SIZE {
        return Err(SPDM_UNSPECIFIED);
    }

    // Feed verify_data to TH (state persists for FINISH phase).
    session.transcript.append(pal, io, vd_slot).await?;

    // ── Finish response: convert to normal or start chunking ───────
    let (resp, returned_len) = guard.finish_response(state, pal, io, head, spdm_len)?;
    Ok((resp, returned_len))
}
