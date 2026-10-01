// Licensed under the Apache-2.0 license

//! KEY_EXCHANGE / KEY_EXCHANGE_RSP handler.
//!
//! Implements the responder side of the SPDM key exchange:
//!
//! 1. Parse and validate the request
//! 2. Compute the optional measurement summary hash
//! 3. Generate the ECDH public value and shared secret
//! 4. Create the session and initialize its transcript
//! 5. Sign TH1 and derive handshake keys
//! 6. Compute responder verify_data
//! 7. Return the response directly or through CHUNK_GET

use caliptra_mcu_spdm_codec::{
    encode_version_selection, parse_supported_versions, select_version, HeartBeatPeriod,
    KeyExchangeReq, KeyExchangeRsp, ResponseBody, SmVersion, SpdmMsgHdrPdu, WireWriter,
    ECDH_P384_EXCHANGE_DATA_SIZE, KEY_EXCHANGE_RANDOM_DATA_LEN, KEY_EXCHANGE_RSP_FIXED_BODY_SIZE,
    OPAQUE_VERSION_SELECTION_SIZE, SHA384_HASH_SIZE,
};
use caliptra_mcu_spdm_traits::*;
use zerocopy::FromBytes;

use crate::build::{align_send_len, sign_transcript};
use crate::chunk::{self, WipeOnDrop};
use crate::error::{
    SpdmError, SpdmResult, SPDM_INVALID_REQUEST, SPDM_UNEXPECTED_REQUEST, SPDM_UNSPECIFIED,
};
use crate::key_schedule::SessionKeyType;
use crate::stack::{ConnState, Phase, Sessions};

const ECDH_P384_ENCRYPTED_CONTEXT_SIZE: usize = 76;

/// Workspace allocation for KEY_EXCHANGE.
///
/// Covers the transcript hash scratch, nonce, and opaque version selection.
/// The measurement summary is generated before the large response is rented,
/// and the signature is written directly into the response buffer.
pub(crate) const KEY_EXCHANGE_WORKSPACE_SIZE: usize =
    SHA384_HASH_SIZE + KEY_EXCHANGE_RANDOM_DATA_LEN + OPAQUE_VERSION_SELECTION_SIZE;

/// FIPS 204 signing context for KEY_EXCHANGE_RSP.
const KEY_EXCHANGE_SIGNING_OP: &[u8; 34] = b"responder-key_exchange_rsp signing";

enum KeyExchangeRequest<'req, L: core::ops::DerefMut<Target = [u8]>> {
    Borrowed(&'req [u8]),
    Buffered {
        guard: WipeOnDrop<L>,
        request_len: usize,
    },
}

impl<L: core::ops::DerefMut<Target = [u8]>> KeyExchangeRequest<'_, L> {
    fn bytes(&self) -> SpdmResult<&[u8]> {
        match self {
            Self::Borrowed(req) => Ok(req),
            Self::Buffered { guard, request_len } => guard
                .as_ref()?
                .get(..*request_len)
                .ok_or(SPDM_INVALID_REQUEST),
        }
    }
}

pub(crate) async fn handle_key_exchange<'a, Pal: SpdmPal, const N: usize>(
    state: &mut ConnState<'_, Pal>,
    sessions: &mut Sessions<Pal, N>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
) -> SpdmResult<PalBytes<'a, Pal>> {
    let (resp, _spdm_len) = handle_key_exchange_req(state, sessions, pal, io, io.request()).await?;
    Ok(resp)
}

/// Handle a KEY_EXCHANGE request with explicit request bytes.
///
/// This supports both direct dispatch and reassembled CHUNK_SEND requests.
pub(crate) async fn handle_key_exchange_req<'a, Pal: SpdmPal, const N: usize>(
    state: &mut ConnState<'_, Pal>,
    sessions: &mut Sessions<Pal, N>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    req: &[u8],
) -> SpdmResult<(PalBytes<'a, Pal>, usize)> {
    let inline_response_limit = state.effective_data_transfer_size(pal);
    handle_key_exchange_request(
        state,
        sessions,
        pal,
        io,
        KeyExchangeRequest::Borrowed(req),
        inline_response_limit,
    )
    .await
}

pub(crate) async fn handle_buffered_key_exchange_req<'a, Pal: SpdmPal, const N: usize>(
    state: &mut ConnState<'_, Pal>,
    sessions: &mut Sessions<Pal, N>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    guard: WipeOnDrop<<Pal as SpdmPalAlloc>::LargeBuf>,
    request_len: usize,
    inline_response_limit: usize,
) -> SpdmResult<(PalBytes<'a, Pal>, usize)> {
    handle_key_exchange_request(
        state,
        sessions,
        pal,
        io,
        KeyExchangeRequest::Buffered { guard, request_len },
        inline_response_limit,
    )
    .await
}

async fn handle_key_exchange_request<'a, Pal: SpdmPal, const N: usize>(
    state: &mut ConnState<'_, Pal>,
    sessions: &mut Sessions<Pal, N>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    request: KeyExchangeRequest<'_, <Pal as SpdmPalAlloc>::LargeBuf>,
    inline_response_limit: usize,
) -> SpdmResult<(PalBytes<'a, Pal>, usize)> {
    if (state.phase as u8) < (Phase::AfterAlgorithms as u8) {
        return Err(SPDM_UNEXPECTED_REQUEST);
    }

    if sessions.has_handshake_in_progress() {
        return Err(SPDM_UNEXPECTED_REQUEST);
    }

    let (
        slot_id,
        req_session_id,
        selected_version,
        spdm_req_len,
        no_sig_len,
        spdm_len,
        response_guard,
        shared_secret,
        meas_summary_hash,
        exchange_data_size,
    ) = {
        let req = request.bytes()?;
        let (hdr, rest) = SpdmMsgHdrPdu::ref_from_prefix(req).map_err(|_| SPDM_INVALID_REQUEST)?;
        if hdr.version != state.version.to_u8() {
            return Err(crate::error::SPDM_VERSION_MISMATCH);
        }

        let exchange_data_size = ECDH_P384_EXCHANGE_DATA_SIZE;
        let ke_req =
            KeyExchangeReq::parse(rest, exchange_data_size).map_err(|_| SPDM_INVALID_REQUEST)?;

        let slot_id = ke_req.fixed.slot_id & 0x0F;
        let meas_hash_type = ke_req.fixed.meas_summary_hash_type;
        let req_session_id = ke_req.fixed.req_session_id_u16();

        if slot_id >= MAX_SLOTS || (pal.provisioned_slots(state.asym_algo()) & (1 << slot_id)) == 0
        {
            return Err(SPDM_INVALID_REQUEST);
        }

        if meas_hash_type != 0 && meas_hash_type != 1 && meas_hash_type != 0xFF {
            return Err(SPDM_INVALID_REQUEST);
        }

        let selected_version = if ke_req.opaque_data.is_empty() {
            None
        } else {
            let supported =
                parse_supported_versions(ke_req.opaque_data).map_err(|_| SPDM_INVALID_REQUEST)?;
            Some(select_version(&supported).map_err(|_| SPDM_INVALID_REQUEST)?)
        };
        let spdm_req_len = SpdmMsgHdrPdu::SIZE
            .checked_add(ke_req.encoded_len())
            .ok_or(SPDM_UNSPECIFIED)?;

        let meas_hash_len = if meas_hash_type == 0 {
            0
        } else {
            SHA384_HASH_SIZE
        };
        let opaque_data_len = if selected_version.is_some() {
            OPAQUE_VERSION_SELECTION_SIZE
        } else {
            0
        };
        let no_sig_len = SpdmMsgHdrPdu::SIZE
            .checked_add(KEY_EXCHANGE_RSP_FIXED_BODY_SIZE)
            .and_then(|n| n.checked_add(exchange_data_size))
            .and_then(|n| n.checked_add(meas_hash_len))
            .and_then(|n| n.checked_add(2 + opaque_data_len))
            .ok_or(SPDM_UNSPECIFIED)?;
        let spdm_len = no_sig_len
            .checked_add(state.asym_algo().signature_size())
            .and_then(|n| n.checked_add(SHA384_HASH_SIZE))
            .ok_or(SPDM_UNSPECIFIED)?;
        let head = pal.header_size();
        let raw_len = head.checked_add(spdm_len).ok_or(SPDM_UNSPECIFIED)?;
        let padded_len = align_send_len(pal, raw_len)?;

        if spdm_len > inline_response_limit {
            chunk::validate_buffered_large_response_with_capacity(
                state,
                spdm_len,
                pal.large_buffered_msg_capacity(),
            )?;
        }

        let meas_summary_hash = if meas_hash_type != 0 {
            let mut hash = pal.alloc_bytes(io, SHA384_HASH_SIZE)?;
            let hash_out: &mut [u8; SHA384_HASH_SIZE] =
                (&mut *hash).try_into().map_err(|_| SPDM_UNSPECIFIED)?;
            crate::measurements::measurement_summary_hash(
                pal,
                io,
                state.asym_algo(),
                meas_hash_type,
                hash_out,
            )
            .await?;
            Some(hash)
        } else {
            None
        };

        let mut response_guard = WipeOnDrop {
            buf: Some(pal.alloc_large_buf(padded_len)?),
        };

        let exchange_data_start = head
            .checked_add(SpdmMsgHdrPdu::SIZE + KEY_EXCHANGE_RSP_FIXED_BODY_SIZE)
            .ok_or(SPDM_UNSPECIFIED)?;
        let exchange_data_end = exchange_data_start
            .checked_add(exchange_data_size)
            .ok_or(SPDM_UNSPECIFIED)?;
        let response_exchange_data = response_guard
            .as_mut()?
            .get_mut(exchange_data_start..exchange_data_end)
            .ok_or(SPDM_UNSPECIFIED)?;
        let shared_secret =
            generate_key_exchange_secret(pal, io, ke_req.exchange_data, response_exchange_data)
                .await?;

        (
            slot_id,
            req_session_id,
            selected_version,
            spdm_req_len,
            no_sig_len,
            spdm_len,
            response_guard,
            shared_secret,
            meas_summary_hash,
            exchange_data_size,
        )
    };

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

    let result = key_exchange_inner(
        state,
        sessions,
        pal,
        io,
        request,
        spdm_req_len,
        slot_id,
        session_id,
        rsp_session_id,
        shared_secret,
        meas_summary_hash,
        selected_version,
        response_guard,
        no_sig_len,
        spdm_len,
        exchange_data_size,
        inline_response_limit,
    )
    .await;

    if result.is_err() {
        sessions.remove_and_destroy(session_id);
    }

    result
}

async fn generate_key_exchange_secret<Pal: SpdmPal>(
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    peer_exchange_data: &[u8],
    response_exchange_data: &mut [u8],
) -> SpdmResult<<Pal as SpdmPalSessionCrypto>::Key> {
    if peer_exchange_data.len() != ECDH_P384_EXCHANGE_DATA_SIZE {
        return Err(SPDM_INVALID_REQUEST);
    }
    if response_exchange_data.len() != ECDH_P384_EXCHANGE_DATA_SIZE {
        return Err(SPDM_UNSPECIFIED);
    }

    let mut ecdh_context = pal.alloc_bytes(io, ECDH_P384_ENCRYPTED_CONTEXT_SIZE)?;
    pal.ecdh_generate(io, &mut ecdh_context, response_exchange_data)
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;
    pal.ecdh_finish(io, &ecdh_context, peer_exchange_data)
        .await
        .map_err(|_| SPDM_UNSPECIFIED)
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
async fn key_exchange_inner<'a, Pal: SpdmPal, const N: usize>(
    state: &mut ConnState<'_, Pal>,
    sessions: &mut Sessions<Pal, N>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    request: KeyExchangeRequest<'_, <Pal as SpdmPalAlloc>::LargeBuf>,
    spdm_req_len: usize,
    slot_id: u8,
    session_id: u32,
    rsp_session_id: u16,
    shared_secret: <Pal as SpdmPalSessionCrypto>::Key,
    meas_summary_hash: Option<PalBytes<'a, Pal>>,
    selected_version: Option<SmVersion>,
    mut guard: WipeOnDrop<<Pal as SpdmPalAlloc>::LargeBuf>,
    no_sig_len: usize,
    spdm_len: usize,
    exchange_data_size: usize,
    inline_response_limit: usize,
) -> SpdmResult<(PalBytes<'a, Pal>, usize)> {
    let hb_period = heartbeat_period_for::<Pal>(state);
    let session = sessions.find_mut(session_id).ok_or(SPDM_UNSPECIFIED)?;
    session.heartbeat_period = hb_period;

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

    let (opaque_buf, rest) = rest.split_at_mut(OPAQUE_VERSION_SELECTION_SIZE);
    debug_assert!(rest.is_empty());

    session.key_schedule.set_dhe_secret(shared_secret);

    let vca_state = state.transcript.vca.as_ref().ok_or(SPDM_UNSPECIFIED)?;
    session.transcript.init_from_running(pal, io, vca_state)?;

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
    session.transcript.append(pal, io, cert_chain_hash).await?;

    {
        let spdm_req = request
            .bytes()?
            .get(..spdm_req_len)
            .ok_or(SPDM_INVALID_REQUEST)?;
        session.transcript.append(pal, io, spdm_req).await?;
    }
    drop(request);

    pal.generate_nonce(io, nonce)
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;

    let opaque_data: &[u8] = if let Some(version) = selected_version {
        encode_version_selection(version, opaque_buf).map_err(|_| SPDM_UNSPECIFIED)?;
        opaque_buf
    } else {
        &[]
    };

    let sig_len = asym_algo.signature_size();
    let head = pal.header_size();
    let resp = guard.buf.as_mut().ok_or(SPDM_UNSPECIFIED)?;

    {
        let meas_hash_ref: Option<&[u8; SHA384_HASH_SIZE]> = match meas_summary_hash.as_deref() {
            Some(hash) => Some(hash.try_into().map_err(|_| SPDM_UNSPECIFIED)?),
            None => None,
        };
        let no_sig_body = KeyExchangeRsp {
            heartbeat_period: hb_period,
            rsp_session_id,
            random_data: nonce,
            exchange_data_len: exchange_data_size,
            meas_summary_hash: meas_hash_ref,
            opaque_data,
            signature: &[],
            responder_verify_data: None,
        };
        debug_assert_eq!(no_sig_body.encoded_size(), no_sig_len);

        let body_slot = resp
            .get_mut(head..head + no_sig_len)
            .ok_or(SPDM_UNSPECIFIED)?;
        no_sig_body
            .encode_with_header(state.version, &mut WireWriter::new(body_slot))
            .map_err(|_| SPDM_UNSPECIFIED)?;
    }
    drop(meas_summary_hash);

    let partial_spdm = resp.get(head..head + no_sig_len).ok_or(SPDM_UNSPECIFIED)?;
    session.transcript.append(pal, io, partial_spdm).await?;

    let th1 = &mut *hash_scratch;
    session.transcript.clone_and_finalize(pal, io, th1).await?;

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
    session.transcript.append(pal, io, sig_slot).await?;

    let th1_prime = &mut *hash_scratch;
    session
        .transcript
        .clone_and_finalize(pal, io, th1_prime)
        .await?;
    session
        .key_schedule
        .generate_handshake_keys(pal, io, th1_prime)
        .await?;

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
    session.transcript.append(pal, io, vd_slot).await?;

    let (resp, returned_len) =
        guard.finish_response_with_limit(state, pal, io, head, spdm_len, inline_response_limit)?;
    Ok((resp, returned_len))
}

/// HeartbeatPeriod to advertise in KEY_EXCHANGE_RSP for this connection.
fn heartbeat_period_for<Pal: SpdmPal>(state: &ConnState<'_, Pal>) -> HeartBeatPeriod {
    use caliptra_mcu_spdm_codec::CapFlags;
    if cfg!(feature = "spdm-set-heartbeat")
        && state.cap_flags.contains(CapFlags::HBEAT)
        && state.peer_cap_flags.contains(CapFlags::HBEAT)
    {
        HeartBeatPeriod(crate::heartbeat::DEFAULT_HEARTBEAT_PERIOD_SECS)
    } else {
        HeartBeatPeriod::DISABLED
    }
}

#[cfg(test)]
#[path = "tests/key_exchange.rs"]
mod tests;
