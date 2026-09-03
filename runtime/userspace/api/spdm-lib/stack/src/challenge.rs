// Licensed under the Apache-2.0 license

//! CHALLENGE / CHALLENGE_AUTH handler.

use caliptra_mcu_spdm_codec::{
    ChallengeAuthRsp, ChallengeReqBody, ResponseBody, SpdmMsgHdrPdu, SpdmVersion, WireWriter,
    REQUESTER_CONTEXT_LEN, SHA384_HASH_SIZE, SPDM_CONTEXT_LEN, SPDM_PREFIX_LEN,
    SPDM_SIGNING_CONTEXT_LEN,
};
use caliptra_mcu_spdm_traits::SpdmPalAlloc;
use caliptra_mcu_spdm_traits::*;
use zerocopy::FromBytes;

use crate::chunk;
use crate::error::{SpdmResult, SPDM_INVALID_REQUEST, SPDM_UNEXPECTED_REQUEST, SPDM_UNSPECIFIED};
use crate::stack::{ConnectionState, Phase};

pub(crate) async fn handle_challenge<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
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
        let ctx = *after
            .first_chunk::<REQUESTER_CONTEXT_LEN>()
            .ok_or(SPDM_INVALID_REQUEST)?;
        requester_context = Some(ctx);
    }

    // Append CHALLENGE request to M1 transcript.
    state.transcript.append_m1(pal, io, req).await?;

    let asym_algo = state.asym_algo();

    // Get cert chain hash — use cache if available, else compute.
    let mut cert_chain_hash = [0u8; SHA384_HASH_SIZE];
    if let Some(cached) = pal.cached_chain_digest(slot_id, asym_algo, SpdmPalHashAlgo::Sha384) {
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
        pal.cache_chain_digest(
            slot_id,
            asym_algo,
            SpdmPalHashAlgo::Sha384,
            &cert_chain_hash,
        );
    }

    // Generate nonce via PAL RNG.
    let mut nonce = [0u8; SPDM_NONCE_LEN];
    pal.generate_nonce(io, &mut nonce)
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;

    let mut meas_summary_hash = [0u8; SHA384_HASH_SIZE];
    if meas_hash_type != 0 {
        crate::measurements::measurement_summary_hash(
            pal,
            io,
            meas_hash_type,
            &mut meas_summary_hash,
        )
        .await?;
    }
    let signature_len = asym_algo.signature_size();
    let (body, no_sig_len) = {
        let meas_hash_ref = if meas_hash_type != 0 {
            Some(&meas_summary_hash)
        } else {
            None
        };
        let body = ChallengeAuthRsp {
            slot_id,
            cert_chain_hash: &cert_chain_hash,
            nonce: &nonce,
            meas_summary_hash: meas_hash_ref,
            opaque_len: 0,
            requester_context: requester_context.as_ref(),
            signature: &[],
        };
        let no_sig_len = body.encoded_size();
        (body, no_sig_len)
    };

    let head = pal.header_size();
    let spdm_len = no_sig_len
        .checked_add(signature_len)
        .ok_or(SPDM_UNSPECIFIED)?;
    let raw_len = head.checked_add(spdm_len).ok_or(SPDM_UNSPECIFIED)?;
    let padded_len = align_send_len(pal, raw_len)?;
    let mut guard = chunk::WipeOnDrop {
        buf: Some(pal.alloc_large_buf(padded_len)?),
    };
    let resp = guard.buf.as_mut().ok_or(SPDM_UNSPECIFIED)?;
    body.encode_with_header(
        state.version,
        &mut WireWriter::new(&mut resp[head..head + no_sig_len]),
    )
    .map_err(|_| SPDM_UNSPECIFIED)?;

    // Append CHALLENGE_AUTH response (without signature) to M1.
    // Only the SPDM message bytes, not transport padding.
    let prefix = resp.get(head..head + no_sig_len).ok_or(SPDM_UNSPECIFIED)?;
    state.transcript.append_m1(pal, io, prefix).await?;

    // Finalize M1 transcript hash.
    let mut m1_hash = [0u8; SHA384_HASH_SIZE];
    state.transcript.finalize_m1(pal, io, &mut m1_hash).await?;

    // Sign directly into the response's signature slot.
    let sig_slot = resp
        .get_mut(head + no_sig_len..head + no_sig_len + signature_len)
        .ok_or(SPDM_UNSPECIFIED)?;
    let signing_ctx = signing_context(state.version);
    let mut mldsa_message = [0u8; SPDM_SIGNING_CONTEXT_LEN + SHA384_HASH_SIZE];
    let signing_input = match asym_algo {
        SpdmPalAsymAlgo::EccP384 => {
            compute_tbs_hash(pal, io, signing_ctx, &mut m1_hash)
                .await
                .map_err(|_| SPDM_UNSPECIFIED)?;
            SigningInput::EccP384Digest(&m1_hash)
        }
        SpdmPalAsymAlgo::MlDsa87 => {
            mldsa_message[..SPDM_SIGNING_CONTEXT_LEN].copy_from_slice(signing_ctx);
            mldsa_message[SPDM_SIGNING_CONTEXT_LEN..].copy_from_slice(&m1_hash);
            SigningInput::Mldsa87Message {
                context: CHALLENGE_AUTH_SIGNING_CONTEXT,
                message: &mldsa_message,
            }
        }
    };
    let sig_len = pal
        .sign(io, slot_id, asym_algo, signing_input, sig_slot)
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;
    if sig_len != signature_len {
        return Err(SPDM_UNSPECIFIED);
    }

    let use_normal_response = spdm_len <= state.effective_data_transfer_size(pal);
    if use_normal_response {
        resp[raw_len..padded_len].fill(0);
        let final_buf = guard.buf.take().ok_or(SPDM_UNSPECIFIED)?;
        let response = pal
            .large_buf_into_bytes(final_buf, padded_len)
            .map_err(|_| SPDM_UNSPECIFIED)?;
        state.phase = Phase::AfterCertificate; // TODO: add Phase::Authenticated
        return Ok(response);
    }

    chunk::validate_buffered_large_response_with_capacity(
        state,
        spdm_len,
        pal.large_buffered_msg_capacity(),
    )?;
    resp.copy_within(head..head + spdm_len, 0);
    let final_buf = guard.buf.take().ok_or(SPDM_UNSPECIFIED)?;
    state.large_msg_ctx.set_buffer(final_buf);
    match chunk::start_buffered_large_response(state, pal, io, spdm_len) {
        Ok((response, _)) => {
            state.phase = Phase::AfterCertificate; // TODO: add Phase::Authenticated
            Ok(response)
        }
        Err(err) => {
            state.large_msg_ctx.reset();
            Err(err)
        }
    }
}

const CHALLENGE_AUTH_SIGNING_CONTEXT: &[u8] = b"responder-challenge_auth signing";

fn align_send_len<Pal: SpdmPal>(pal: &Pal, len: usize) -> SpdmResult<usize> {
    let align = pal.send_len_alignment();
    if align == 0 {
        return Err(SPDM_UNSPECIFIED);
    }
    len.checked_add(align - 1)
        .map(|n| n / align * align)
        .ok_or(SPDM_UNSPECIFIED)
}

const SIGNING_CTX_V10: [u8; SPDM_SIGNING_CONTEXT_LEN] = build_signing_context(b"1.0.*");
const SIGNING_CTX_V11: [u8; SPDM_SIGNING_CONTEXT_LEN] = build_signing_context(b"1.1.*");
const SIGNING_CTX_V12: [u8; SPDM_SIGNING_CONTEXT_LEN] = build_signing_context(b"1.2.*");
const SIGNING_CTX_V13: [u8; SPDM_SIGNING_CONTEXT_LEN] = build_signing_context(b"1.3.*");
const SIGNING_CTX_V14: [u8; SPDM_SIGNING_CONTEXT_LEN] = build_signing_context(b"1.4.*");

/// Build the SPDM signing context for CHALLENGE_AUTH.
const fn build_signing_context(ver: &[u8; 5]) -> [u8; SPDM_SIGNING_CONTEXT_LEN] {
    let mut ctx = [0u8; SPDM_SIGNING_CONTEXT_LEN];

    // Prefix: "dmtf-spdm-v" + version + ".*" repeated 4× = 64 bytes.
    let base = b"dmtf-spdm-v";
    let mut repeat = 0;
    let mut pos = 0;
    while repeat < 4 {
        let mut i = 0;
        while i < base.len() {
            ctx[pos + i] = base[i];
            i += 1;
        }
        pos += base.len();
        let mut j = 0;
        while j < ver.len() {
            ctx[pos + j] = ver[j];
            j += 1;
        }
        pos += ver.len();
        repeat += 1;
    }

    // Operation context: zero-padded on the left, string at the end.
    let op = b"responder-challenge_auth signing";
    let pad = SPDM_CONTEXT_LEN - op.len();
    let mut k = 0;
    while k < op.len() {
        ctx[SPDM_PREFIX_LEN + pad + k] = op[k];
        k += 1;
    }

    ctx
}

fn signing_context(version: SpdmVersion) -> &'static [u8; SPDM_SIGNING_CONTEXT_LEN] {
    match version {
        SpdmVersion::V10 => &SIGNING_CTX_V10,
        SpdmVersion::V11 => &SIGNING_CTX_V11,
        SpdmVersion::V12 => &SIGNING_CTX_V12,
        SpdmVersion::V13 => &SIGNING_CTX_V13,
        SpdmVersion::V14 => &SIGNING_CTX_V14,
    }
}

/// Hash(signing_context || M1_hash) → TBS digest for signing.
async fn compute_tbs_hash<Pal: SpdmPal>(
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    signing_ctx: &[u8; SPDM_SIGNING_CONTEXT_LEN],
    m1_hash: &mut [u8; SHA384_HASH_SIZE],
) -> mcu_error::McuResult<()> {
    let mut state = pal
        .hash_init(io, SpdmPalHashAlgo::Sha384, signing_ctx)
        .await?;
    pal.hash_update(io, &mut state, m1_hash).await?;
    pal.hash_finish(io, &mut state, m1_hash).await
}

#[cfg(test)]
#[allow(clippy::duplicate_mod)]
#[path = "tests/support.rs"]
mod support;

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use caliptra_mcu_spdm_codec::{CapFlags, PqcAsymAlgos, ReqRespCode};
    use futures::executor::block_on;
    use std::vec;

    #[test]
    fn mldsa87_challenge_auth_is_returned_as_a_large_response() {
        let pal = support::TestPal {
            mtu: 1024,
            large_buffered_msg_capacity: 8192,
            ..Default::default()
        };
        let mut state = support::negotiated_state(SpdmVersion::V14);
        state.negotiated_base_asym_sel = caliptra_mcu_spdm_codec::AsymAlgos::EMPTY;
        state.negotiated_pqc_asym_sel = PqcAsymAlgos::ML_DSA_87;
        state.peer_cap_flags = CapFlags::CHUNK;
        state.peer_data_transfer_size = 1024;
        state.peer_max_spdm_msg_size = 8192;

        let mut request = vec![SpdmVersion::V14.to_u8(), ReqRespCode::CHALLENGE.0, 0, 0];
        request.extend_from_slice(&[0xA5; SPDM_NONCE_LEN]);
        request.extend_from_slice(&[0x5A; REQUESTER_CONTEXT_LEN]);
        let io = support::TestIo::message(request);
        block_on(state.transcript.append_vca(&pal, &io, b"vca")).unwrap();

        let error = block_on(handle_challenge(&mut state, &pal, &io)).unwrap();
        assert_eq!(error[1], ReqRespCode::ERROR.0);
        let handle = *error.last().unwrap();
        let response = block_on(support::drain_chunked_response(
            &mut state, &pal, &io, handle,
        ))
        .unwrap();

        assert_eq!(response[1], ReqRespCode::CHALLENGE_AUTH.0);
        assert_eq!(
            response.len(),
            2 + 2 + 48 + 32 + 2 + REQUESTER_CONTEXT_LEN + 4627
        );
        assert!(response[response.len() - 4627..]
            .iter()
            .all(|byte| *byte == 0x77));
        let sign_op = pal.sign_op.borrow();
        let support::SignOp::Mldsa87Message { context, message } = sign_op.as_ref().unwrap() else {
            panic!("expected ML-DSA message signing input");
        };
        assert_eq!(context, CHALLENGE_AUTH_SIGNING_CONTEXT);
        assert_eq!(message.len(), SPDM_SIGNING_CONTEXT_LEN + SHA384_HASH_SIZE);
        assert_eq!(
            &message[..SPDM_SIGNING_CONTEXT_LEN],
            signing_context(SpdmVersion::V14)
        );
        assert_ne!(
            &message[SPDM_SIGNING_CONTEXT_LEN..],
            vec![0; SHA384_HASH_SIZE]
        );
    }
}
