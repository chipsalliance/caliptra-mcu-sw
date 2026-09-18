// Licensed under the Apache-2.0 license

//! CHALLENGE / CHALLENGE_AUTH handler.

use caliptra_mcu_spdm_codec::{
    ChallengeAuthRsp, ChallengeReqBody, ResponseBody, SpdmMsgHdrPdu, SpdmVersion, WireWriter,
    REQUESTER_CONTEXT_LEN, SHA384_HASH_SIZE,
};
use caliptra_mcu_spdm_traits::SpdmPalAlloc;
use caliptra_mcu_spdm_traits::*;
use zerocopy::FromBytes;

use crate::build::{align_send_len, finish_buffered_response, sign_transcript};
use crate::chunk;
use crate::error::{SpdmResult, SPDM_INVALID_REQUEST, SPDM_UNEXPECTED_REQUEST, SPDM_UNSPECIFIED};
use crate::stack::{ConnectionState, Phase};

#[inline(never)]
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
    let body = {
        let meas_hash_ref = if meas_hash_type != 0 {
            Some(&meas_summary_hash)
        } else {
            None
        };
        ChallengeAuthRsp {
            slot_id,
            cert_chain_hash: &cert_chain_hash,
            nonce: &nonce,
            meas_summary_hash: meas_hash_ref,
            opaque_len: 0,
            requester_context: requester_context.as_ref(),
            // Sized separately below: an ML-DSA-87 signature is 4627 bytes, so
            // the response is laid out in a large buffer and may need chunking.
            signature: &[],
        }
    };
    let no_sig_len = body.encoded_size();

    let head = pal.header_size();
    let spdm_len = no_sig_len
        .checked_add(signature_len)
        .ok_or(SPDM_UNSPECIFIED)?;
    let raw_len = head.checked_add(spdm_len).ok_or(SPDM_UNSPECIFIED)?;
    let padded_len = align_send_len(pal, raw_len)?;

    // Reject an undeliverable response before signing. An ML-DSA-87 signature
    // always pushes CHALLENGE_AUTH past the MTU, so a requester that negotiates
    // PQC without CHUNK would otherwise force a full CertifyKey + Sign — and two
    // DPE handle rotations — per request only to discard the result.
    let use_normal_response = spdm_len <= state.effective_data_transfer_size(pal);
    if !use_normal_response {
        chunk::validate_buffered_large_response_with_capacity(
            state,
            spdm_len,
            pal.large_buffered_msg_capacity(),
        )?;
    }

    let mut guard = chunk::WipeOnDrop {
        buf: Some(pal.alloc_large_buf(padded_len)?),
    };
    let resp = guard.buf.as_mut().ok_or(SPDM_UNSPECIFIED)?;
    let body_slot = resp
        .get_mut(head..head + no_sig_len)
        .ok_or(SPDM_UNSPECIFIED)?;
    body.encode_with_header(state.version, &mut WireWriter::new(body_slot))
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
    sign_transcript(
        pal,
        io,
        slot_id,
        asym_algo,
        state.version,
        CHALLENGE_AUTH_SIGNING_CONTEXT,
        &mut m1_hash,
        sig_slot,
        signature_len,
    )
    .await?;

    let (response, _) = finish_buffered_response(
        state,
        pal,
        io,
        guard,
        head,
        spdm_len,
        raw_len,
        padded_len,
        use_normal_response,
    )?;
    state.phase = Phase::AfterCertificate; // TODO: add Phase::Authenticated
    Ok(response)
}

/// FIPS 204 signing context for CHALLENGE_AUTH (DSP0274 1.4 Table 51).
const CHALLENGE_AUTH_SIGNING_CONTEXT: &[u8] = b"responder-challenge_auth signing";

#[cfg(test)]
fn signing_context(
    version: SpdmVersion,
) -> [u8; caliptra_mcu_spdm_codec::SPDM_SIGNING_CONTEXT_LEN] {
    crate::build::spdm_signing_context(version, CHALLENGE_AUTH_SIGNING_CONTEXT).unwrap()
}

#[cfg(test)]
#[path = "tests/challenge.rs"]
mod tests;
