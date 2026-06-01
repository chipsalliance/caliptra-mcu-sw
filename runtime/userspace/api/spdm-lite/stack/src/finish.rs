// Licensed under the Apache-2.0 license

//! FINISH handler (DSP0274 §10.11.4).
//!
//! Processes the decrypted FINISH request from an SPDM secured message:
//!
//! 1. Parse and validate (no mutual auth → no signature)
//! 2. Feed FINISH header+params to TH
//! 3. Verify requester verify_data = HMAC(RequestFinishedKey, hash(TH))
//! 4. Feed verify_data + FINISH_RSP to TH
//! 5. Finalize TH2, derive data keys
//!
//! The caller is responsible for encrypting the returned SPDM response
//! with `ResponseHandshakeKey`, destroying handshake secrets, and
//! transitioning the session to [`SessionState::Established`].

use mcu_spdm_lite_codec::{
    FinishReqBody, FinishRsp, ResponseBody, SpdmMsgHdrPdu, SpdmVersion,
    SHA384_HASH_SIZE, WireWriter,
};
use mcu_spdm_lite_traits::*;
use zerocopy::FromBytes;

use crate::error::{
    SpdmResult, SPDM_DECRYPT_ERROR, SPDM_INVALID_REQUEST, SPDM_UNSPECIFIED,
};
use crate::key_schedule::SessionKeyType;
use crate::session::{SessionInfo, SessionState};

/// Size of the FINISH_RSP SPDM message (common header + 2 reserved).
pub(crate) const FINISH_RSP_SPDM_SIZE: usize = SpdmMsgHdrPdu::SIZE + 2;

/// Handle a decrypted FINISH request.
///
/// `spdm_msg` is the decrypted SPDM message (starts with the 2-byte
/// common header). On success returns the FINISH_RSP SPDM bytes and
/// derives data-phase keys.
///
/// The caller must then:
/// 1. Encrypt the response with `ResponseHandshakeKey`
/// 2. Destroy handshake secrets
/// 3. Transition session state to [`SessionState::Established`]
#[inline(never)]
pub(crate) async fn handle_finish<Pal: SpdmPal>(
    version: SpdmVersion,
    session: &mut SessionInfo<
        <Pal as SpdmPalSessionCrypto>::Key,
        Pal::State,
    >,
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    spdm_msg: &[u8],
) -> SpdmResult<[u8; FINISH_RSP_SPDM_SIZE]> {
    // ── Validate session state ──────────────────────────────────────
    if session.state != SessionState::HandshakeInProgress {
        return Err(SPDM_INVALID_REQUEST);
    }

    // ── Parse FINISH request ────────────────────────────────────────
    let (hdr, rest) = SpdmMsgHdrPdu::ref_from_prefix(spdm_msg)
        .map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != version.to_u8() {
        return Err(crate::error::SPDM_VERSION_MISMATCH);
    }

    let (finish_req, after) = FinishReqBody::ref_from_prefix(rest)
        .map_err(|_| SPDM_INVALID_REQUEST)?;

    // No mutual auth — reject if requester signature present.
    if finish_req.signature_present() {
        return Err(SPDM_INVALID_REQUEST);
    }

    // Requester verify_data (SHA-384 HMAC).
    if after.len() != SHA384_HASH_SIZE {
        return Err(SPDM_INVALID_REQUEST);
    }
    let req_verify_data = &after[..SHA384_HASH_SIZE];

    // ── Feed FINISH header + params (without verify_data) to TH ────
    let finish_hdr_len =
        SpdmMsgHdrPdu::SIZE + core::mem::size_of::<FinishReqBody>();
    session
        .transcript
        .append(pal, io, &spdm_msg[..finish_hdr_len])
        .await?;

    // ── Verify requester HMAC ───────────────────────────────────────
    let mut th_hash = [0u8; SHA384_HASH_SIZE];
    session
        .transcript
        .clone_and_finalize(pal, io, &mut th_hash)
        .await?;

    let mut expected_vd = [0u8; SHA384_HASH_SIZE];
    let vd_len = session
        .key_schedule
        .hmac_finished(
            pal,
            io,
            SessionKeyType::RequestFinishedKey,
            &th_hash,
            &mut expected_vd,
        )
        .await?;
    if vd_len != SHA384_HASH_SIZE {
        return Err(SPDM_UNSPECIFIED);
    }

    // Constant-time comparison.
    let mut diff = 0u8;
    for (a, b) in req_verify_data.iter().zip(expected_vd.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(SPDM_DECRYPT_ERROR);
    }

    // ── Feed verify_data to TH (completes FINISH_REQ in TH) ────────
    session
        .transcript
        .append(pal, io, req_verify_data)
        .await?;

    // ── Build FINISH_RSP SPDM message ──────────────────────────────
    let mut rsp_buf = [0u8; FINISH_RSP_SPDM_SIZE];
    FinishRsp
        .encode_with_header(version, &mut WireWriter::new(&mut rsp_buf))
        .map_err(|_| SPDM_UNSPECIFIED)?;

    // ── Feed FINISH_RSP to TH ──────────────────────────────────────
    session
        .transcript
        .append(pal, io, &rsp_buf)
        .await?;

    // ── Finalize TH → TH2 ─────────────────────────────────────────
    let mut th2 = [0u8; SHA384_HASH_SIZE];
    session
        .transcript
        .finalize(pal, io, &mut th2)
        .await?;

    // ── Derive data keys ───────────────────────────────────────────
    session
        .key_schedule
        .generate_data_keys(pal, io, &th2)
        .await?;

    Ok(rsp_buf)
}
