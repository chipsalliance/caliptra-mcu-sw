// Licensed under the Apache-2.0 license

//! FINISH handler.
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

use caliptra_mcu_spdm_codec::{
    FinishReqBody, FinishRsp, ResponseBody, SpdmMsgHdrPdu, SpdmVersion, WireWriter,
    SHA384_HASH_SIZE,
};
use caliptra_mcu_spdm_traits::*;
use zerocopy::FromBytes;

use crate::error::{SpdmResult, SPDM_DECRYPT_ERROR, SPDM_INVALID_REQUEST, SPDM_UNSPECIFIED};
use crate::key_schedule::SessionKeyType;
use crate::session::{SessionInfo, SessionState};

/// Maximum FINISH_RSP SPDM message size (common header, 2 reserved bytes,
/// and the V1.4 empty OpaqueData length).
pub(crate) const FINISH_RSP_MAX_SPDM_SIZE: usize = SpdmMsgHdrPdu::SIZE + 4;

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
    session: &mut SessionInfo<<Pal as SpdmPalSessionCrypto>::Key, Pal::State>,
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    spdm_msg: &[u8],
) -> SpdmResult<([u8; FINISH_RSP_MAX_SPDM_SIZE], usize)> {
    // ── Validate session state ──────────────────────────────────────
    if session.state != SessionState::HandshakeInProgress {
        return Err(SPDM_INVALID_REQUEST);
    }

    // ── Parse FINISH request ────────────────────────────────────────
    let (hdr, rest) = SpdmMsgHdrPdu::ref_from_prefix(spdm_msg).map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != version.to_u8() {
        return Err(crate::error::SPDM_VERSION_MISMATCH);
    }

    let (finish_req, req_verify_data, request_prefix_len) =
        split_finish_request_payload(version, rest)?;

    // No mutual auth — reject if requester signature present.
    if finish_req.signature_present() {
        return Err(SPDM_INVALID_REQUEST);
    }

    // ── Feed FINISH header + params + V1.4 OpaqueData (without verify_data) to TH ──
    let finish_prefix_len = SpdmMsgHdrPdu::SIZE + request_prefix_len;
    session
        .transcript
        .append(pal, io, &spdm_msg[..finish_prefix_len])
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
    session.transcript.append(pal, io, req_verify_data).await?;

    // ── Build FINISH_RSP SPDM message ──────────────────────────────
    let mut rsp_buf = [0u8; FINISH_RSP_MAX_SPDM_SIZE];
    let rsp_body = FinishRsp {
        include_opaque: version >= SpdmVersion::V14,
    };
    let rsp_len = rsp_body.encoded_size();
    rsp_body
        .encode_with_header(version, &mut WireWriter::new(&mut rsp_buf))
        .map_err(|_| SPDM_UNSPECIFIED)?;

    // ── Feed FINISH_RSP to TH ──────────────────────────────────────
    session
        .transcript
        .append(pal, io, &rsp_buf[..rsp_len])
        .await?;

    // ── Finalize TH → TH2 ─────────────────────────────────────────
    let mut th2 = [0u8; SHA384_HASH_SIZE];
    session.transcript.finalize(pal, io, &mut th2).await?;

    // ── Derive data keys ───────────────────────────────────────────
    session
        .key_schedule
        .generate_data_keys(pal, io, &th2)
        .await?;

    Ok((rsp_buf, rsp_len))
}

fn split_finish_request_payload(
    version: SpdmVersion,
    rest: &[u8],
) -> SpdmResult<(&FinishReqBody, &[u8], usize)> {
    let (finish_req, after_fixed) =
        FinishReqBody::ref_from_prefix(rest).map_err(|_| SPDM_INVALID_REQUEST)?;

    let after_opaque = if version >= SpdmVersion::V14 {
        let opaque_len_bytes = after_fixed.get(..2).ok_or(SPDM_INVALID_REQUEST)?;
        let opaque_len = u16::from_le_bytes([opaque_len_bytes[0], opaque_len_bytes[1]]) as usize;
        after_fixed
            .get(2 + opaque_len..)
            .ok_or(SPDM_INVALID_REQUEST)?
    } else {
        after_fixed
    };

    if after_opaque.len() != SHA384_HASH_SIZE {
        return Err(SPDM_INVALID_REQUEST);
    }

    let request_prefix_len = rest.len() - after_opaque.len();
    Ok((finish_req, after_opaque, request_prefix_len))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;
    use zerocopy::IntoBytes;

    fn finish_payload(version: SpdmVersion, opaque: &[u8]) -> Vec<u8> {
        let mut payload = FinishReqBody {
            req_signature_present: 0,
            req_slot_id: 0,
        }
        .as_bytes()
        .to_vec();
        if version >= SpdmVersion::V14 {
            payload.extend_from_slice(&(opaque.len() as u16).to_le_bytes());
            payload.extend_from_slice(opaque);
        }
        payload.extend_from_slice(&[0xa5; SHA384_HASH_SIZE]);
        payload
    }

    #[test]
    fn v14_finish_request_skips_opaque_data_before_verify_data() {
        let payload = finish_payload(SpdmVersion::V14, &[1, 2, 3]);
        let (_, verify_data, prefix_len) =
            split_finish_request_payload(SpdmVersion::V14, &payload).unwrap();

        assert_eq!(prefix_len, core::mem::size_of::<FinishReqBody>() + 2 + 3);
        assert_eq!(verify_data, &[0xa5; SHA384_HASH_SIZE]);
    }

    #[test]
    fn pre_v14_finish_request_has_no_opaque_data() {
        let payload = finish_payload(SpdmVersion::V13, &[]);
        let (_, verify_data, prefix_len) =
            split_finish_request_payload(SpdmVersion::V13, &payload).unwrap();

        assert_eq!(prefix_len, core::mem::size_of::<FinishReqBody>());
        assert_eq!(verify_data, &[0xa5; SHA384_HASH_SIZE]);
    }

    #[test]
    fn v14_finish_request_rejects_truncated_opaque_data() {
        let mut payload = finish_payload(SpdmVersion::V14, &[]);
        payload[2..4].copy_from_slice(&1u16.to_le_bytes());

        assert!(split_finish_request_payload(SpdmVersion::V14, &payload).is_err());
    }

    #[test]
    fn v14_finish_response_encodes_empty_opaque_data() {
        let rsp = FinishRsp {
            include_opaque: true,
        };
        let mut encoded = [0u8; FINISH_RSP_MAX_SPDM_SIZE];
        rsp.encode_with_header(SpdmVersion::V14, &mut WireWriter::new(&mut encoded))
            .unwrap();

        assert_eq!(rsp.encoded_size(), FINISH_RSP_MAX_SPDM_SIZE);
        assert_eq!(
            encoded,
            [
                SpdmVersion::V14.to_u8(),
                caliptra_mcu_spdm_codec::ReqRespCode::FINISH_RSP.0,
                0,
                0,
                0,
                0,
            ]
        );
    }
}
