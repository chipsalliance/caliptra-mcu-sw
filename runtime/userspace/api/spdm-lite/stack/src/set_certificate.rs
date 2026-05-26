// Licensed under the Apache-2.0 license

//! SET_CERTIFICATE → SET_CERTIFICATE_RSP handler (DSP0274 §10.13).
//!
//! The incoming certificate payload already resides in the per-exchange
//! receive buffer. This handler validates the SPDM cert-chain wrapper in
//! place and passes borrowed DER bytes to the PAL, avoiding a second
//! certificate-sized allocation.

use mcu_spdm_lite_codec::{
    CapFlags, OtherParamSupport, SetCertificateReqBody, SetCertificateRsp, SpdmMsgHdrPdu,
    SpdmVersion,
};
use mcu_spdm_lite_traits::{PalBytes, SpdmPal, SpdmPalIo, SpdmPalIoTransport, MAX_SLOTS};
use zerocopy::FromBytes;

use crate::build::build_response;
use crate::error::{
    SpdmResult, SPDM_INVALID_REQUEST, SPDM_UNEXPECTED_REQUEST, SPDM_UNSUPPORTED_REQUEST,
    SPDM_VERSION_MISMATCH,
};
use crate::stack::{ConnectionState, Phase};

const SPDM_CERT_CHAIN_HDR_LEN: usize = 4 + SHA384_DIGEST_SIZE;
const SHA384_DIGEST_SIZE: usize = 48;
const CERT_MODEL_DEVICE_CERT: u8 = 1;
const CERT_MODEL_GENERIC_CERT: u8 = 3;

pub(crate) async fn handle_set_certificate<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
) -> SpdmResult<PalBytes<'a, Pal>> {
    if (state.phase as u8) < (Phase::AfterAlgorithms as u8) {
        return Err(SPDM_UNEXPECTED_REQUEST);
    }
    if !pal.set_certificate_supported() || !state.cap_flags.contains(CapFlags::SET_CERT) {
        return Err(SPDM_UNSUPPORTED_REQUEST);
    }

    let req = io.request();
    let (hdr, body) = SpdmMsgHdrPdu::ref_from_prefix(req).map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != state.version.to_u8() {
        return Err(SPDM_VERSION_MISMATCH);
    }
    if state.version < SpdmVersion::V12 {
        return Err(SPDM_UNSUPPORTED_REQUEST);
    }

    let req_body = SetCertificateReqBody::ref_from_bytes(
        body.get(..SetCertificateReqBody::SIZE)
            .ok_or(SPDM_INVALID_REQUEST)?,
    )
    .map_err(|_| SPDM_INVALID_REQUEST)?;
    let payload = body
        .get(SetCertificateReqBody::SIZE..)
        .ok_or(SPDM_INVALID_REQUEST)?;

    let slot_id = req_body.slot_id();
    validate_request_attributes(state, req_body, slot_id)?;

    if req_body.erase() {
        if !payload.is_empty() || req_body.cert_model() != 0 {
            return Err(SPDM_INVALID_REQUEST);
        }
        pal.erase_cert_chain(io, slot_id, state.asym_algo()).await?;
    } else {
        let (root_hash, der) = validate_spdm_cert_chain(payload)?;
        let _ = (req_body.key_pair_id, effective_cert_model(state, req_body), root_hash);
        pal.write_cert_chain(io, slot_id, state.asym_algo(), der)
            .await?;
    }

    build_response(pal, io, state.version, &SetCertificateRsp { slot_id })
}

fn validate_request_attributes<S: Clone>(
    state: &ConnectionState<S>,
    req: &SetCertificateReqBody,
    slot_id: u8,
) -> SpdmResult<()> {
    if slot_id == 0 || slot_id >= MAX_SLOTS {
        return Err(SPDM_INVALID_REQUEST);
    }

    if state.version < SpdmVersion::V13 {
        if req.key_pair_id != 0 || req.cert_model() != 0 || req.erase() {
            return Err(SPDM_INVALID_REQUEST);
        }
        return Ok(());
    }

    if multi_key_conn_rsp(state) {
        if req.key_pair_id == 0 {
            return Err(SPDM_INVALID_REQUEST);
        }
        if !req.erase()
            && !(CERT_MODEL_DEVICE_CERT..=CERT_MODEL_GENERIC_CERT).contains(&req.cert_model())
        {
            return Err(SPDM_INVALID_REQUEST);
        }
    } else if req.key_pair_id != 0 || req.cert_model() != 0 {
        return Err(SPDM_INVALID_REQUEST);
    }

    Ok(())
}

fn effective_cert_model<S: Clone>(state: &ConnectionState<S>, req: &SetCertificateReqBody) -> u8 {
    if multi_key_conn_rsp(state) && req.cert_model() != 0 {
        req.cert_model()
    } else {
        CERT_MODEL_DEVICE_CERT
    }
}

fn multi_key_conn_rsp<S: Clone>(state: &ConnectionState<S>) -> bool {
    state.version >= SpdmVersion::V13
        && state
            .other_param_sel
            .contains(OtherParamSupport::MULTI_KEY_CONN)
        && state.cap_flags.multi_key_conn_rsp()
        && state.peer_cap_flags.multi_key_conn_rsp()
}

fn validate_spdm_cert_chain(payload: &[u8]) -> SpdmResult<([u8; SHA384_DIGEST_SIZE], &[u8])> {
    if payload.len() < SPDM_CERT_CHAIN_HDR_LEN {
        return Err(SPDM_INVALID_REQUEST);
    }

    let length = u16::from_le_bytes([payload[0], payload[1]]) as usize;
    let reserved = u16::from_le_bytes([payload[2], payload[3]]);
    if reserved != 0 || length != payload.len() || length < SPDM_CERT_CHAIN_HDR_LEN {
        return Err(SPDM_INVALID_REQUEST);
    }

    let der = &payload[SPDM_CERT_CHAIN_HDR_LEN..];
    if der.is_empty() {
        return Err(SPDM_INVALID_REQUEST);
    }

    let mut root_hash = [0u8; SHA384_DIGEST_SIZE];
    root_hash.copy_from_slice(&payload[4..SPDM_CERT_CHAIN_HDR_LEN]);
    Ok((root_hash, der))
}
