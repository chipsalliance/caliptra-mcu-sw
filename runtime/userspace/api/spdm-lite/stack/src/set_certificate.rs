// Licensed under the Apache-2.0 license

//! SET_CERTIFICATE → SET_CERTIFICATE_RSP handler.
//!
//! The incoming certificate payload already resides in the per-exchange
//! receive buffer. This handler validates the SPDM cert-chain wrapper in
//! place and passes borrowed DER bytes to the PAL, avoiding a second
//! certificate-sized allocation.

use mcu_error::McuErrorCode;
use mcu_spdm_lite_codec::{
    AsymAlgos, CapFlags, HashAlgos, ReqRespCode, SetCertificateReqBody, SetCertificateRsp,
    SpdmMsgHdrPdu, SpdmVersion,
};
use mcu_spdm_lite_errors::as_spdm_wire;
use mcu_spdm_lite_traits::{
    PalBytes, SpdmPal, SpdmPalAlloc, SpdmPalIo, SpdmPalIoTransport, MAX_SLOTS,
};
use zerocopy::FromBytes;

use crate::build::build_response;
use crate::error::{
    SpdmError, SpdmResult, SPDM_INVALID_REQUEST, SPDM_SESSION_REQUIRED, SPDM_UNEXPECTED_REQUEST,
    SPDM_UNSPECIFIED, SPDM_UNSUPPORTED_REQUEST, SPDM_VERSION_MISMATCH,
};
use crate::stack::{multi_key_conn_rsp, ConnectionState, Phase};

const SPDM_CERT_CHAIN_HDR_LEN: usize = 4 + SHA384_DIGEST_SIZE;
const SHA384_DIGEST_SIZE: usize = 48;
const CERT_MODEL_DEVICE_CERT: u8 = 1;
const CERT_MODEL_ALIAS_CERT: u8 = 2;
const CERT_MODEL_GENERIC_CERT: u8 = 3;

pub(crate) async fn handle_set_certificate<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
) -> SpdmResult<PalBytes<'a, Pal>> {
    let req = io.request();
    if req.len() > pal.mtu() {
        return Err(SPDM_INVALID_REQUEST);
    }
    let slot_id = handle_set_certificate_request(state, pal, io, req).await?;
    build_response(pal, io, state.version, &SetCertificateRsp { slot_id })
}

pub(crate) async fn handle_set_certificate_request<Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    req: &[u8],
) -> SpdmResult<u8> {
    if (state.phase as u8) < (Phase::AfterAlgorithms as u8) {
        return Err(SPDM_UNEXPECTED_REQUEST);
    }
    if !state.advertised_cap_flags.contains(CapFlags::SET_CERT) {
        return Err(unsupported_set_certificate());
    }

    let (hdr, body) = SpdmMsgHdrPdu::ref_from_prefix(req).map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != state.version.to_u8() {
        return Err(SPDM_VERSION_MISMATCH);
    }
    if state.version < SpdmVersion::V12 {
        return Err(unsupported_set_certificate());
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
    validate_request_slot(slot_id, pal.supported_slots())?;

    let erase = req_body.erase();
    let cert_model = if erase {
        0
    } else {
        effective_cert_model(state, req_body)?
    };
    if !pal.set_certificate_authorized(io, slot_id, req_body.key_pair_id, cert_model, erase) {
        return Err(SPDM_SESSION_REQUIRED);
    }

    validate_request_attributes(state, req_body)?;
    validate_negotiated_set_certificate_algorithms(state)?;

    if erase {
        if !payload.is_empty() || req_body.cert_model() != 0 {
            return Err(SPDM_INVALID_REQUEST);
        }
        pal.erase_cert_chain(io, slot_id, state.asym_algo()).await?;
    } else {
        let (root_hash, der) = validate_spdm_cert_chain(payload)?;
        pal.validate_set_certificate_chain(
            io,
            slot_id,
            req_body.key_pair_id,
            cert_model,
            root_hash,
            der,
        )
        .await
        .map_err(map_set_cert_validation_error)?;
        pal.write_cert_chain(
            io,
            slot_id,
            state.asym_algo(),
            req_body.key_pair_id,
            cert_model,
            root_hash,
            der,
        )
        .await?;
    }

    Ok(slot_id)
}

fn unsupported_set_certificate() -> SpdmError {
    SPDM_UNSUPPORTED_REQUEST.with_data(ReqRespCode::SET_CERTIFICATE.0)
}

fn validate_request_slot(slot_id: u8, supported_slots: u8) -> SpdmResult<()> {
    // Caliptra's Vendor certificate lives in slot 0 and is read-only;
    // SET_CERTIFICATE may only provision mutable owner/device slots.
    if slot_id == 0 || slot_id >= MAX_SLOTS {
        return Err(SPDM_INVALID_REQUEST);
    }
    if supported_slots & (1u8 << slot_id) == 0 {
        return Err(SPDM_INVALID_REQUEST);
    }
    Ok(())
}

fn validate_request_attributes<S, L>(
    state: &ConnectionState<S, L>,
    req: &SetCertificateReqBody,
) -> SpdmResult<()> {
    if state.version < SpdmVersion::V13 {
        if req.key_pair_id != 0 || req.cert_model() != 0 || req.erase() {
            return Err(SPDM_INVALID_REQUEST);
        }
        return Ok(());
    }

    if multi_key_conn_rsp(state)? {
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

fn effective_cert_model<S, L>(
    state: &ConnectionState<S, L>,
    req: &SetCertificateReqBody,
) -> SpdmResult<u8> {
    if multi_key_conn_rsp(state)? && req.cert_model() != 0 {
        Ok(req.cert_model())
    } else {
        Ok(cert_model_from_capabilities(state.advertised_cap_flags))
    }
}

fn cert_model_from_capabilities(cap_flags: CapFlags) -> u8 {
    if cap_flags.contains(CapFlags::ALIAS_CERT) {
        CERT_MODEL_ALIAS_CERT
    } else {
        CERT_MODEL_DEVICE_CERT
    }
}

fn validate_negotiated_set_certificate_algorithms<S, L>(
    state: &ConnectionState<S, L>,
) -> SpdmResult<()> {
    if state.negotiated_base_hash_sel != HashAlgos::SHA_384 {
        return Err(SPDM_UNSPECIFIED);
    }
    if state.negotiated_base_asym_sel != AsymAlgos::ECDSA_ECC_NIST_P384 {
        return Err(SPDM_INVALID_REQUEST);
    }
    Ok(())
}

fn validate_spdm_cert_chain(payload: &[u8]) -> SpdmResult<(&[u8; SHA384_DIGEST_SIZE], &[u8])> {
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
    // Validate DER framing of the chain; PAL re-walks and is responsible
    // for verifying SHA-384(root cert) == root_hash.
    let _root_cert_len = validate_der_chain(der)?;

    let root_hash: &[u8; SHA384_DIGEST_SIZE] = payload
        .get(4..SPDM_CERT_CHAIN_HDR_LEN)
        .and_then(|s| s.try_into().ok())
        .ok_or(SPDM_INVALID_REQUEST)?;
    Ok((root_hash, der))
}

fn validate_der_chain(der: &[u8]) -> SpdmResult<usize> {
    let mut offset = 0usize;
    let mut root_cert_len = None;
    while offset < der.len() {
        let cert_len = der_sequence_len(&der[offset..]).ok_or(SPDM_INVALID_REQUEST)?;
        if root_cert_len.is_none() {
            root_cert_len = Some(cert_len);
        }
        offset = offset.checked_add(cert_len).ok_or(SPDM_INVALID_REQUEST)?;
    }
    root_cert_len.ok_or(SPDM_INVALID_REQUEST)
}

fn der_sequence_len(input: &[u8]) -> Option<usize> {
    if input.len() < 2 || input[0] != 0x30 {
        return None;
    }

    let len_byte = input[1];
    let (header_len, content_len) = if len_byte & 0x80 == 0 {
        (2usize, len_byte as usize)
    } else {
        let len_len = (len_byte & 0x7f) as usize;
        if len_len == 0 || len_len > 4 || input.len() < 2 + len_len {
            return None;
        }
        let mut content_len = 0usize;
        for &byte in &input[2..2 + len_len] {
            content_len = content_len.checked_shl(8)?;
            content_len = content_len.checked_add(byte as usize)?;
        }
        (2 + len_len, content_len)
    };

    if content_len == 0 {
        return None;
    }
    let total_len = header_len.checked_add(content_len)?;
    (total_len <= input.len()).then_some(total_len)
}

fn map_set_cert_validation_error(err: McuErrorCode) -> SpdmError {
    as_spdm_wire(err)
        .map(SpdmError::new)
        .unwrap_or(SPDM_INVALID_REQUEST)
}

#[cfg(test)]
#[path = "tests/set_certificate.rs"]
mod tests;
