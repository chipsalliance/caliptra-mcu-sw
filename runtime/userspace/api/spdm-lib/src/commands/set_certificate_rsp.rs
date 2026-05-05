// Licensed under the Apache-2.0 license

use crate::cert_store::{CertStoreError, MAX_CERT_SLOTS_SUPPORTED};
use crate::codec::{Codec, CommonCodec, MessageBuf};
use crate::commands::error_rsp::ErrorCode;
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult};
use crate::protocol::*;
use crate::state::ConnectionState;
use bitfield::bitfield;
use caliptra_mcu_libapi_caliptra::crypto::hash::SHA384_HASH_SIZE;
use zerocopy::{FromBytes, Immutable, IntoBytes};

const CERT_MODEL_NONE: u8 = 0;
const CERT_MODEL_DEVICE_CERT: u8 = 1;
const CERT_MODEL_ALIAS_CERT: u8 = 2;
const CERT_MODEL_GENERIC_CERT: u8 = 3;

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct SetCertificateReq {
    attributes: SetCertificateReqAttributes,
    key_pair_id: u8,
}

impl CommonCodec for SetCertificateReq {}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable, Clone, Copy)]
    #[repr(C)]
    struct SetCertificateReqAttributes(u8);
    impl Debug;
    u8;
    pub slot_id, set_slot_id: 3,0;
    pub cert_model, set_cert_model: 6,4;
    pub erase, set_erase: 7,7;
}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct SetCertificateRsp {
    spdm_version: SpdmMsgHdr,
    slot_id: u8,
    param2: u8,
}

impl CommonCodec for SetCertificateRsp {}

fn map_cert_store_error(err: CertStoreError) -> ErrorCode {
    match err {
        CertStoreError::SlotBusy => ErrorCode::Busy,
        CertStoreError::OperationFailed => ErrorCode::OperationFailed,
        CertStoreError::ResetRequired => ErrorCode::ResetRequired,
        _ => ErrorCode::Unspecified,
    }
}

fn cert_model_from_capabilities(ctx: &SpdmContext<'_>) -> u8 {
    if ctx.local_capabilities.flags.alias_cert_cap() != 0 {
        CERT_MODEL_ALIAS_CERT
    } else {
        CERT_MODEL_DEVICE_CERT
    }
}

fn validate_request_attributes(
    ctx: &mut SpdmContext<'_>,
    req: &SetCertificateReq,
    connection_version: SpdmVersion,
    rsp: &mut MessageBuf<'_>,
) -> CommandResult<(u8, bool, u8)> {
    let slot_id = req.attributes.slot_id();
    if slot_id >= MAX_CERT_SLOTS_SUPPORTED || slot_id >= ctx.device_certs_store.slot_count() {
        Err(ctx.generate_error_response(rsp, ErrorCode::InvalidRequest, 0, None))?;
    }

    // Caliptra treats slot 0 as the vendor-provisioned immutable identity slot.
    if slot_id == 0 {
        Err(ctx.generate_error_response(rsp, ErrorCode::InvalidRequest, 0, None))?;
    }

    if ctx.session_mgr.active_session_id().is_none() {
        Err(ctx.generate_error_response(rsp, ErrorCode::SessionRequired, 0, None))?;
    }

    if connection_version < SpdmVersion::V13 {
        if req.key_pair_id != 0 || req.attributes.cert_model() != 0 || req.attributes.erase() != 0 {
            Err(ctx.generate_error_response(rsp, ErrorCode::InvalidRequest, 0, None))?;
        }
        return Ok((slot_id, false, cert_model_from_capabilities(ctx)));
    }

    let erase = req.attributes.erase() != 0;
    let cert_model = req.attributes.cert_model();

    if ctx.state.connection_info.multi_key_conn_rsp() {
        if req.key_pair_id == 0 {
            Err(ctx.generate_error_response(rsp, ErrorCode::InvalidRequest, 0, None))?;
        }
        if !erase && !(CERT_MODEL_DEVICE_CERT..=CERT_MODEL_GENERIC_CERT).contains(&cert_model) {
            Err(ctx.generate_error_response(rsp, ErrorCode::InvalidRequest, 0, None))?;
        }
        Ok((slot_id, erase, cert_model))
    } else {
        if req.key_pair_id != 0 || cert_model != CERT_MODEL_NONE {
            Err(ctx.generate_error_response(rsp, ErrorCode::InvalidRequest, 0, None))?;
        }
        Ok((slot_id, erase, cert_model_from_capabilities(ctx)))
    }
}

fn validate_spdm_cert_chain(
    rsp: &MessageBuf<'_>,
) -> Result<([u8; SHA384_HASH_SIZE], usize, usize), CommandError> {
    let remaining_len = rsp.data_len();
    if remaining_len < SPDM_CERT_CHAIN_METADATA_LEN {
        return Err(CommandError::ErrorCode(ErrorCode::InvalidRequest));
    }

    let cert_chain = rsp.data(remaining_len).map_err(CommandError::Codec)?;
    let length = u16::from_le_bytes([cert_chain[0], cert_chain[1]]) as usize;
    let reserved = u16::from_le_bytes([cert_chain[2], cert_chain[3]]);

    if reserved != 0 || length < SPDM_CERT_CHAIN_METADATA_LEN || length != remaining_len {
        return Err(CommandError::ErrorCode(ErrorCode::InvalidRequest));
    }

    let cert_chain_len = length - SPDM_CERT_CHAIN_METADATA_LEN;
    if cert_chain_len == 0 {
        return Err(CommandError::ErrorCode(ErrorCode::InvalidRequest));
    }

    let mut root_cert_hash = [0u8; SHA384_HASH_SIZE];
    root_cert_hash.copy_from_slice(&cert_chain[4..SPDM_CERT_CHAIN_METADATA_LEN]);

    Ok((root_cert_hash, SPDM_CERT_CHAIN_METADATA_LEN, cert_chain_len))
}

async fn process_set_certificate<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<u8> {
    let connection_version = ctx.validate_spdm_version(&spdm_hdr, req_payload)?;
    if connection_version < SpdmVersion::V12 {
        Err(ctx.generate_error_response(
            req_payload,
            ErrorCode::UnsupportedRequest,
            ReqRespCode::SetCertificate.into(),
            None,
        ))?;
    }

    let req = SetCertificateReq::decode(req_payload).map_err(|_| {
        ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
    })?;

    let (slot_id, erase, cert_model) =
        validate_request_attributes(ctx, &req, connection_version, req_payload)?;
    ctx.validate_negotiated_hash_algo(req_payload)?;
    let asym_algo = ctx.validate_negotiated_base_asym_algo(req_payload)?;

    let store_result = if erase {
        if req_payload.data_len() != 0 || req.attributes.cert_model() != 0 {
            Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
        }
        ctx.device_certs_store
            .erase_cert_chain(asym_algo, slot_id)
            .await
    } else {
        let (root_cert_hash, cert_chain_offset, cert_chain_len) =
            validate_spdm_cert_chain(req_payload).map_err(|_| {
                ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
            })?;
        let cert_chain = &req_payload
            .data(cert_chain_offset + cert_chain_len)
            .map_err(|e| (false, CommandError::Codec(e)))?[cert_chain_offset..];
        let mut cert_info = CertificateInfo::default();
        cert_info.set_cert_model(cert_model);
        ctx.device_certs_store
            .write_cert_chain(
                asym_algo,
                slot_id,
                req.key_pair_id,
                cert_info,
                &root_cert_hash,
                cert_chain,
            )
            .await
    };

    store_result
        .map_err(|e| ctx.generate_error_response(req_payload, map_cert_store_error(e), 0, None))?;

    Ok(slot_id)
}

fn generate_set_certificate_response(
    ctx: &SpdmContext<'_>,
    slot_id: u8,
    rsp: &mut MessageBuf<'_>,
) -> CommandResult<()> {
    let connection_version = ctx.state.connection_info.version_number();
    let rsp_msg = SetCertificateRsp {
        spdm_version: SpdmMsgHdr::new(connection_version, ReqRespCode::SetCertificateRsp),
        slot_id,
        param2: 0,
    };

    let payload_len = rsp_msg
        .encode(rsp)
        .map_err(|e| (false, CommandError::Codec(e)))?;
    rsp.push_data(payload_len)
        .map_err(|e| (false, CommandError::Codec(e)))?;
    Ok(())
}

pub(crate) async fn handle_set_certificate<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    if ctx.state.connection_info.state() < ConnectionState::AlgorithmsNegotiated {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    }

    if ctx.local_capabilities.flags.set_certificate_cap() == 0 {
        Err(ctx.generate_error_response(
            req_payload,
            ErrorCode::UnsupportedRequest,
            ReqRespCode::SetCertificate.into(),
            None,
        ))?;
    }

    let slot_id = process_set_certificate(ctx, spdm_hdr, req_payload).await?;

    ctx.prepare_response_buffer(req_payload)?;
    generate_set_certificate_response(ctx, slot_id, req_payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message_buf_with_payload<'a>(raw: &'a mut [u8], payload: &[u8]) -> MessageBuf<'a> {
        let mut buf = MessageBuf::new(raw);
        buf.put_data(payload.len()).unwrap();
        buf.data_mut(payload.len())
            .unwrap()
            .copy_from_slice(payload);
        buf
    }

    fn cert_chain_payload(der_chain: &[u8]) -> [u8; SPDM_CERT_CHAIN_METADATA_LEN + 4] {
        let mut payload = [0u8; SPDM_CERT_CHAIN_METADATA_LEN + 4];
        let length = payload.len() as u16;
        payload[0..2].copy_from_slice(&length.to_le_bytes());
        payload[4..SPDM_CERT_CHAIN_METADATA_LEN].fill(0x5a);
        payload[SPDM_CERT_CHAIN_METADATA_LEN..].copy_from_slice(der_chain);
        payload
    }

    #[test]
    fn test_validate_spdm_cert_chain_accepts_well_formed_payload() {
        let payload = cert_chain_payload(&[1, 2, 3, 4]);
        let mut raw = [0u8; 128];
        let buf = message_buf_with_payload(&mut raw, &payload);

        let (root_hash, offset, len) = validate_spdm_cert_chain(&buf).unwrap();

        assert_eq!(root_hash, [0x5a; SHA384_HASH_SIZE]);
        assert_eq!(offset, SPDM_CERT_CHAIN_METADATA_LEN);
        assert_eq!(len, 4);
    }

    #[test]
    fn test_validate_spdm_cert_chain_rejects_bad_length() {
        let mut payload = cert_chain_payload(&[1, 2, 3, 4]);
        let bad_length = payload.len() as u16 - 1;
        payload[0..2].copy_from_slice(&bad_length.to_le_bytes());
        let mut raw = [0u8; 128];
        let buf = message_buf_with_payload(&mut raw, &payload);

        assert!(validate_spdm_cert_chain(&buf).is_err());
    }

    #[test]
    fn test_validate_spdm_cert_chain_rejects_empty_der_chain() {
        let mut payload = [0u8; SPDM_CERT_CHAIN_METADATA_LEN];
        let length = payload.len() as u16;
        payload[0..2].copy_from_slice(&length.to_le_bytes());
        let mut raw = [0u8; 128];
        let buf = message_buf_with_payload(&mut raw, &payload);

        assert!(validate_spdm_cert_chain(&buf).is_err());
    }

    #[test]
    fn test_certificate_info_cert_model_bits_are_low_three_bits() {
        let mut cert_info = CertificateInfo::default();
        cert_info.set_cert_model(CERT_MODEL_GENERIC_CERT);

        assert_eq!(cert_info.cert_model(), CERT_MODEL_GENERIC_CERT);
    }
}
