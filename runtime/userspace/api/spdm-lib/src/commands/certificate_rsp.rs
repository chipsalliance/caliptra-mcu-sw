// Licensed under the Apache-2.0 license

use crate::cert_store::{
    cert_slot_mask, spdm_cert_chain_len, spdm_read_cert_chain, SpdmCertStore,
    MAX_CERT_SLOTS_SUPPORTED,
};
use crate::chunk_ctx::LargeResponse;
use crate::codec::{Codec, CommonCodec, MessageBuf};
use crate::commands::error_rsp::ErrorCode;
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult};
use crate::protocol::*;
use crate::state::ConnectionState;
use crate::transcript::{Transcript, TranscriptContext};
use bitfield::bitfield;
use libapi_caliptra::crypto::asym::AsymAlgo;
use zerocopy::{FromBytes, Immutable, IntoBytes};

const CERTIFICATE_RESP_HEADER_SIZE: usize = size_of::<CertificateRespHdr>();

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub struct GetCertificateReq {
    pub slot_id: SlotId,
    pub param2: CertificateReqAttributes,
    pub offset: u16,
    pub length: u16,
}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable)]
    #[repr(C)]
    pub struct SlotId(u8);
    impl Debug;
    u8;
    pub slot_id, set_slot_id: 3,0;
    reserved, _: 7,4;
}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable)]
    #[repr(C)]
    pub struct CertificateReqAttributes(u8);
    impl Debug;
    u8;
    pub slot_size_requested, set_slot_size_requested: 0,0;
    reserved, _: 7,1;
}

impl CommonCodec for GetCertificateReq {}

#[derive(IntoBytes, FromBytes, Immutable)]
#[repr(C, packed)]
pub struct CertificateRespHdr {
    spdm_version: SpdmMsgHdr,
    slot_id: SlotId,
    param2: CertificateRespAttributes,
    portion_length: u16,
    remainder_length: u16,
}

impl CommonCodec for CertificateRespHdr {}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable, Default)]
    #[repr(C)]
    pub struct CertificateRespAttributes(u8);
    impl Debug;
    u8;
    pub certificate_info, set_certificate_info: 2,0;
    reserved, _: 7,3;
}

#[derive(Debug, Clone)]
pub(crate) struct CertificateResponse {
    spdm_version: SpdmVersion,
    slot_id: u8,
    asym_algo: AsymAlgo,
    offset: u16,
    portion_len: u16,
    remainder_len: u16,
    total_cert_chain_len: u16,
    cert_info: Option<CertificateInfo>,
}

impl CertificateResponse {
    async fn resp_hdr(&self) -> CommandResult<[u8; CERTIFICATE_RESP_HEADER_SIZE]> {
        let mut buf = [0u8; CERTIFICATE_RESP_HEADER_SIZE];
        let mut msg_buf = MessageBuf::new(&mut buf);

        let slot_id_struct = SlotId(self.slot_id);
        let mut resp_attr = CertificateRespAttributes::default();
        if let Some(cert_info) = self.cert_info {
            resp_attr.set_certificate_info(cert_info.cert_model());
        }

        let certificate_rsp_common = CertificateRespHdr {
            spdm_version: SpdmMsgHdr::new(self.spdm_version, ReqRespCode::Certificate),
            slot_id: slot_id_struct,
            param2: resp_attr,
            portion_length: self.portion_len,
            remainder_length: self.remainder_len,
        };
        certificate_rsp_common
            .encode(&mut msg_buf)
            .map_err(|e| (false, CommandError::Codec(e)))?;

        Ok(buf)
    }

    pub async fn encode_rsp_hdr(&self, rsp: &mut MessageBuf<'_>) -> CommandResult<usize> {
        let rsp_hdr_bytes = self.resp_hdr().await?;
        rsp.put_data(rsp_hdr_bytes.len())
            .map_err(|e| (false, CommandError::Codec(e)))?;
        let rsp_hdr_buf = rsp
            .data_mut(rsp_hdr_bytes.len())
            .map_err(|e| (false, CommandError::Codec(e)))?;
        rsp_hdr_buf.copy_from_slice(&rsp_hdr_bytes);
        rsp.pull_data(rsp_hdr_bytes.len())
            .map_err(|e| (false, CommandError::Codec(e)))?;
        Ok(rsp_hdr_bytes.len())
    }

    pub async fn get_chunk(
        &self,
        shared_transcript: &mut Transcript,
        cert_store: &dyn SpdmCertStore,
        cert_rsp_offset: usize,
        chunk: &mut [u8],
    ) -> CommandResult<usize> {
        let certchain_offset: usize;
        let mut chunk_data_len = 0;
        let mut rem_len = chunk
            .len()
            .min((self.portion_len - cert_rsp_offset as u16) as usize);
        if cert_rsp_offset < CERTIFICATE_RESP_HEADER_SIZE {
            // Read from the response header
            let header_bytes = self.resp_hdr().await?;
            let header_offset = cert_rsp_offset;
            let header_rem_len = CERTIFICATE_RESP_HEADER_SIZE - header_offset;
            let copy_len = header_rem_len.min(chunk.len());
            chunk[..copy_len]
                .copy_from_slice(&header_bytes[header_offset..header_offset + copy_len]);
            rem_len = rem_len.saturating_sub(copy_len);
            certchain_offset = self.offset as usize;
            chunk_data_len = copy_len;
        } else {
            certchain_offset =
                self.offset as usize + cert_rsp_offset.saturating_sub(CERTIFICATE_RESP_HEADER_SIZE);
        }

        if rem_len > 0 {
            let rem_chunk = &mut chunk[chunk_data_len..];
            let read_len = spdm_read_cert_chain(
                cert_store,
                self.slot_id,
                self.asym_algo,
                certchain_offset,
                rem_chunk,
            )
            .await
            .map_err(|e| (false, CommandError::CertStore(e)))?;
            chunk_data_len += read_len;
        }

        shared_transcript
            .append(TranscriptContext::M1, None, &chunk[..chunk_data_len])
            .await
            .map_err(|e| (false, CommandError::Transcript(e)))?;
        Ok(chunk_data_len)
    }
}

async fn generate_certificate_response<'a>(
    ctx: &mut SpdmContext<'a>,
    rsp_ctx: CertificateResponse,
    rsp: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Ensure the selected hash algorithm is SHA384 and retrieve the asymmetric algorithm (currently only ECC-P384 is supported)
    ctx.validate_negotiated_hash_algo(rsp)?;
    let asym_algo = rsp_ctx.asym_algo;
    let total_cert_chain_len = rsp_ctx.total_cert_chain_len;
    let slot_id = rsp_ctx.slot_id;
    let portion_len: u16 = rsp_ctx.portion_len;
    let offset: u16 = rsp_ctx.offset;

    if portion_len > SPDM_MAX_CERT_CHAIN_PORTION_LEN {
        let large_rsp_len = CERTIFICATE_RESP_HEADER_SIZE + portion_len as usize;
        let large_rsp = LargeResponse::Certificate(rsp_ctx.clone());
        let handle = ctx.large_resp_context.init(large_rsp, large_rsp_len);
        Err(ctx.generate_error_response(rsp, ErrorCode::LargeResponse, 0, Some(&[handle])))?;
    }

    if offset >= total_cert_chain_len {
        return Err(ctx.generate_error_response(rsp, ErrorCode::InvalidRequest, 0, None));
    }

    // Start filling the response payload
    let mut payload_len = rsp_ctx.encode_rsp_hdr(rsp).await?;

    if portion_len > 0 {
        rsp.put_data(portion_len as usize)
            .map_err(|e| (false, CommandError::Codec(e)))?;
        let cert_chain_buf = rsp
            .data_mut(portion_len as usize)
            .map_err(|e| (false, CommandError::Codec(e)))?;
        let read_len = spdm_read_cert_chain(
            ctx.device_certs_store,
            slot_id,
            asym_algo,
            offset as usize,
            cert_chain_buf,
        )
        .await
        .map_err(|e| (false, CommandError::CertStore(e)))?;

        rsp.pull_data(read_len)
            .map_err(|e| (false, CommandError::Codec(e)))?;
        payload_len += read_len;
    }

    // Append the response message to the M1 transcript
    ctx.append_message_to_transcript(rsp, TranscriptContext::M1, None)
        .await?;

    rsp.push_data(payload_len)
        .map_err(|e| (false, CommandError::Codec(e)))?;
    Ok(())
}

async fn process_get_certificate<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<CertificateResponse> {
    // Validate the version
    let connection_version = ctx.validate_spdm_version(&spdm_hdr, req_payload)?;

    // Decode the GET_CERTIFICATE request payload
    let req = GetCertificateReq::decode(req_payload).map_err(|_| {
        ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
    })?;

    let slot_id = req.slot_id.slot_id();
    if slot_id >= MAX_CERT_SLOTS_SUPPORTED {
        Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
    }

    // Check if the slot is provisioned. Otherwise, return an InvalidRequest error.
    let slot_mask = 1 << slot_id;
    let (_, provisioned_slot_mask) = cert_slot_mask(ctx.device_certs_store).await;

    if provisioned_slot_mask & slot_mask == 0 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
    }

    let mut offset = req.offset;
    let mut length = req.length;

    // When SlotSizeRequested=1b in the GET_CERTIFICATE request, the Responder shall return
    // the number of bytes available for certificate chain storage in the RemainderLength field of the response.
    if connection_version >= SpdmVersion::V13 && req.param2.slot_size_requested() != 0 {
        offset = 0;
        length = 0;
    }

    // Reset the transcript context
    ctx.reset_transcript_via_req_code(ReqRespCode::GetCertificate);

    // Append the request to the M1 transcript
    ctx.append_message_to_transcript(req_payload, TranscriptContext::M1, None)
        .await?;

    // Prepare the response context
    let asym_algo = ctx.validate_negotiated_base_asym_algo(req_payload)?;
    let certchain_len = spdm_cert_chain_len(ctx.device_certs_store, slot_id, asym_algo)
        .await
        .map_err(|_| {
            ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
        })?;
    let cert_info = if connection_version >= SpdmVersion::V13
        && ctx.state.connection_info.multi_key_conn_rsp()
    {
        ctx.device_certs_store.cert_info(slot_id).await
    } else {
        None
    };
    let mut remainder_len: u16 = certchain_len.saturating_sub(offset as usize) as u16;
    let portion_len = if ctx.support_large_msg_chunking() {
        // When chunking is supported, use the full requested length
        length.min(remainder_len as u16)
    } else {
        // When chunking is not supported, limit to max portion length
        length
            .min(SPDM_MAX_CERT_CHAIN_PORTION_LEN)
            .min(remainder_len as u16)
    };
    remainder_len = remainder_len.saturating_sub(portion_len);

    let cert_resp_context = CertificateResponse {
        spdm_version: connection_version,
        slot_id,
        asym_algo,
        offset,
        portion_len,
        remainder_len,
        total_cert_chain_len: certchain_len as u16,
        cert_info,
    };

    Ok(cert_resp_context)
}

pub(crate) async fn handle_get_certificate<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Validate the state
    if ctx.state.connection_info.state() < ConnectionState::AlgorithmsNegotiated {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    }

    // Check if the certificate capability is supported.
    if ctx.local_capabilities.flags.cert_cap() == 0 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnsupportedRequest, 0, None))?;
    }

    // Process the GET_CERTIFICATE request
    let rsp_ctx = process_get_certificate(ctx, spdm_hdr, req_payload).await?;

    // Generate the CERTIFICATE response
    ctx.prepare_response_buffer(req_payload)?;
    generate_certificate_response(ctx, rsp_ctx, req_payload).await?;

    // Set the connection state to AfterCertificate
    if ctx.state.connection_info.state() < ConnectionState::AfterCertificate {
        ctx.state
            .connection_info
            .set_state(ConnectionState::AfterCertificate);
    }

    Ok(())
}
